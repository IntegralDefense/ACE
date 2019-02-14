# vim: sw=4:ts=4:et
#
# ACE API analysis routines

import datetime
import json
import logging
import os.path
import shutil
import tempfile
import uuid

from .. import db, json_result, json_request

import saq
from saq import LOCAL_TIMEZONE
from saq.analysis import RootAnalysis, _JSONEncoder
from saq.database import get_db_connection, ALERT
from saq.error import report_exception
from saq.constants import *
from saq.util import parse_event_time, storage_dir_from_uuid, validate_uuid, workload_storage_dir

from flask import Blueprint, request, abort, Response, send_from_directory
from werkzeug import secure_filename

analysis_bp = Blueprint('analysis', __name__, url_prefix='/analysis')

KEY_ANALYSIS = 'analysis'

KEY_ANALYSIS_MODE = 'analysis_mode'
KEY_LOG_LEVEL = 'log_level'
KEY_TOOL = 'tool'
KEY_TOOL_INSTANCE = 'tool_instance'
KEY_TYPE = 'type'
KEY_DESCRIPTION = 'description'
KEY_EVENT_TIME = 'event_time'
KEY_DETAILS = 'details'
KEY_OBSERVABLES = 'observables'
KEY_TAGS = 'tags'
KEY_COMPANY_NAME = 'company_name'

KEY_O_TYPE = 'type'
KEY_O_VALUE = 'value'
KEY_O_TIME = 'time'
KEY_O_TAGS = 'tags'
KEY_O_DIRECTIVES = 'directives'
KEY_O_LIMITED_ANALYSIS = 'limited_analysis'

@analysis_bp.route('/submit', methods=['POST'])
def submit():

    if KEY_ANALYSIS not in request.values:
        abort(Response("missing {} field (see documentation)".format(KEY_ANALYSIS), 400))

    r = json.loads(request.values[KEY_ANALYSIS])

    # the specified company needs to match the company of this node
    # TODO eventually we'll have a single node that serves API to all configured companies

    if KEY_COMPANY_NAME in r and r[KEY_COMPANY_NAME] != saq.CONFIG['global']['company_name']:
        abort(Response("wrong company {} (are you sending to the correct system?)".format(r[KEY_COMPANY_NAME]), 400))

    if KEY_DESCRIPTION not in r:
        abort(Response("missing {} field in submission".format(KEY_DESCRIPTION), 400))

    root = RootAnalysis()
    root.uuid = str(uuid.uuid4())

    # does the engine use a different drive for the workload?
    analysis_mode = r[KEY_ANALYSIS_MODE] if KEY_ANALYSIS_MODE in r else saq.CONFIG['engine']['default_analysis_mode']
    if analysis_mode != ANALYSIS_MODE_CORRELATION:
        root.storage_dir = workload_storage_dir(root.uuid)
    else:
        root.storage_dir = storage_dir_from_uuid(root.uuid)

    root.initialize_storage()

    try:

        root.analysis_mode = r[KEY_ANALYSIS_MODE] if KEY_ANALYSIS_MODE in r else saq.CONFIG['engine']['default_analysis_mode']
        root.company_id = saq.CONFIG['global'].getint('company_id')
        root.tool = r[KEY_TOOL] if KEY_TOOL in r else 'api'
        root.tool_instance = r[KEY_TOOL_INSTANCE] if KEY_TOOL_INSTANCE in r else 'api({})'.format(request.remote_addr)
        root.alert_type = r[KEY_TYPE] if KEY_TYPE in r else saq.CONFIG['api']['default_alert_type']
        root.description = r[KEY_DESCRIPTION]
        root.event_time = LOCAL_TIMEZONE.localize(datetime.datetime.now())
        if KEY_EVENT_TIME in r:
            try:
                root.event_time = parse_event_time(r[KEY_EVENT_TIME])
            except ValueError as e:
                abort(Response("invalid event time format for {} (use {} format)".format(r[KEY_EVENT_TIME], event_time_format_json_tz), 400))

        root.details = r[KEY_DETAILS] if KEY_DETAILS in r else {}

        # go ahead and allocate storage
        # XXX use temp dir instead...

        if KEY_TAGS in r:
            for tag in r[KEY_TAGS]:
                root.add_tag(tag)

        # add the observables
        if KEY_OBSERVABLES in r:
            for o in r[KEY_OBSERVABLES]:
                # check for required fields
                for field in [ KEY_O_TYPE, KEY_O_VALUE ]:
                    if field not in o:
                        abort(Response("an observable is missing the {} field".format(field), 400))

                o_type = o[KEY_O_TYPE]
                o_value = o[KEY_O_VALUE]
                o_time = None
                if KEY_O_TIME in o:
                    try:
                        o_time = parse_event_time(o[KEY_O_TIME])
                    except ValueError:
                        abort(Response("an observable has an invalid time format {} (use {} format)".format(
                                       o[KEY_O_TIME], event_time_format_json_tz), 400))

                observable = root.add_observable(o_type, o_value, o_time=o_time)

                if KEY_O_TAGS in o:
                    for tag in o[KEY_O_TAGS]:
                        observable.add_tag(tag)

                if KEY_O_DIRECTIVES in o:
                    for directive in o[KEY_O_DIRECTIVES]:
                        # is this a valid directive?
                        if directive not in VALID_DIRECTIVES:
                            abort(Response("observable {} has invalid directive {} (choose from {})".format(
                                           '{}:{}'.format(o_type, o_value), directive, ','.join(VALID_DIRECTIVES)), 400))

                        observable.add_directive(directive)

                if KEY_O_LIMITED_ANALYSIS in o:
                    for module_name in o[KEY_O_LIMITED_ANALYSIS]:
                        observable.limit_analysis(module_name)

        # save the files to disk and add them as observables of type file
        for f in request.files.getlist('file'):
            logging.debug("recording file {}".format(f.filename))
            #temp_dir = tempfile.mkdtemp(dir=saq.CONFIG.get('api', 'incoming_dir'))
            #_path = os.path.join(temp_dir, secure_filename(f.filename))
            try:
                #if os.path.exists(_path):
                    #logging.error("duplicate file name {}".format(_path))
                    #abort(400)

                #logging.debug("saving file to {}".format(_path))
                #try:
                    #f.save(_path)
                #except Exception as e:
                    #logging.error("unable to save file to {}: {}".format(_path, e))
                    #abort(400)

                full_path = os.path.join(root.storage_dir, f.filename)

                try:
                    dest_dir = os.path.dirname(full_path)
                    if not os.path.isdir(dest_dir):
                        try:
                            os.makedirs(dest_dir)
                        except Exception as e:
                            logging.error("unable to create directory {}: {}".format(dest_dir, e))
                            abort(400)

                    logging.debug("saving file {}".format(full_path))
                    f.save(full_path)

                    # add this as a F_FILE type observable
                    root.add_observable(F_FILE, os.path.relpath(full_path, start=root.storage_dir))

                except Exception as e:
                    logging.error("unable to copy file from {} to {} for root {}: {}".format(
                                  _path, full_path, root, e))
                    abort(400)

            except Exception as e:
                logging.error("unable to deal with file {}: {}".format(f, e))
                report_exception()
                abort(400)

            #finally:
                #try:
                    #shutil.rmtree(temp_dir)
                #except Exception as e:
                    #logging.error("unable to delete temp dir {}: {}".format(temp_dir, e))

        try:
            if not root.save():
                logging.error("unable to save analysis")
                abort(Response("an error occured trying to save the alert - review the logs", 400))

            # if we received a submission for correlation mode then we go ahead and add it to the database
            if root.analysis_mode == ANALYSIS_MODE_CORRELATION:
                ALERT(root)

            # add this analysis to the workload
            root.schedule()

        except Exception as e:
            logging.error("unable to sync to database: {}".format(e))
            report_exception()
            abort(Response("an error occured trying to save the alert - review the logs", 400))

        return json_result({'result': {'uuid': root.uuid}})
    
    except Exception as e:
        logging.error("error processing submit: {}".format(e))
        report_exception()

        try:
            if os.path.isdir(root.storage_dir):
                logging.info("removing failed submit dir {}".format(root.storage_dir))
                shutil.rmtree(root.storage_dir)
        except Exception as e2:
            logging.error("unable to delete failed submit dir {}: {}".format(root.storage_dir, e))

        raise e

@analysis_bp.route('/resubmit/<uuid>', methods=['GET'])
def resubmit(uuid):
    try:
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(uuid))
        root.load()
        root.reset()
        root.schedule()
        return json_result({'result':'success'})
    except Exception as e:
        return json_result({'result':'failed', 'error':str(e)})

@analysis_bp.route('/<uuid>', methods=['GET'])
def get_analysis(uuid):

    storage_dir = storage_dir_from_uuid(uuid)
    if saq.CONFIG['engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    if not os.path.exists(storage_dir):
        abort(Response("invalid uuid {}".format(uuid), 400))

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()
    return json_result({'result': root.json})

@analysis_bp.route('/status/<uuid>', methods=['GET'])
def get_status(uuid):

    try:
        validate_uuid(uuid)
    except ValueError as e:
        abort(Response(str(e), 400))

    storage_dir = storage_dir_from_uuid(uuid)
    if saq.CONFIG['engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    if not os.path.exists(storage_dir):
        abort(Response("invalid uuid {}".format(uuid), 400))

    result = {
        'workload': None,
        'delayed_analysis': [],
        'locks': None,
        'alert': None
    }

    with get_db_connection() as db:
        c = db.cursor()

        # is this still in the workload?
        c.execute("""
SELECT 
    id, 
    uuid, 
    node_id, 
    analysis_mode, 
    insert_date
FROM
    workload
WHERE
    uuid = %s
""", (uuid,))
        row = c.fetchone()
        if row is not None:
            result['workload'] = {
                'id': row[0],
                'uuid': row[1],
                'node_id': row[2],
                'analysis_mode': row[3],
                'insert_date': row[4]
            }

        # is this an alert?
        c.execute("""
SELECT 
    id, 
    uuid,
    location,
    insert_date,
    storage_dir,
    disposition,
    disposition_time,
    detection_count
FROM
    alerts
WHERE
    uuid = %s
""", (uuid,))
        row = c.fetchone()
        if row is not None:
            result['alert'] = {
                'id': row[0],
                'uuid': row[1],
                'location': row[2],
                'insert_date': row[3],
                'storage_dir': row[4],
                'disposition': row[5],
                'disposition_time': row[6],
                'detection_count': row[7]
            }

        # is there any delayed analysis scheduled for it?
        c.execute("""
SELECT
    id,
    uuid,
    observable_uuid,
    analysis_module,
    insert_date,
    delayed_until,
    node_id
FROM
    delayed_analysis
WHERE
    uuid = %s
ORDER BY
    delayed_until
""", (uuid,))
        for row in c:
            result['delayed_analysis'].append({
                'id': row[0],
                'uuid': row[1],
                'observable_uuid': row[2],
                'analysis_module': row[3],
                'insert_date': row[4],
                'delayed_until': row[5],
                'node_id': row[6]
            })

        # are there any locks on it?
        c.execute("""
SELECT
    uuid,
    lock_uuid,
    lock_time,
    lock_owner
FROM
    locks
WHERE
    uuid = %s
""", (uuid,))
        row = c.fetchone()
        if row is not None:
            result['locks'] = {
                'uuid': row[0],
                'lock_uuid': row[1],
                'lock_time': row[2],
                'lock_owner': row[3]
            }

    return json_result({'result': result})

@analysis_bp.route('/details/<uuid>/<name>', methods=['GET'])
def get_details(uuid, name):
    storage_dir = storage_dir_from_uuid(uuid)
    if saq.CONFIG['engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()

    # find the analysis with this name
    for analysis in root.all_analysis:
        if analysis.external_details_path == name:
            #analysis.load()
            return json_result({'result': analysis.details})

    abort(Response("invalid uuid or invalid details name", 400))

@analysis_bp.route('/file/<uuid>/<file_uuid_or_name>', methods=['GET'])
def get_file(uuid, file_uuid_or_name):
    storage_dir = storage_dir_from_uuid(uuid)
    if saq.CONFIG['engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()

    # is this a UUID?
    try:
        validate_uuid(file_uuid_or_name)
        file_observable = root.get_observable(file_uuid_or_name)
        if file_observable is None:
            abort(Response("invalid file_uuid {}".format(file_uuid_or_name), 400))

    except ValueError:
        file_observable = root.find_observable(lambda o: o.type == F_FILE and o.value == file_uuid_or_name)
        if file_observable is None:
            abort(Response("invalid file name {}".format(file_uuid_or_name), 400))
        

    # NOTE we use an absolute path here because if we don't then
    # send_from_directory makes it relavive from the app root path
    # which is (/opt/ace/api)

    target_path = os.path.join(saq.SAQ_HOME, root.storage_dir, file_observable.value)
    if not os.path.exists(target_path):
        abort(Response("file path {} does not exist".format(target_path), 400))

    # XXX revisit how we save (name) files
    return send_from_directory(os.path.dirname(target_path), 
                               os.path.basename(target_path), 
                               as_attachment=True,
                               attachment_filename=os.path.basename(target_path).encode().decode('latin-1', errors='ignore'))
