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
from saq.constants import *
from saq.util import parse_event_time

from flask import Blueprint, request, abort, Response
from werkzeug import secure_filename

analysis_bp = Blueprint('analysis', __name__, url_prefix='/analysis')

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

@alert_bp.route('/submit', methods=['POST'])
def submit():

    if 'alert' not in request.values:
        abort(Response("missing alert field (see documentation)", 400))

    r = json.loads(request.values['alert'])

    # the specified company needs to match the company of this node
    # TODO eventually we'll have a single node that serves API to all configured companies

    if KEY_COMPANY_NAME in r and r[KEY_COMPANY_NAME] != saq.CONFIG['global']['company_name']:
        abort(Response("wrong company {} (are you sending to the correct system?)".format(r[KEY_COMPANY_NAME]), 400))

    if KEY_DESCRIPTION not in r:
        abort(Response("missing {} field in submission".format(KEY_DESCRIPTION), 400))

    root = RootAnalysis()
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

    # TODO add a try/catch to clean up a failed upload

    # go ahead and allocate storage
    root.uuid = str(uuid.uuid4())
    # XXX use temp dir instead...
    root.storage_dir = os.path.join(saq.CONFIG['global']['data_dir'], saq.SAQ_NODE, root.uuid[0:3], root.uuid)
    root.initialize_storage()

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

    # save the files to disk and add them as observables of type file
    for f in request.files.getlist('file'):
        logging.debug("recording file {}".format(f.filename))
        temp_dir = tempfile.mkdtemp(dir=saq.CONFIG.get('server', 'incoming_dir'))
        _path = os.path.join(temp_dir, secure_filename(f.filename))
        try:
            if os.path.exists(_path):
                logging.error("duplicate file name {}".format(_path))
                abort(400)

            logging.debug("saving file to {}".format(_path))
            try:
                f.save(_path)
            except Exception as e:
                logging.error("unable to save file to {}: {}".format(_path, e))
                abort(400)

            full_path = os.path.join(root.storage_dir, f.filename)

            try:
                dest_dir = os.path.dirname(full_path)
                if not os.path.isdir(dest_dir):
                    try:
                        os.makedirs(dest_dir)
                    except Exception as e:
                        logging.error("unable to create directory {}: {}".format(dest_dir, e))
                        abort(400)

                logging.debug("copying file {} to {}".format(_path, full_path))
                shutil.copy(_path, full_path)

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

        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temp dir {}: {}".format(temp_dir, e))

    try:
        if not root.save():
            logging.error("unable to save analysis")
            abort(Response("an error occured trying to save the alert - review the logs", 400))

        # add this analysis to the workload
        root.schedule()

    except Exception as e:
        logging.error("unable to sync to database: {}".format(e))
        report_exception()
        abort(Response("an error occured trying to save the alert - review the logs", 400))

    return json_result({'result': {'id': alert.id, 'uuid': alert.uuid}})

@alert_bp.route('/<alert_id>', methods=['GET'])
def get_alert(alert_id):

    query = db.session.query(Alert)

    try:
        # assume its a database integer
        query = query.filter(Alert.id == int(alert_id))
    except ValueError:
        # if not then assume its a uuid
        query = query.filter(Alert.uuid == alert_id)

    try:
        alert = query.one()
    except Exception as e:
        return json_result({'result': None})

    alert.load()
    return json_result({'result': alert.json})
