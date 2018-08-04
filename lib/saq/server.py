# vim: sw=4:ts=4:et

# Network Server
# accepts incoming alerts

# version 1.0 - original version
# version 1.1 - way improved schema
# version 1.2 - added is_suspect to observables
# version 1.3 - ? (never documented)
# version 1.4 - removed is_suspect from observables (no longer required)
#             - added detection_points
#             - backwards compatible with 1.3
# version 1.5 - added company_name
#             - backwares compatible with 1.3

import logging
import json
import os.path
import tempfile
import shutil

from config import config
import saq
from saq.error import report_exception
from saq.database import Alert
from saq.constants import *

from flask import Flask, request
from werkzeug import secure_filename
app = Flask(__name__)
app.config.from_object(config[saq.CONFIG['global']['instance_type']])

# see the end of the file for the protocol handler map

@app.route('/submit_alert', methods=['POST'])
def accept_alert(*args, **kwargs):
    assert saq.CONFIG is not None

    # did this request include a protocol version?
    # if it did not then we default to version 1.0 (which did not include the version in the request)
    protocol_version = '1.0'
    if 'protocol_version' in request.values:
        protocol_version = request.values['protocol_version']

    logging.info("client {} using procotol version {}".format(request.remote_addr, protocol_version))

    request_handler = None
    try:
        request_handler = protocol_handler_map[protocol_version]
    except KeyError:
        logging.error("invalid protocol version {0}".format(protocol_version))
        return "", 500
    
    return request_handler(*args, **kwargs)

def request_handler_1_3():
    assert saq.CONFIG is not None

    # TODO actually use the library
    # protocol constants copied over from the client library ;)
    KEY_ID = 'id'
    KEY_UUID = 'uuid'
    KEY_TOOL = 'tool'
    KEY_TOOL_INSTANCE = 'tool_instance'
    KEY_TYPE = 'type'
    KEY_DESCRIPTION = 'description'
    KEY_EVENT_TIME = 'event_time'
    KEY_DETAILS = 'details'
    KEY_OBSERVABLES = 'observables'
    KEY_TAGS = 'tags'
    KEY_NAME = 'name'
    KEY_COMPANY_NAME = 'company_name'

    # client passes in the JSON contents of the alert
    contents = json.loads(request.form['alert'])

    alert = Alert()
    alert.uuid = contents[KEY_UUID]
    alert.storage_dir = os.path.join(saq.CONFIG['global']['data_dir'], saq.SAQ_NODE, alert.uuid[0:3], alert.uuid)
    alert.initialize_storage()
    alert.tool = contents[KEY_TOOL]
    alert.tool_instance = contents[KEY_TOOL_INSTANCE]
    alert.alert_type = contents[KEY_TYPE]
    alert.description = contents[KEY_DESCRIPTION]
    alert.event_time = contents[KEY_EVENT_TIME]
    alert.details = contents[KEY_DETAILS]

    if KEY_NAME in contents:
        alert.name = contents[KEY_NAME]

    if KEY_COMPANY_NAME in contents and contents[KEY_COMPANY_NAME]:
        alert.company_name = contents[KEY_COMPANY_NAME]
    else:
        alert.company_name = saq.CONFIG['global']['company_name']

    # add all the specified observables
    # each key in the observable dictionary is the type
    for o_type in contents[KEY_OBSERVABLES].keys():
        # protocol verison 1.2 only had two elements (value, time)
        # version 1.3 has four (value, time, is_suspect, directives)
        for values in contents[KEY_OBSERVABLES][o_type]:
            o_value = values[0]
            o_time = values[1]
            is_suspect = values[2] # DEPRECATED
            directives = values[3]

            o = alert.add_observable(o_type, o_value, o_time)
            if o:
                for directive in directives:
                    o.add_directive(directive)

    # add all the specified tags
    for tag in contents[KEY_TAGS]:
        alert.add_tag(tag)

    # save the files to disk and add them as observables of type file
    for f in request.files.getlist('data'):
        logging.debug("recording file {}".format(f.filename))
        temp_dir = tempfile.mkdtemp(dir=saq.CONFIG.get('server', 'incoming_dir'))
        _path = os.path.join(temp_dir, secure_filename(f.filename))
        try:
            if os.path.exists(_path):
                logging.error("duplicate file name {}".format(_path))
                raise RuntimeError("duplicate file name {}".format(_path))

            logging.debug("saving file to {}".format(_path))
            try:
                f.save(_path)
            except Exception as e:
                logging.error("unable to save file to {}: {}".format(_path, e))
                raise e

            full_path = os.path.join(alert.storage_dir, f.filename)

            try:
                dest_dir = os.path.dirname(full_path)
                if not os.path.isdir(dest_dir):
                    try:
                        os.makedirs(dest_dir)
                    except Exception as e:
                        logging.error("unable to create directory {}: {}".format(dest_dir, e))
                        raise e

                logging.debug("copying file {} to {}".format(_path, full_path))
                shutil.copy(_path, full_path)

                # add this as a F_FILE type observable
                alert.add_observable(F_FILE, os.path.relpath(full_path, start=alert.storage_dir))

            except Exception as e:
                logging.error("unable to copy file from {} to {} for alert {}: {}".format(
                              _path, full_path, alert, e))
                raise e

        except Exception as e:
            logging.error("unable to deal with file {}: {}".format(f, e))
            report_exception()
            return "", 500

        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temp dir {}: {}".format(temp_dir, e))

    try:
        if not alert.sync():
            logging.error("unable to sync alert")
            return "", 500

        # send the alert to the automated analysis engine
        alert.request_correlation()

    except Exception as e:
        logging.error("unable to sync to database: {}".format(e))
        report_exception()
        return "", 500

    return str(alert.id), 200

def request_handler_1_2():
    assert saq.CONFIG is not None

    # TODO actually use the library
    # protocol constants copied over from the client library ;)
    KEY_ID = 'id'
    KEY_UUID = 'uuid'
    KEY_TOOL = 'tool'
    KEY_TOOL_INSTANCE = 'tool_instance'
    KEY_TYPE = 'type'
    KEY_DESCRIPTION = 'description'
    KEY_EVENT_TIME = 'event_time'
    KEY_DETAILS = 'details'
    KEY_OBSERVABLES = 'observables'
    KEY_TAGS = 'tags'
    KEY_ATTACHMENTS = 'attachments'
    KEY_NAME = 'name'

    # client passes in the JSON contents of the alert
    contents = json.loads(request.form['alert'])

    alert = Alert()

    # set all of the properties individually
    # XXX fix me
    # it looks like the construction logic doesn't quite work here
    # when loading from the arguments to the constructor, the internal
    # variables with leading underscores get set rather than the properties
    # representing the database columns it was designed that way to allow the
    # JSON stuff to work correctly, so I'll need to revisit that later

    alert.uuid = contents[KEY_UUID]
    alert.storage_dir = os.path.join(saq.CONFIG['global']['data_dir'], saq.SAQ_NODE, alert.uuid[0:3], alert.uuid)
    alert.initialize_storage()
    alert.tool = contents[KEY_TOOL]
    alert.tool_instance = contents[KEY_TOOL_INSTANCE]
    alert.alert_type = contents[KEY_TYPE]
    alert.description = contents[KEY_DESCRIPTION]
    alert.event_time = contents[KEY_EVENT_TIME]
    alert.details = contents[KEY_DETAILS]

    # XXX shame on me for not testing well enough
    if KEY_NAME in contents:
        alert.name = contents[KEY_NAME]

    # add all the specified observables
    # each key in the observable dictionary is the type
    for o_type in contents[KEY_OBSERVABLES].keys():
        # protocol verison 1.2 only had two elements (value, time)
        # version 1.3 has three (value, time, is_suspect)
        for values in contents[KEY_OBSERVABLES][o_type]:
            o_value = values[0]
            o_time = values[1]
            is_suspect = False # deprecated
            if len(values) > 2:
                is_suspect = values[2]

            alert.add_observable(o_type, o_value, o_time)

    # add all the specified tags
    for tag in contents[KEY_TAGS]:
        alert.add_tag(tag)

    #alert._materialize()

    # save the attachments to disk and add them as observables of type file
    for f in request.files.getlist('data'):
        logging.debug("recording file {0}".format(f.filename))
        # XXX why not just save straight to the destination address?
        temp_dir = tempfile.mkdtemp(dir=saq.CONFIG.get('server', 'incoming_dir'))
        _path = os.path.join(temp_dir, secure_filename(f.filename))
        try:
            if os.path.exists(_path):
                logging.error("duplicate file name {0}".format(_path))
                raise RuntimeError("duplicate file name {0}".format(_path))

            logging.debug("saving file to {0}".format(_path))
            try:
                f.save(_path)
            except Exception as e:
                logging.error("unable to save file to {0}: {1}".format(_path, str(e)))
                raise e

            full_path = os.path.join(alert.storage_dir, f.filename)

            try:
                dest_dir = os.path.dirname(full_path)
                if not os.path.isdir(dest_dir):
                    try:
                        os.makedirs(dest_dir)
                    except Exception as e:
                        logging.error("unable to create directory {0}: {1}".format(dest_dir, str(e)))
                        raise e

                logging.debug("copying file {0} to {1}".format(_path, full_path))
                shutil.copy(_path, full_path)

                # add this as a F_FILE type observable
                alert.add_observable(F_FILE, os.path.relpath(full_path, start=alert.storage_dir))

            except Exception as e:
                logging.error("unable to copy file from {0} to {1} for alert {2}: {3}".format(
                    _path, full_path, alert, str(e)))
                raise e

        except Exception as e:
            logging.error("unable to deal with file {0}: {1}".format(f, str(e)))
            report_exception()
            return "", 500

        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temp dir {0}: {1}".format(temp_dir, str(e)))

    try:
        if not alert.sync():
            logging.error("unable to sync alert")
            return "", 500

        # send the alert to the automated analysis engine
        alert.request_correlation()

    except Exception as e:
        logging.error("unable to sync to database: {0}".format(str(e)))
        report_exception()
        return "", 500

    return str(alert.id), 200

def request_handler_1_0():
    assert saq.CONFIG is not None

    logging.warning("using deprecated network protocol")

    # client passes in the JSON contents of the alert
    contents = json.loads(request.form['alert'])

    # create a new Alert object - this already comes with an ID we can use
    # note that we use network_json here since this is a new alert coming across the wire
    alert = Alert(network_json=contents)

    # we need somewhere to store this alert
    alert.storage_dir = os.path.join(saq.CONFIG['global']['data_dir'], saq.SAQ_NODE, alert.uuid[0:3], alert.uuid)
    alert.initialize_storage()
    alert._materialize()

    # save the attachments to disk
    # XXX I think that this will only allow attachments into the main (root) directory of the alert
    # TODO - support relative directories here
    for f in request.files.getlist('data'):
        logging.debug("recording file {0}".format(f.filename))
        temp_dir = tempfile.mkdtemp(dir=saq.CONFIG.get('server', 'incoming_dir'))
        _path = os.path.join(temp_dir, secure_filename(f.filename))
        try:
            if os.path.exists(_path):
                logging.error("duplicate file name {0}".format(_path))
                raise RuntimeError("duplicate file name {0}".format(_path))

            logging.debug("saving file to {0}".format(_path))
            try:
                f.save(_path)
            except Exception as e:
                logging.error("unable to save file to {0}: {1}".format(_path, str(e)))
                raise e

            full_path = os.path.join(alert.storage_dir, f.filename)

            try:
                dest_dir = os.path.dirname(full_path)
                if not os.path.isdir(dest_dir):
                    os.makedirs(dest_dir)

                logging.debug("copying file {0} to {1}".format(_path, full_path))
                shutil.copy(_path, full_path)

            except Exception as e:
                logging.error("unable to copy file from {0} to {1} for alert {2}: {3}".format(
                    _path, full_path, alert, str(e)))
                raise e

        except Exception as e:
            report_exception()
            return "", 500

        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error("unable to delete temp dir {0}: {1}".format(temp_dir, str(e)))

    # update the attachment paths
    for attachment in alert.attachments:
        logging.debug("moving reference for {0} to {1}".format(attachment.path, alert.storage_dir))
        attachment.path = os.path.join(alert.storage_dir, attachment.path)

    attempt = 0
    while attempt < 3:
        try:
            if not alert.sync():
                logging.error("unable to submit alert")
                return "", 500
            else:
                # send the alert to the automated analysis engine
                alert.request_correlation()

                break
        except Exception as e:
            logging.error("unable to sync to database: {0}".format(str(e)))
            attempt += 1
            if attempt < 3:
                continue

            return "", 500

    return str(alert.id), 200

# this defines what functions to call based on the protocol version
protocol_handler_map = {
    '1.0': request_handler_1_0,
    '1.1': request_handler_1_2,
    '1.2': request_handler_1_2,
    '1.3': request_handler_1_3,
    '1.4': request_handler_1_3,
    '1.5': request_handler_1_3
}
