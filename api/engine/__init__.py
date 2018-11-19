# vim: sw=4:ts=4:et
#
# ACE API engine routines

import io
import json
import logging
import os
import os.path
import shutil
import tarfile
import tempfile
import threading

import saq
from .. import json_result, json_request
from saq.analysis import RootAnalysis
from saq.database import use_db
from saq.error import report_exception
from saq.util import validate_uuid, storage_dir_from_uuid

from flask import Blueprint, request, abort, Response, make_response

engine_bp = Blueprint('engine', __name__, url_prefix='/engine')

KEY_UUID = 'uuid'
KEY_LOCK_UUID = 'lock_uuid'

@engine_bp.route('/download/<uuid>', methods=['GET'])
def download(uuid):

    validate_uuid(uuid)

    target_dir = storage_dir_from_uuid(uuid)
    if not os.path.isdir(target_dir):
        logging.error("request to download unknown target {}".format(target_dir))
        abort(make_response("unknown target {}".format(target_dir), 400))
        #abort(Response("unknown target {}".format(target_dir)))

    logging.info("received request to download {} to {}".format(uuid, request.remote_addr))

    # create the tar file we're going to send back
    fp, path = tempfile.mkstemp(prefix="download_{}".format(uuid), suffix='.tar', 
                                dir=os.path.join(saq.SAQ_HOME, saq.CONFIG['global']['tmp_dir']))

    try:
        tar = tarfile.open(fileobj=os.fdopen(fp, 'wb'), mode='w|')
        tar.add(target_dir, '.')
        tar.close()

        os.lseek(fp, 0, os.SEEK_SET)

        def _iter_send():
            while True:
                data = os.read(fp, io.DEFAULT_BUFFER_SIZE)
                if data == b'':
                    raise StopIteration()
                yield data

        return Response(_iter_send(), mimetype='application/octet-stream')
            
    finally:
        try:
            os.remove(path)
        except:
            pass

KEY_UPLOAD_MODIFIERS = 'upload_modifiers'
KEY_OVERWRITE = 'overwrite'
KEY_ARCHIVE = 'archive'
KEY_SYNC = 'sync'

@engine_bp.route('/upload/<uuid>', methods=['POST'])
def upload(uuid):
    
    validate_uuid(uuid)

    if KEY_UPLOAD_MODIFIERS not in request.values:
        abort(Response("missing key {} in request".format(KEY_UPLOAD_MODIFIERS), 400))

    if KEY_ARCHIVE not in request.files:
        abort(Response("missing files key {}".format(KEY_ARCHIVE), 400))

    upload_modifiers = json.loads(request.values[KEY_UPLOAD_MODIFIERS])
    if not isinstance(upload_modifiers, dict):
        abort(Response("{} should be a dict".format(KEY_UPLOAD_MODIFIERS), 400))

    overwrite = False
    if KEY_OVERWRITE in upload_modifiers:
        overwrite = upload_modifiers[KEY_OVERWRITE]
        if not isinstance(overwrite, bool):
            abort(Response("{} should be a boolean".format(KEY_OVERWRITE), 400))

    sync = False
    if KEY_SYNC in upload_modifiers:
        sync = upload_modifiers[KEY_SYNC]
        if not isinstance(sync, bool):
            abort(Response("{} should be a boolean".format(KEY_SYNC), 400))

    logging.info("requested upload for {}".format(uuid))

    # does the target directory already exist?
    target_dir = storage_dir_from_uuid(uuid)
    if os.path.exists(target_dir):
        # are we over-writing it?
        if not overwrite:
            abort(Response("{} already exists (specify overwrite modifier to replace the data)".format(target_dir), 400))

        # if we are overwriting the entry then we need to completely clear the 
        # TODO implement this

    try:
        os.makedirs(target_dir)
    except Exception as e:
        logging.error("unable to create directory {}: {}".format(target_dir, e))
        report_exception()
        abort(Response("unable to create directory {}: {}".format(target_dir, e), 400))

    logging.debug("target directory for {} is {}".format(uuid, target_dir))

    # save the tar file so we can extract it
    fp, tar_path = tempfile.mkstemp(suffix='.tar', prefix='upload_{}'.format(uuid), dir=saq.CONFIG['global']['tmp_dir'])
    os.close(fp)

    try:
        request.files[KEY_ARCHIVE].save(tar_path)

        t = tarfile.open(tar_path, 'r|')
        t.extractall(path=target_dir)

        logging.debug("extracted {} to {}".format(uuid, target_dir))

        # update the root analysis to indicate it's new location 
        root = RootAnalysis(storage_dir=target_dir)
        root.load()

        root.location = saq.SAQ_NODE
        root.company_id = saq.COMPANY_ID
        root.company_name = saq.COMPANY_NAME

        root.save()

        if sync:
            root.schedule()

        # looks like it worked
        return json_result({'result': True})

    except Exception as e:
        logging.error("unable to upload {}: {}".format(uuid, e))
        report_exception()
        abort(Response("unable to upload {}: {}".format(uuid, e)))

    finally:
        try:
            os.remove(tar_path)
        except Exception as e:
            logging.error("unable to remove {}: {}".format(tar_path,e ))

@engine_bp.route('/clear/<uuid>/<lock_uuid>', methods=['GET'])
@use_db
def clear(uuid, lock_uuid, db, c):

    validate_uuid(uuid)
    validate_uuid(lock_uuid)

    # make sure this uuid is locked with with the given lock_uuid
    # this is less a security feature than it is a mistake-blocker :-)
    c.execute("SELECT uuid FROM locks WHERE uuid = %s AND lock_uuid = %s", (uuid, lock_uuid))
    row = c.fetchone()
    if row is None:
        logging.warning("request to clear uuid {} with invalid lock uuid {}".format(uuid, lock_uuid))
        abort(Response("nope", 400))

    target_dir = storage_dir_from_uuid(uuid)
    if not os.path.isdir(target_dir):
        logging.error("request to clear unknown target {}".format(target_dir))
        abort(Response("unknown target {}".format(target_dir)))

    logging.info("received request to clear {} from {}".format(uuid, request.remote_addr))
    
    try:
        shutil.rmtree(target_dir)
    except Exception as e:
        logging.error("unable to clear {}: {}".format(target_dir, e))
        report_exception()
        abort(Response("clear failed"))

    # looks like it worked
    return json_result({'result': True})
