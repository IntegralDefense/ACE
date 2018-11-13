# vim: sw=4:ts=4:et
#
# ACE API engine routines

import io
import logging
import os
import shutil
import tarfile
import tempfile
import threading

import saq
from .. import json_result, json_request
from saq.database import use_db
from saq.error import report_exception
from saq.util import validate_uuid, storage_dir_from_uuid

from flask import Blueprint, request, abort, Response, make_response

engine_bp = Blueprint('engine', __name__, url_prefix='/engine')

KEY_UUID = 'uuid'
KEY_LOCK_UUID = 'lock_uuid'

@engine_bp.route('/transfer/<uuid>', methods=['GET'])
def transfer(uuid):

    validate_uuid(uuid)

    target_dir = storage_dir_from_uuid(uuid)
    if not os.path.isdir(target_dir):
        logging.error("request to transfer unknown target {}".format(target_dir))
        abort(make_response("unknown target {}".format(target_dir), 400))
        #abort(Response("unknown target {}".format(target_dir)))

    logging.info("received request to transfer {} to {}".format(uuid, request.remote_addr))

    # create the tar file we're going to send back
    fp, path = tempfile.mkstemp(prefix="transfer_{}".format(uuid), suffix='.tar', 
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
