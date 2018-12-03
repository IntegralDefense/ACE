# vim: sw=4:ts=4:et:cc=120

import io
import json
import logging
import os, os.path
import re

from .. import json_result

import saq
from saq.cloudphish import *
from saq.database import get_db_connection, execute_with_retry

from flask import Blueprint, request, abort, make_response, send_from_directory, redirect, url_for

cloudphish_bp = Blueprint('cloudphish', __name__, url_prefix='/cloudphish')

@cloudphish_bp.before_app_first_request
def initialize():
    initialize_url_filter()

@cloudphish_bp.route('/submit', methods=['GET', 'POST'])
def submit():
    #enable_cached_db_connections()

    url = request.values.get('url', None)
    if not url:
        return "Invalid request.", 400

    # XXX this is a hack but urls should be all ASCII anyways
    # so technically this changes the sha256 hash we get out of it but that's OK
    # because if it's not ASCII it's not a valid anyways
    url = url.encode('ascii', errors='ignore').decode('ascii')
    reprocess = True if request.values.get('r', None) == '1' else False
    ignore_filters = True if request.values.get('force', None) == '1' else False
    details = {}

    # to support any future changes we just store all of the variables that were passed in
    for key in request.values.keys():
        if key not in [ 'a', 'r', 'url' ]:
            details[key] = request.values.get(key)

    logging.info("received submission for {} reprocess {} details {}".format(url, reprocess, details))

    result = analyze_url(url, reprocess, ignore_filters, details)

    logging.debug("returning result {} for {}".format(result, url))
    return json_result(result.json())

@cloudphish_bp.route('/cloudphish/download', methods=['GET'])
def download():
    #enable_cached_db_connections()

    sha256 = request.args.get('s', None)
    if not sha256:
        return "Invalid request.", 400

    if not re.match(r'^[a-fA-F0-9]{64}$', sha256):
        return "Invalid request.", 400

    content_location = None
    content_file_name = None

    content_metadata = get_content_metadata(sha256)
    if content_metadata:
        content_location, content_file_name = content_metadata
        # is this a different node?
        if content_location != saq.SAQ_NODE:
            # TODO fix this
            return redirect('https://{}/cloudphish/download?s={}'.format(content_location, sha256))
    else:
        # otherwise we just don't know about it
        return "Unknown content", 404

    path = os.path.join(saq.SAQ_HOME, saq.CONFIG['cloudphish']['cache_dir'], sha256[0:2].lower(), sha256.lower())
    if not os.path.exists(path):
        return "Unknown content", 404

    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True, 
                               attachment_filename=content_file_name)

@cloudphish_bp.route('/cloudphish/download_alert', methods=['GET'])
def download_alert():
    #enable_cached_db_connections()

    sha256 = request.args.get('s', None)
    if not sha256:
        return "Invalid request.", 400

    if not re.match(r'^[a-fA-F0-9]{64}$', sha256):
        return "Invalid request.", 400

    # look up the alert uuid by the sha256_content
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT uuid FROM cloudphish_analysis_results WHERE result = 'ALERT' AND sha256_content = UNHEX(%s)",
                  (sha256, ))
        result = c.fetchone()
        if result is None:
            return "Unknown content", 404

        _uuid = result[0]
        return redirect(url_for('engine.download', uuid=_uuid))

@cloudphish_bp.route('/cloudphish/clear_alert', methods=['GET'])
def clear_alert():
    #enable_cached_db_connections()

    url = request.values.get('url', None)
    sha256 = request.values.get('sha256', None)

    if not url and not sha256:
        return "Invalid request (missing url or sha256.)", 400

    if url:
        url = url.encode('ascii', errors='ignore').decode('ascii')

    if not sha256:
        sha256 = hash_url(url)
        if not sha256:
            return "Invalid request.", 400

    if not re.match(r'^[a-fA-F0-9]{64}$', sha256):
        return "Invalid request (not a valid hash.)", 400

    row_count = 0
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""SELECT HEX(sha256_content) FROM cloudphish_analysis_results WHERE sha256_url = UNHEX(%s)""", 
                 (sha256,))

        row = c.fetchone()
        if row:
            sha256_content = row[0]
            row_count = execute_with_retry(db, c, """UPDATE cloudphish_analysis_results SET result = 'CLEAR' 
                                                     WHERE sha256_content = UNHEX(%s)""", 
                                          (sha256_content,), commit=True)
        else:
            logging.warning("missing url {} (sha256 {})".format(url, sha256))

    logging.info("request to clear cloudphish alert for {} row_count {}".format(url if url else sha256, row_count))

    response = make_response(json.dumps({'result': 'OK', 'row_count': row_count}))
    response.mime_type = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response, 200
