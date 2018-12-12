# vim: sw=4:ts=4:et:cc=120

import io
import json
import logging
import os, os.path
import re

from urllib.parse import urlparse, urlunparse

from .. import json_result

import saq
from saq.cloudphish import *
from saq.database import get_db_connection, execute_with_retry

from flask import Blueprint, request, abort, make_response, send_from_directory, redirect, url_for, Response

cloudphish_bp = Blueprint('cloudphish', __name__, url_prefix='/cloudphish')

@cloudphish_bp.before_app_first_request
def initialize():
    initialize_url_filter()

def _get_url_and_hash():

    # did the user pass in a url?
    url = request.values.get('url', None)
    sha256 = None

    if url is not None:
        try:
            # is it a valid encoding?
            url.encode('ascii')
            # yes? go ahead and get the hash too
            return url, hash_url(url)
        except Exception as e:
            error_message = "(encoded) url {} has non-ascii characters".format(url.encode('unicode_escape'))
            logging.info(error_message)
            abort(Response(error_message, 500))

    # otherwise, did the user pass in the sha256 hash of the url instead?
    sha256 = request.args.get('s', None)
    if sha256 is None:
        abort(Response("Invalid request (missing sha256)", 400))

    # make sure it's actually a hash
    if not re.match(r'^[a-fA-F0-9]{64}$', sha256):
        abort(Response("Invalid request (s is not a sha256 value)", 400))

    return None, sha256

@cloudphish_bp.route('/submit', methods=['GET', 'POST'])
def submit():
    url, _ = _get_url_and_hash()
    if not url:
        return "Invalid request.", 400

    reprocess = True if request.values.get('r', None) == '1' else False
    ignore_filters = True if request.values.get('ignore_filters', None) == '1' else False
    details = {}

    # to support any future changes we just store all of the variables that were passed in
    for key in request.values.keys():
        if key not in [ 'a', 'r', 'url' ]:
            details[key] = request.values.get(key)

    logging.info("received submission for {} reprocess {} details {}".format(url, reprocess, details))
    result = analyze_url(url, reprocess, ignore_filters, details)
    logging.debug("returning result {} for {}".format(result, url))
    return json_result(result.json())

@cloudphish_bp.route('/download', methods=['GET'])
def download():
    url, sha256_url = _get_url_and_hash()

    content_location = None
    content_file_name = None

    # get the sha256_content for this url
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT HEX(sha256_content) FROM cloudphish_analysis_results WHERE sha256_url = UNHEX(%s)",
                 (sha256_url,))
        row = c.fetchone()
        if row is None:
            return "Unknown URL", 404

        sha256_content = row[0]

    content_metadata = get_content_metadata(sha256_content)
    if not content_metadata:
        return "Unknown content", 404

    content_location, content_file_name = content_metadata
    # is this a different node?
    if content_location != saq.SAQ_NODE:
        # get the correct location for the node from the database
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("SELECT location FROM nodes WHERE name = %s", (content_location,))
            row = c.fetchone()
            if row is None:
                return "node {} no longer exists".format(content_location), 404

            # replace the netloc of this url with the new location 
            target_url = url_for('cloudphish.download', s=sha256_url, _external=True)
            parsed_url = list(urlparse(target_url))
            parsed_url[1] = row[0]
            target_url = urlunparse(parsed_url)

            logging.debug("sending redirect to {}".format(target_url))
            return redirect(target_url)

    path = os.path.join(saq.SAQ_HOME, saq.CONFIG['cloudphish']['cache_dir'], 
                        sha256_content[0:2].lower(), sha256_content.lower())

    if not os.path.exists(path):
        return "Unknown content path", 404

    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True, 
                               attachment_filename=content_file_name)

@cloudphish_bp.route('/clear_alert', methods=['GET'])
def clear_alert():
    url, sha256_url = _get_url_and_hash()

    row_count = 0
    with get_db_connection() as db:
        c = db.cursor()
        row_count = execute_with_retry(db, c, """UPDATE cloudphish_analysis_results SET result = 'CLEAR' 
                                                 WHERE sha256_url = UNHEX(%s)""", 
                                      (sha256_url,), commit=True)

    logging.info("request to clear cloudphish alert for {} row_count {}".format(url if url else sha256_url, row_count))

    response = make_response(json.dumps({'result': 'OK', 'row_count': row_count}))
    response.mime_type = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response, 200
