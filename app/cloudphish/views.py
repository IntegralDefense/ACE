# vim: sw=4:ts=4:et:cc=120

import datetime
import hashlib
import io
import json
import logging
import os.path
import pickle
import re
import socket
import uuid

from subprocess import Popen, PIPE, DEVNULL
from urllib.parse import urlparse

import saq
from saq.analysis import RootAnalysis
from saq.crawlphish import CrawlphishURLFilter
from saq.cloudphish import *
from saq.constants import *
from saq.database import get_db_connection, execute_with_retry, enable_cached_db_connections
from saq.error import report_exception

from app.cloudphish import *

from flask import redirect, request, make_response, send_from_directory, Response
import pymysql.err

@cloudphish.before_app_first_request
def initialize():
    initialize_url_filter()

# in this experiment we find that the thread id changes but the process ID stays the same
# when running this under apache
@cloudphish.route('/cloudphish/debug', methods=['GET'])
def debug():

    import threading
    import os

    message = """

current thread id = {}
current pid = {}
thread count = {}

""".format(threading.get_ident(), os.getpid(), threading.active_count())
    
    return message, 200

@cloudphish.route('/cloudphish/submit', methods=['GET', 'POST'])
def submit():
    enable_cached_db_connections()

    url = request.values.get('url', None)
    if not url:
        return "Invalid request.", 400

    # XXX this is a hack but urls should be all ASCII anyways
    # so technically this changes the sha256 hash we get out of it but that's OK
    # because if it's not ASCII it's not a valid anyways
    url = url.encode('ascii', errors='ignore').decode('ascii')

    reprocess = True if request.values.get('r', None) == '1' else False
    alertable = True if request.values.get('a', None) == '1' else False
    details = {}

    # to support any future changes we just store all of the variables that were passed in
    for key in request.values.keys():
        if key not in [ 'a', 'r', 'url' ]:
            details[key] = request.values.get(key)

    logging.info("received submission for {} reprocess {} alertable {}".format(url, reprocess, alertable))

    result = analyze_url(url, reprocess, alertable, **details)
    logging.debug("returning result {} for {}".format(result, url))
    response = make_response(json.dumps(result.json(), sort_keys=True, indent=4))
    response.mime_type = 'application/json'
    return response, 200

@cloudphish.route('/cloudphish/download', methods=['GET'])
def download():
    enable_cached_db_connections()

    sha256 = request.args.get('s', None)
    if not sha256:
        return "Invalid request.", 400

    if not re.match(r'^[a-fA-F0-9]{64}$', sha256):
        return "Invalid request.", 400

    path = os.path.join(saq.SAQ_HOME, saq.CONFIG['cloudphish']['cache_dir'], sha256[0:2].lower(), sha256.lower())
    if not os.path.exists(path):
        # if we don't have the content see if it's on another node
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""SELECT location FROM content_metadata WHERE sha256_content = UNHEX(%s)""", (sha256,))
            row = c.fetchone()
            if row:
                content_location = row[0]
                # is this a different node?
                if content_location != saq.CONFIG['engine_cloudphish']['location']:
                    return redirect('https://{}/cloudphish/download?s={}'.format(content_location, sha256))

        # otherwise we just don't know about it
        return "Unknown content", 404
            

    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True)

@cloudphish.route('/cloudphish/download_alert', methods=['GET'])
def download_alert():
    enable_cached_db_connections()

    sha256 = request.args.get('s', None)
    if not sha256:
        return "Invalid request.", 400

    if not re.match(r'^[a-fA-F0-9]{64}$', sha256):
        return "Invalid request.", 400

    path = os.path.join(saq.SAQ_HOME, saq.CONFIG['cloudphish']['cache_dir'], sha256[0:2].lower(), sha256.lower())
    if not os.path.exists(path):
        # if we don't have the content see if it's on another node
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""SELECT location FROM content_metadata WHERE sha256_content = UNHEX(%s)""", (sha256,))
            row = c.fetchone()
            if row:
                content_location = row[0]
                # is this a different node?
                if content_location != saq.CONFIG['engine_cloudphish']['location']:
                    return redirect('https://{}/cloudphish/download_alert?s={}'.format(content_location, sha256))

        # otherwise we just don't know about it
        return "Unknown content", 404

    ace_path = '{}.ace.tar.gz'.format(path)
    if not os.path.exists(ace_path):
        return "No alert data.", 404

    def return_alert():
        with open(ace_path, 'rb') as fp:
            while True:
                _buffer = fp.read(io.DEFAULT_BUFFER_SIZE)
                if _buffer == b'':
                    break

                yield _buffer

    return Response(return_alert(), mimetype='application/gzip')

@cloudphish.route('/cloudphish/clear_alert', methods=['GET'])
def clear_alert():
    enable_cached_db_connections()

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
    with get_db_connection('cloudphish') as db:
        c = db.cursor()
        c.execute("""SELECT HEX(sha256_content) FROM analysis_results WHERE sha256_url = UNHEX(%s)""", (sha256,))
        row = c.fetchone()
        if row:
            sha256_content = row[0]
            c.execute("""UPDATE analysis_results SET result = 'CLEAR' WHERE sha256_content = UNHEX(%s)""", (sha256_content,))
            row_count = c.rowcount
            db.commit()
        else:
            logging.warning("missing url {} (sha256 {})".format(url, sha256))

    logging.info("request to clear cloudphish alert for {} row_count {}".format(url if url else sha256, row_count))

    response = make_response(json.dumps({'result': 'OK', 'row_count': row_count}))
    response.mime_type = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response, 200
