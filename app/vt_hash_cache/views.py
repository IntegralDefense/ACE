# vim: sw=4:ts=4:et:cc=120

import json
import logging

import memcache
import requests

import saq
from saq.database import get_db_connection, execute_with_retry, enable_cached_db_connections
from saq.error import report_exception

from app.vt_hash_cache import *

from flask import redirect, request, make_response, Response
import pymysql.err

HASH_TYPE_MD5 = 'MD5'
HASH_TYPE_SHA1 = 'SHA1'
HASH_TYPE_SHA2 = 'SHA2'

VT_KEY_MD5_HASH = 'md5'
VT_KEY_SHA1_HASH = 'sha1'
VT_KEY_SHA2_HASH = 'sha256'

@vt_hash_cache_bp.route('/vthc/query', methods=['GET'])
def query():

    #
    # NOTE
    # hashes are stored and compared in LOWER CASE
    #

    # let's be backwards compatible with VT, eh?
    if 'resource' in request.values:
        _hash = request.values['resource'].lower()
    else:
        _hash = request.values['h'].lower()

    _hash_type = None
    result_id = None
    vt_result = None
    md5_hash = None
    sha1_hash = None
    sha2_hash = None
    
    # determine the type by the lenght of the hash
    if len(_hash) == 32:
        _hash_type = HASH_TYPE_MD5
    elif len(_hash) == 40:
        _hash_type = HASH_TYPE_SHA1
    elif len(_hash) == 64:
        _hash_type = HASH_TYPE_SHA2
    else:
         return "invalid hash", 500

    # do we already have a cached query result for this?
    client = memcache.Client(['unix:/opt/saq/var/memcached.socket'], debug=0)
    result_id = client.get(_hash)

    if result_id:
        vt_result = client.get(str(result_id))

    if vt_result:
        logging.info("vt cache hit for {}".format(_hash))

    if result_id is None or vt_result is None:
        # if not then look it up in the database
        with get_db_connection('vt_hash_cache') as db:
            c = db.cursor()

            if _hash_type == HASH_TYPE_MD5:
                column = 'md5'
            elif _hash_type == HASH_TYPE_SHA1:
                column = 'sha1'
            elif _hash_type == HASH_TYPE_SHA2:
                column = 'sha2'

            # there could potentionally be multiple rows
            # get the latest result
            c.execute("""SELECT result_id, insert_date, result, 
                                md5, sha1, sha2 FROM result_cache WHERE {} = %s
                                ORDER BY insert_date DESC LIMIT 1""".format(column), (_hash,))
            row = c.fetchone()
            if not row:
                # if we don't have it in the database then we perform a query here
                try:
                    logging.info("vt api request for {}".format(_hash))
                    r = requests.get(saq.CONFIG['virus_total']['query_url'], params={
                        'resource': _hash,
                        'apikey': saq.CONFIG['virus_total']['api_key']}, proxies=saq.PROXIES, timeout=5)
                except Exception as e:
                    return "unable to query VT: {}".format(e), 500

                if r.status_code == 403:
                    return "invalid virus total api key", 500

                if r.status_code != 200:
                    return "got invalid HTTP result {}: {}".format(r.status_code, r.reason), 500

                # note that here were just using whatever virus total sends
                # if they change their JSON structure we'll probably break

                logging.info("got valid vt result for {}".format(_hash))
                vt_result = r.content.decode() # JSON string format

                # VT gives us all three hashes in it's results
                try:
                    vt_json = json.loads(vt_result)
                except Exception as e:
                    logging.error("unable to load json for {}: {}".format(_hash, e))
                    return "invalid json result", 500

                if isinstance(vt_json, list):
                    if len(vt_json) > 1:
                        logging.warning("vt result has more than one entry for {}".format(_hash))
                    vt_json = vt_json[0]

                md5_hash = None
                sha1_hash = None
                sha2_hash = None

                if _hash_type == HASH_TYPE_MD5:
                    md5_hash = _hash
                elif VT_KEY_MD5_HASH in vt_json:
                    md5_hash = vt_json[VT_KEY_MD5_HASH].lower()

                if _hash_type == HASH_TYPE_SHA1:
                    sha1_hash = _hash
                elif VT_KEY_SHA1_HASH in vt_json:
                    sha1_hash = vt_json[VT_KEY_SHA1_HASH].lower()

                if _hash_type == HASH_TYPE_SHA2:
                    sha2_hash = _hash
                elif VT_KEY_SHA2_HASH in vt_json:
                    sha2_hash = vt_json[VT_KEY_SHA2_HASH].lower()

                c.execute("""INSERT INTO result_cache ( result, md5, sha1, sha2 ) 
                             VALUES ( %s, %s, %s, %s )""", ( vt_result, md5_hash, sha1_hash, sha2_hash))
                result_id = c.lastrowid
                if not result_id:
                    logging.error("unable to get result_id after INSERT")
                    return "database error (see logs)", 500
                db.commit()

            else:
                logging.info("vt db hit for {}".format(_hash))
                
                # database results are available
                result_id, insert_date, vt_result, md5_hash, sha1_hash, sha2_hash = row

    if not result_id:
        return "Result unavailable", 500

    if not result_id:
        return "VT Result unavailable", 500

    # now cache the result
    if md5_hash:
        client.set(md5_hash, str(result_id))
    if sha1_hash:
        client.set(sha1_hash, str(result_id))
    if sha2_hash:
        client.set(sha2_hash, str(result_id))

    client.set(str(result_id), vt_result)
        
    response = make_response(vt_result)
    response.mime_type = 'application/json'
    return response, 200
