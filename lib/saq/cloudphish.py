# vim: sw=4:ts=4:et:cc=120
# constants used by cloudphish

import datetime
import logging
import hashlib
import pickle
import uuid

from urllib.parse import urlparse

import saq
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.crawlphish import CrawlphishURLFilter
from saq.database import execute_with_retry, use_db
from saq.error import report_exception
from saq.util import storage_dir_from_uuid

import pymysql.err

__all__ = [ 
    'RESULT_OK',
    'RESULT_ERROR',
    'KEY_RESULT',
    'KEY_DETAILS',
    'KEY_STATUS',
    'KEY_ANALYSIS_RESULT',
    'KEY_HTTP_RESULT',
    'KEY_HTTP_MESSAGE',
    'KEY_SHA256_CONTENT',
    'KEY_SHA256_URL',
    'KEY_LOCATION',
    'KEY_FILE_NAME',
    'KEY_UUID',
    'STATUS_NEW',
    'STATUS_ANALYZING',
    'STATUS_ANALYZED',
    'SCAN_RESULT_UNKNOWN',
    'SCAN_RESULT_ERROR',
    'SCAN_RESULT_CLEAR',
    'SCAN_RESULT_ALERT',
    'SCAN_RESULT_PASS',
    'hash_url',
    'get_cached_analysis',
    'create_analysis',
    'initialize_url_filter',
    'analyze_url',
    'KEY_DETAILS_URL',
    'KEY_DETAILS_SHA256_URL',
    'KEY_DETAILS_ALERTABLE',
    'KEY_DETAILS_CONTEXT',
    'update_cloudphish_result',
    'update_content_metadata',
    'get_content_metadata',
]

# json schema
# KEY_RESULT: RESULT_OK | RESULT_ERROR
# KEY_DETAILS: str (reason for error)
# KEY_STATUS: STATUS_* (current analysis status of this url)
# KEY_ANALYSIS_RESULT: SCAN_RESULT_* (analysis result of the url)
# KEY_HTTP_RESULT: http status code (200, 404, etc...)
# KEY_HTTP_MESSAGE: server description of status code OR detailed reason for SCAN_RESULT_PASS
# KEY_SHA256_CONTENT: the sha256 hash of the content that was downloaded from this url
# KEY_LOCATION: the server hosting the content
# KEY_FILE_NAME: the name of the file that was downloaded from the url

RESULT_OK = 'OK'
RESULT_ERROR = 'ERROR'

KEY_RESULT = 'result'
KEY_DETAILS = 'details'
KEY_STATUS = 'status'
KEY_ANALYSIS_RESULT = 'analysis_result'
KEY_HTTP_RESULT = 'http_result'
KEY_HTTP_MESSAGE = 'http_message'
KEY_SHA256_CONTENT = 'sha256_content'
KEY_SHA256_URL = 'sha256_url'
KEY_LOCATION = 'location'
KEY_FILE_NAME = 'file_name'
KEY_UUID = 'uuid'

STATUS_NEW = 'NEW'
STATUS_ANALYZING = 'ANALYZING'
STATUS_ANALYZED = 'ANALYZED'

SCAN_RESULT_UNKNOWN = 'UNKNOWN'
SCAN_RESULT_ERROR = 'ERROR'
SCAN_RESULT_CLEAR = 'CLEAR'
SCAN_RESULT_ALERT = 'ALERT'
SCAN_RESULT_PASS = 'PASS'

KEY_DETAILS_URL = 'url'
KEY_DETAILS_SHA256_URL = 'sha256_url'
KEY_DETAILS_ALERTABLE = 'alertable'
KEY_DETAILS_CONTEXT = 'context'

# some utility functions
@use_db
def update_cloudphish_result(
    sha256_url,
    http_result_code=None,
    http_message=None,
    sha256_content=None,
    result=None,
    status=None, 
    db=None, c=None):
    
    sql = []
    params = []

    if http_result_code is not None:
        sql.append('http_result_code = %s')
        params.append(http_result_code)

    if http_message is not None:
        sql.append('http_message = %s')
        params.append(http_message[:256])

    if sha256_content is not None:
        sql.append('sha256_content = UNHEX(%s)')
        params.append(sha256_content)

    if result is not None:
        sql.append('result = %s')
        params.append(result)

    if status is not None:
        sql.append('status = %s')
        params.append(status)

    if not sql:
        logging.warning("update_cloudphish_result called for {} but nothing was passed in to update?".format(sha256_url))
        return

    params.append(sha256_url)

    sql = "UPDATE cloudphish_analysis_results SET {} WHERE sha256_url = UNHEX(%s)".format(', '.join(sql))
    logging.debug("executing cloudphish update {}".format(sql, params))
    return execute_with_retry(db, c, sql, tuple(params), commit=True)

@use_db
def update_content_metadata(sha256_content, node, file_name, db, c):
    return execute_with_retry(db, c, """
INSERT INTO cloudphish_content_metadata ( sha256_content, node, name ) VALUES ( UNHEX(%s), %s, %s )
ON DUPLICATE KEY UPDATE node = %s, name = %s""", ( sha256_content, node, file_name, node, file_name ), commit=True)

@use_db
def get_content_metadata(sha256_content, db, c):
    assert isinstance(sha256_content, str) and sha256_content
    c.execute("SELECT node, name FROM cloudphish_content_metadata WHERE sha256_content = UNHEX(%s)", 
              sha256_content)
    row = c.fetchone()
    if row is None:
        return None

    return row[0], row[1].decode('unicode_internal')

# global url filter
url_filter = None

def initialize_url_filter():
    global url_filter
    # initialize the crawlphish url filter
    url_filter = CrawlphishURLFilter()
    # TODO schedule tasks to reload lists
    url_filter.load()
    logging.debug("url filter loaded")

def hash_url(url):
    """Returns a sha256 hash of the given URL."""
    h = hashlib.sha256()
    h.update(url.encode('ascii', errors='ignore'))
    return h.hexdigest()

class CloudphishAnalysisResult(object):
    def __init__(self, result, details, status=None, analysis_result=None, http_result=None, http_message=None,
                 sha256_content=None, sha256_url=None, location=None, file_name=None, uuid=None):

        self.result = result
        self.details = details
        self.status = status
        self.analysis_result = analysis_result
        self.http_result = http_result
        self.http_message = http_message
        self.sha256_content = sha256_content
        self.sha256_url = sha256_url
        self.location = location
        self.file_name = file_name
        self.uuid = uuid

    def json(self):
        return { KEY_RESULT: self.result,
                 KEY_DETAILS: self.details,
                 KEY_STATUS: self.status,
                 KEY_ANALYSIS_RESULT: self.analysis_result,
                 KEY_HTTP_RESULT: self.http_result,
                 KEY_HTTP_MESSAGE: self.http_message,
                 KEY_SHA256_CONTENT: self.sha256_content,
                 KEY_SHA256_URL: self.sha256_url,
                 KEY_LOCATION: self.location,
                 KEY_FILE_NAME: self.file_name,
                 KEY_UUID: self.uuid }

    def __str__(self):
        return "CloudphishAnalysisResult(result:{},details:{},status:{},analysis_result:{},http_result:{}," \
               "http_message:{},sha256_content:{},sha256_url:{},location:{},file_name:{},uuid:{})".format(
            self.result, self.details, self.status, self.analysis_result, self.http_result, self.http_message,
            self.sha256_content, self.sha256_url, self.location, self.file_name, self.uuid)
    
    def __repr__(self):
        return str(self)

def get_cached_analysis(url):
    """Returns the CloudphishAnalysisResult of the cached analysis or None if analysis is not cached."""
    try:
        return _get_cached_analysis(url)
    except Exception as e:
        message = "Unable to get analysis for url {}: {}".format(url, e)
        logging.error(message)
        report_exception()

        return CloudphishAnalysisResults(RESULT_ERROR, message)

@use_db
def _get_cached_analysis(url, db, c):
    sha256 = hash_url(url)

    # have we already requested and/or processed this URL before?
    c.execute("""SELECT
                     ar.status,
                     ar.result,
                     ar.http_result_code,
                     ar.http_message,
                     HEX(ar.sha256_content),
                     cm.node,
                     cm.name,
                     ar.uuid
                 FROM cloudphish_analysis_results AS ar
                 LEFT JOIN cloudphish_content_metadata AS cm ON ar.sha256_content = cm.sha256_content
                 WHERE sha256_url = UNHEX(%s)""", (sha256,))

    row = c.fetchone()
    if row:
        status, result, http_result, http_message, sha256_content, node, file_name, uuid = row
        if file_name:
            file_name = file_name.decode('unicode_internal')

        root_details = None
        try:
            root = RootAnalysis(storage_dir=storage_dir_from_uuid(uuid))
            root.load()
            root_details = root.details
        except Exception as e:
            logging.error("unable to load cloudphish analysis {}: {}".format(uuid, e))
            report_exception()

        return CloudphishAnalysisResult(RESULT_OK,      # result
                                        root_details,   # details 
                                        status=status,
                                        analysis_result=result,
                                        http_result=http_result,
                                        http_message=http_message,
                                        sha256_content=sha256_content,
                                        sha256_url=sha256,
                                        location=node,
                                        file_name=file_name,
                                        uuid=uuid)

    # if we have not then we return None
    return None
    
def create_analysis(url, reprocess, details):
    try:
        # url must be parsable
        urlparse(url)
        return _create_analysis(url, reprocess, details)
    except Exception as e:
        message = "unable to create analysis request for url {}: {}".format(url, e)
        logging.error(message)
        report_exception()

        return CloudphishAnalysisResult(RESULT_ERROR, message)

@use_db
def _create_analysis(url, reprocess, details, db, c):
    assert isinstance(url, str)
    assert isinstance(reprocess, bool)
    assert isinstance(details, dict)

    sha256_url = hash_url(url)

    if reprocess:
        # if we're reprocessing the url then we clear any existing analysis
        # IF the current analysis has completed
        # it's OK if we delete nothing here
        execute_with_retry("""DELETE FROM cloudphish_analysis_results 
                              WHERE sha256_url = UNHEX(%s) AND status = 'ANALYZED'""", 
                          (sha256_url,), commit=True)

    # if we're at this point it means that when we asked the database for an entry from cloudphish_analysis_results
    # it was empty, OR, we cleared existing analysis
    # however, we could have multiple requests coming in at the same time for the same url
    # so we need to take that into account here

    # first we'll generate our analysis uuid we're going to use
    _uuid = str(uuid.uuid4())

    # so first we try to insert it
    try:
        execute_with_retry(db, c, """INSERT INTO cloudphish_analysis_results ( sha256_url, uuid, insert_date ) 
                                     VALUES ( UNHEX(%s), %s, NOW() )""",
                           (sha256_url, _uuid), commit=True)
    except pymysql.err.IntegrityError as e:
        # (<class 'pymysql.err.IntegrityError'>--(1062, "Duplicate entry
        # if we get a duplicate key entry here then it means that an entry was created between when we asked
        # and now
        if e.args[0] != 1062:
            raise e

        # so just return that one that was already created
        return get_cached_analysis(url)

    # at this point we've inserted an entry into cloudphish_analysis_results for this url
    # now at it's processing to the workload

    root = RootAnalysis()
    root.uuid = _uuid
    root.storage_dir = storage_dir_from_uuid(root.uuid)
    root.initialize_storage()
    root.analysis_mode = ANALYSIS_MODE_CLOUDPHISH
    # this is kind of a kludge but,
    # the company_id initially starts out as whatever the default is for this node
    # later, should the analysis turn into an alert, the company_id changes to whatever
    # is stored as the "d" field in the KEY_DETAILS_CONTEXT
    root.company_id = saq.COMPANY_ID
    root.tool = 'ACE - Cloudphish'
    root.tool_instance = saq.SAQ_NODE
    root.alert_type = ANALYSIS_TYPE_CLOUDPHISH
    root.description = 'ACE Cloudphish Detection - {}'.format(url)
    root.event_time = datetime.datetime.now()
    root.details = {
        KEY_DETAILS_URL: url,
        KEY_DETAILS_SHA256_URL: sha256_url,
        # this used to be configurable but it's always true now
        KEY_DETAILS_ALERTABLE: True,
        KEY_DETAILS_CONTEXT: details, # <-- optionally contains the source company_id
    }

    url_observable = root.add_observable(F_URL, url)
    if url_observable:
        url_observable.add_directive(DIRECTIVE_CRAWL)

    root.save()
    root.schedule()

    return get_cached_analysis(url)

def analyze_url(url, reprocess, ignore_filters, details):
    """Analyze the given url with cloudphish. If reprocess is True then the existing (cached) results are deleted 
       and the url is processed again."""

    assert isinstance(url, str) and url
    assert isinstance(reprocess, bool)
    assert isinstance(ignore_filters, bool)
    assert isinstance(details, dict)

    result = None

    # if we've not requested reprocessing then we get the cached results if they exist
    if not reprocess:
        result = get_cached_analysis(url)

    if result is None:
        # we do not have analysis for this url yet
        # now we check to see if we will even analyze this url
        if not ignore_filters:
            filtered_result = url_filter.filter(url)
            if filtered_result.filtered:
                result = CloudphishAnalysisResult(RESULT_OK,
                                                  None,                     # details
                                                  STATUS_ANALYZED,          # status
                                                  SCAN_RESULT_PASS,         # analysis_result   
                                                  None,                     # http_result
                                                  filtered_result.reason,   # http_message
                                                  None,                     # sha256_content    
                                                  None,                     # location  
                                                  None)                     # file_name

    if result is None:
        logging.debug("creating analysis request for url {} reprocess {}".format(url, reprocess))
        result = create_analysis(url, reprocess, details)

    return result
