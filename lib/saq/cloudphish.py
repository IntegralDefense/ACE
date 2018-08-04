# vim: sw=4:ts=4:et:cc=120
# constants used by cloudphish

import logging
import hashlib
import pickle

from urllib.parse import urlparse

from saq.crawlphish import CrawlphishURLFilter
from saq.database import get_db_connection, execute_with_retry
from saq.error import report_exception

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
    'KEY_LOCATION',
    'KEY_FILE_NAME',
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
KEY_LOCATION = 'location'
KEY_FILE_NAME = 'file_name'

STATUS_NEW = 'NEW'
STATUS_ANALYZING = 'ANALYZING'
STATUS_ANALYZED = 'ANALYZED'

SCAN_RESULT_UNKNOWN = 'UNKNOWN'
SCAN_RESULT_ERROR = 'ERROR'
SCAN_RESULT_CLEAR = 'CLEAR'
SCAN_RESULT_ALERT = 'ALERT'
SCAN_RESULT_PASS = 'PASS'

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
                 sha256_content=None, location=None, file_name=None):

        self.result = result
        self.details = details
        self.status = status
        self.analysis_result = analysis_result
        self.http_result = http_result
        self.http_message = http_message
        self.sha256_content = sha256_content
        self.location = location
        self.file_name = file_name

    def json(self):
        return { KEY_RESULT: self.result,
                 KEY_DETAILS: self.details,
                 KEY_STATUS: self.status,
                 KEY_ANALYSIS_RESULT: self.analysis_result,
                 KEY_HTTP_RESULT: self.http_result,
                 KEY_HTTP_MESSAGE: self.http_message,
                 KEY_SHA256_CONTENT: self.sha256_content,
                 KEY_LOCATION: self.location,
                 KEY_FILE_NAME: self.file_name }

    def __str__(self):
        return "CloudphishAnalysisResult(result:{},details:{},status:{},analysis_result:{},http_result:{},http_message:{},sha256_content:{},location:{},file_name:{})".format(
            self.result, self.details, self.status, self.analysis_result, self.http_result, self.http_message,
            self.sha256_content, self.location, self.file_name)
    
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

def _get_cached_analysis(url):
    sha256 = hash_url(url)
    # have we already processed this url?
    with get_db_connection('cloudphish') as db:
        c = db.cursor()
        c.execute("""SELECT
                         ar.status,
                         ar.result,
                         ar.http_result_code,
                         ar.http_message,
                         HEX(ar.sha256_content),
                         cm.location,
                         cm.name
                     FROM analysis_results AS ar
                     LEFT JOIN content_metadata AS cm ON ar.sha256_content = cm.sha256_content
                     WHERE sha256_url = UNHEX(%s)""", (sha256,))
        row = c.fetchone()
        if row:
            file_name = row[6]
            if file_name:
                file_name = file_name.decode()

            return CloudphishAnalysisResult(RESULT_OK,      # result
                                            None,           # details 
                                            row[0],         # status
                                            row[1],         # analysis_results
                                            row[2],         # http_result
                                            row[3],         # http_message
                                            row[4],         # sha256_content
                                            row[5],         # location
                                            file_name)


    return None
    
def create_analysis(url, reprocess, alertable, **kwargs):
    try:
        # url must be parsable
        urlparse(url)
        return _create_analysis(url, reprocess, alertable, **kwargs)
    except Exception as e:
        message = "unable to create analysis request for url {}: {}".format(url, e)
        logging.error(message)
        report_exception()

        return CloudphishAnalysisResult(RESULT_ERROR, message)

def _create_analysis(url, reprocess, alertable, **kwargs):
    assert isinstance(url, str)
    assert isinstance(reprocess, bool)
    assert isinstance(alertable, bool)
    assert isinstance(kwargs, dict)

    sha256_url = hash_url(url)
    new_entry = False

    try:
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            execute_with_retry(c, """INSERT INTO analysis_results ( sha256_url ) VALUES ( UNHEX(%s) )""", 
                              (sha256_url,))
            db.commit()
            new_entry = True
    except pymysql.err.IntegrityError as e:
        # timing issue -- created as we were getting ready to create
        # (<class 'pymysql.err.IntegrityError'>--(1062, "Duplicate entry
        if e.args[0] != 1062:
            raise e

        logging.debug("entry for {} already created".format(url))

    with get_db_connection('cloudphish') as db:
        c = db.cursor()
        # if we didn't just create this then we update the status of the existing entry
        # we don't need to do this if we just created it because 
        if reprocess or not new_entry:
            execute_with_retry(c, 
                """UPDATE analysis_results SET status = %s WHERE sha256_url = UNHEX(%s)""",
                (STATUS_NEW, sha256_url))

        try:
            execute_with_retry(c, 
                """INSERT INTO workload ( sha256_url, url, alertable, details ) VALUES ( UNHEX(%s), %s, %s, %s )""",
                (sha256_url, url, alertable, pickle.dumps(kwargs)))
        except pymysql.err.IntegrityError as e:
            # timing issue -- created as we were getting ready to create
            # (<class 'pymysql.err.IntegrityError'>--(1062, "Duplicate entry
            if e.args[0] != 1062:
                raise e

            logging.debug("analysis request for {} already exists".format(url))

        db.commit()

    return get_cached_analysis(url)

def analyze_url(url, reprocess, alertable, **kwargs):
    """Analyze the given url with cloudphish."""

    # what is the status of this url?
    result = None
    if not reprocess:
        result = get_cached_analysis(url)

    if result is None:
        # we do not have analysis for this url yet
        # now we check to see if we will even analyze this url
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

        else:
            logging.debug("creating analysis request for url {} reprocess {} alertable {}".format(
                          url, reprocess, alertable))
            result = create_analysis(url, reprocess, alertable, **kwargs)

    return result
