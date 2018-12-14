# vim: sw=4:ts=4:et:cc=120

import io
import json
import logging
import os.path
import shutil
import tempfile
import time

from subprocess import Popen, PIPE
from urllib.parse import urlparse

import ace_api
import saq
from saq.analysis import Analysis, RootAnalysis
from saq.cloudphish import *
from saq.constants import *
from saq.database import use_db, execute_with_retry
from saq.error import report_exception
from saq.modules import AnalysisModule

import requests

KEY_QUERY_RESULT = 'query_result'
KEY_QUERY_START = 'query_start'

class CloudphishAnalysis(Analysis):

    def initialize_details(self):
        self.details = {}

    @property
    def query_result(self):
        if self.details is None:
            return None

        if KEY_QUERY_RESULT not in self.details:
            return None

        return self.details[KEY_QUERY_RESULT]

    @query_result.setter
    def query_result(self, value):
        if self.details is None:
            self.details = {}

        self.details[KEY_QUERY_RESULT] = value
        self.set_modified()

    @property
    def query_start(self):
        if self.details is None:
            return None

        if KEY_QUERY_START not in self.details:
            return None

        return self.details[KEY_QUERY_START]

    @query_start.setter
    def query_start(self, value):
        assert isinstance(value, int)

        if self.details is None:
            self.details = {}

        self.details[KEY_QUERY_START] = value
        self.set_modified()

    @property
    def result(self):
        if self.query_result is None:
            return None

        if KEY_RESULT not in self.query_result:
            return None

        return self.query_result[KEY_RESULT]

    @result.setter
    def result(self, value):
        if self.query_result is None:
            self.query_result = {}

        self.query_result[KEY_RESULT] = value
        self.set_modified()

    @property
    def result_details(self):
        if self.query_result is None:
            return None

        if KEY_DETAILS not in self.query_result:
            return None

        return self.query_result[KEY_DETAILS]

    @result_details.setter
    def result_details(self, value):
        if self.query_result is None:
            self.query_result = {}

        self.query_result[KEY_DETAILS] = value
        self.set_modified()

    @property
    def status(self):
        if self.query_result is None:
            return None

        if KEY_STATUS not in self.query_result:
            return None

        return self.query_result[KEY_STATUS]

    @property
    def analysis_result(self):
        if self.query_result is None:
            return None

        if KEY_ANALYSIS_RESULT not in self.query_result:
            return None

        return self.query_result[KEY_ANALYSIS_RESULT]

    @property
    def http_result(self):
        if self.query_result is None:
            return None

        if KEY_HTTP_RESULT not in self.query_result:
            return None

        return self.query_result[KEY_HTTP_RESULT]

    @property
    def http_message(self):
        if self.query_result is None:
            return None

        if KEY_HTTP_MESSAGE not in self.query_result:
            return None

        return self.query_result[KEY_HTTP_MESSAGE]

    @property
    def sha256_content(self):
        if self.query_result is None:
            return None

        if KEY_SHA256_CONTENT not in self.query_result:
            return None

        return self.query_result[KEY_SHA256_CONTENT]

    @property
    def location(self):
        if self.query_result is None:
            return None

        if KEY_LOCATION not in self.query_result:
            return None

        return self.query_result[KEY_LOCATION]

    @property
    def file_name(self):
        if self.query_result is None:
            return None

        if KEY_FILE_NAME not in self.query_result:
            return None

        return self.query_result[KEY_FILE_NAME]

    @property
    def uuid(self):
        if self.query_result is None:
            return None

        if KEY_UUID not in self.query_result:
            return None

        return self.query_result[KEY_UUID]

    @property
    def context(self):
        if self.query_result is None:
            return None

        if KEY_DETAILS not in self.query_result:
            return None

        if self.query_result[KEY_DETAILS] is None:
            return None

        if KEY_DETAILS_CONTEXT not in self.query_result[KEY_DETAILS]:
            return None

        return self.query_result[KEY_DETAILS][KEY_DETAILS_CONTEXT]

    def generate_summary(self):
        if self.query_result is None:
            return None

        if self.result != RESULT_OK:
            return "Cloudphish Error: {} ({})".format(self.result, self.result_details)

        message = "Cloudphish Analysis: {}".format(self.analysis_result)
        if self.analysis_result == SCAN_RESULT_PASS:
            message += ': {}'.format(self.http_message)

        return message

class CloudphishAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.next_pool_index = 0

    @property
    def generated_analysis_type(self):
        return CloudphishAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def query_timeout(self):
        return self.config.getint('query_timeout')

    @property
    def use_proxy(self):
        return self.config.getboolean('use_proxy')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    def verify_environment(self):
        self.verify_config_exists('timeout')
        self.verify_config_exists('use_proxy')
        self.verify_config_exists('frequency')

    def get_cloudphish_server(self):
        """Returns the next cloudphish hostname[:port] to use.  This will round robin available selections."""
        pool = []
        for key in self.config.keys():
            if key.startswith('cloudphish.'):
                pool.append(self.config[key])

        if self.next_pool_index >= len(pool):
            self.next_pool_index = 0

        result = pool[self.next_pool_index]
        self.next_pool_index += 1
        return result

    def _get_next_url(self):
        """Returns the next cloudphish URL to use.  This will round robin available selections."""
        pool = []
        for key in self.config.keys():
            if key.startswith('cloudphish.'):
                pool.append(self.config[key])

        if self.next_pool_index >= len(pool):
            self.next_pool_index = 0

        result = pool[self.next_pool_index]
        self.next_pool_index += 1
        return result

    def execute_analysis(self, url):
        analysis = url.get_analysis(CloudphishAnalysis)
        if analysis is None:
            try:
                # do basic URL sanity checks
                parsed_url = urlparse(url.value)
            
                #if parsed_url.hostname and '.' not in parsed_url.hostname:
                    #logging.debug("ignoring invalid FQDN {} in url {}".format(parsed_url.hostname, url.value))
                    #return False

                # only analyze http, https and ftp schemes
                if parsed_url.scheme not in [ 'http', 'https', 'ftp' ]:
                    logging.debug("{} is not a supported scheme for cloudphish".format(parsed_url.scheme))
                    return False

                # URL seems ok
                analysis = self.create_analysis(url)
                
            except Exception as e:
                logging.debug("possible invalid URL: {}: {}".format(url.value, e))
                return False

        # start the clock XXX isn't this built-in to the delay analysis system?
        if analysis.query_start is None:
            analysis.query_start = int(time.time())
        #else:
            ## or has the clock expired?
            #if int(time.time()) - analysis.query_start > self.query_timeout:
                #logging.warning("cloudphish query for {} has timed out".format(url.value))
                #analysis.result = RESULT_ERROR
                #analysis.result_details = 'QUERY TIMED OUT'
                #return

        # do we have a local cache result for this url?
        sha256_url = hash_url(url.value)
        json_result = None

        # once we decide on a cloudphish server to use we need to keep using the same one 
        # for the same url
        if self.state is None:
            self.state = {}

        if 'cloudphish_server' in self.state:
            cloudphish_server = self.state['cloudphish_server']
        else:
            cloudphish_server = self.get_cloudphish_server()
            self.state['cloudphish_server'] = cloudphish_server

        logging.debug("making cloudphish query against {} for {}".format(cloudphish_server, url.value))

        try:
            context = {
                'c': self.root.uuid, # context
                't': {} # tracking information XXX fix this
            }

            response = ace_api.cloudphish_submit(url.value, 
                                                 context=context, 
                                                 remote_host=cloudphish_server,
                                                 ssl_verification=saq.CA_CHAIN_PATH,
                                                 proxies=saq.PROXIES if self.use_proxy else None,
                                                 timeout=self.timeout)

            logging.debug("got result {} for cloudphish query {}".format(response, url))

            #response = requests.request('POST', self.get_submit_url(), params = { 
                   #'url': url.value, 
                   #'c': self.root.uuid, # context
                   #'i': self.root.company_name if self.root.company_name else saq.CONFIG['global']['company_name'],
                   #'d': self.root.company_id if self.root.company_id else saq.CONFIG['global'].getint('company_id') }
                #data = { 
                    #'t': json.dumps(self.engine.get_tracking_information(self.root)), },
                #timeout=self.timeout,
                #proxies=saq.PROXIES if self.use_proxy else {},
                #verify=saq.CA_CHAIN_PATH,
                #stream=False)

        except Exception as e:
            logging.warning("cloudphish request failed: {}".format(e))
            analysis.result = RESULT_ERROR
            analysis.result_details = 'REQUEST FAILED ({})'.format(e)
            return True

        # check the results first
        # if the analysis isn't ready yet then we come back later
        if response[KEY_RESULT] == RESULT_OK:
            if response[KEY_STATUS] == STATUS_ANALYZING or response[KEY_STATUS] == STATUS_NEW:
                # deal with the possibility that cloudphish messed up
                # XXX where did this come from?
                #if response[KEY_ANALYSIS_RESULT] != SCAN_RESULT_ALERT:
                    # has the clock expired?
                    #if int(time.time()) - analysis.query_start > self.query_timeout:
                        #logging.warning("cloudphish query for {} has timed out".format(url.value))
                        #analysis.result = RESULT_ERROR
                        #analysis.result_details = 'QUERY TIMED OUT'
                        #return False

                # otherwise we delay analysis
                logging.info("waiting for cloudphish analysis of {} ({})".format(
                             url.value, response[KEY_STATUS]))

                if not self.delay_analysis(url, analysis, seconds=self.frequency, timeout_seconds=self.query_timeout):
                    # analysis timed out
                    analysis.result = RESULT_ERROR
                    analysis.result_details = 'QUERY TIMED OUT'
                    return True

        # sha256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 is the hash for the empty string
        # we ignore this case
        if response[KEY_SHA256_CONTENT] and response[KEY_SHA256_CONTENT].upper() == \
        'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855':
            logging.debug("ignoring result of 0 length data for {}".format(url.value))
            analysis.result = RESULT_ERROR
            analysis.result_details = 'EMPTY CONTENT'
            return False

        # save the analysis results
        analysis.query_result = response

        # did cloudphish generate an alert?
        if analysis.analysis_result == SCAN_RESULT_ALERT:
            # if cloudphish generated an alert then we'll need to wait for the alert correlation to finish
            # TODO

            temp_dir = None
            try:
                # create a temporary directory to load the alert into
                temp_dir = tempfile.mkdtemp(prefix='cloudphish_', dir=saq.TEMP_DIR)

                # grab the alert it created
                logging.info("downloading alert info for {}".format(url.value))
                ace_api.download(analysis.uuid, 
                                 temp_dir, 
                                 remote_host=cloudphish_server,
                                 ssl_verification=saq.CA_CHAIN_PATH,
                                 proxies=saq.PROXIES if self.use_proxy else None,
                                 timeout=self.timeout)

                #response = requests.request('GET', self.get_download_alert_url(), 
                                            #params={ 's': analysis.sha256_content },
                                            #timeout=self.timeout,
                                            #proxies=saq.PROXIES if self.use_proxy else {},
                                            #verify=saq.CA_CHAIN_PATH,
                                            #stream=True)

                # load the new alert
                cloudphish_alert = RootAnalysis()
                cloudphish_alert.storage_dir = temp_dir
                try:
                    cloudphish_alert.load()
                except Exception as e:
                    logging.warning("unable to load cloudphish alert for {}: {}".format(url.value, e))
                    # XXX there is a reason for this but I forget what it was lol

                # merge this alert into the analysis for this url
                self.root.merge(analysis, cloudphish_alert)

            finally:
                # make sure we clean up these temp directories
                try:
                    if temp_dir:
                        shutil.rmtree(temp_dir)
                except Exception as e:
                    logging.error("unable to delete directory {}: {}".format(temp_dir, e))
                    report_exception()

        # are we forcing the download of the URL?
        elif url.has_directive(DIRECTIVE_FORCE_DOWNLOAD) and analysis.file_name:
            # TODO fix this file naming scheme
            target_file = os.path.join(self.root.storage_dir, analysis.file_name)
            if os.path.exists(target_file):
                logging.warning("target file {} exists".format(target_file))
                return True

            try:
                logging.info("downloading file {} from {}".format(target_file, url.value))
                ace_api.cloudphish_download(url=url.value,
                                            output_path=target_file,
                                            remote_host=cloudphish_server,
                                            ssl_verification=saq.CA_CHAIN_PATH,
                                            proxies=saq.PROXIES if self.use_proxy else None,
                                            timeout=self.timeout)

                #response = requests.request('GET', self.get_download_url(), 
                                            #params={ 's': analysis.sha256_content },
                                            #timeout=self.timeout,
                                            #proxies=saq.PROXIES if self.use_proxy else {},
                                            #verify=saq.CA_CHAIN_PATH,
                                            #stream=True)

                #with open(target_file, 'wb') as fp:
                    #for chunk in response.iter_content(chunk_size=io.DEFAULT_BUFFER_SIZE):
                        #if chunk:
                            #fp.write(chunk)

                analysis.add_observable(F_FILE, os.path.relpath(target_file, start=self.root.storage_dir))

            except Exception as e:
                logging.error("unable to download file {} for url {} from cloudphish: {}".format(
                              target_file, url.value, e))
                report_exception()

        return True

# 
# this replaces the old cloudphish engine
#

class CloudphishRequestAnalyzer(AnalysisModule):
    def _sanity_check(self):
        """Returns True if we've got what we need in the details of the analysis, False otherwise."""
        if self.root.alert_type != ANALYSIS_TYPE_CLOUDPHISH:
            return False

        # update the status of this cloudphish request in the database to
        # indicate we've started analyzing it

        # lots of sanity checking first
        if not self.root.details or not isinstance(self.root.details, dict):
            logging.error("missing or invalid details in {} (details = {})".format(self.root, self.root.details))
            return False

        if KEY_DETAILS_SHA256_URL not in self.root.details:
            logging.error("missing key {} in details of {}".format(KEY_DETAILS_SHA256_URL, self.root))
            return False

        if not self.root.details[KEY_DETAILS_SHA256_URL]:
            logging.error("missing value for {} in details of {}".format(KEY_DETAILS_SHA256_URL, self.root))
            return False

        return True
        
    def execute_pre_analysis(self):

        if not self._sanity_check():
            return

        row_count = update_cloudphish_result(self.root.details[KEY_DETAILS_SHA256_URL], status=STATUS_ANALYZING)
        if row_count != 1:
            logging.warning("got rowcount {} for update to sha256_url {}".format(row_count, 
                            self.root.details[KEY_DETAILS_SHA256_URL]))

    def execute_post_analysis(self):

        # make sure we've got what we need first
        if not self._sanity_check():
            return 

        url = None
        for o in self.root.observables:
            if o.type == F_URL and o.has_directive(DIRECTIVE_CRAWL):
                url = o
                break

        if not url:
            logging.error("cannot find original url for {}".format(self.root))
            return

        # get the crawlphish analysis for this url
        from saq.modules.url import CrawlphishAnalysisV2

        sha256_url = self.root.details[KEY_DETAILS_SHA256_URL]
        crawlphish_analysis = url.get_analysis(CrawlphishAnalysisV2)

        if crawlphish_analysis is None:
            # something went wrong with the analysis of the url
            update_cloudphish_result(sha256_url, status=STATUS_ANALYZED, result=SCAN_RESULT_ERROR)
            return

        # update the database with the results
        if crawlphish_analysis.filtered_status:
            scan_result = SCAN_RESULT_PASS
        elif not crawlphish_analysis.downloaded:
            scan_result = SCAN_RESULT_ERROR
        # did we find something to alert on?
        elif self.root.has_detections():
            scan_result = SCAN_RESULT_ALERT
        else:
            scan_result = SCAN_RESULT_CLEAR

        http_result_code = crawlphish_analysis.status_code
        http_message = crawlphish_analysis.status_code_reason

        if scan_result == SCAN_RESULT_ERROR:
            http_message = crawlphish_analysis.error_reason

        sha256_content = None
        file_name = None

        # if we downloaded a file then we want to save it to our cache
        while crawlphish_analysis.file_name:
            # find the file observable added to this analysis
            file_observable = crawlphish_analysis.find_observable(lambda o: o.type == F_FILE)

            if not file_observable:
                logging.info("nothing downloaded from {}".format(url_observable.value))
            else:
                logging.debug("found downloaded file {} for {}".format(file_observable, url))
                file_observable.compute_hashes()
                if not file_observable.sha256_hash:
                    logging.error("missing sha256 hash for {}".format(file_observable))
                    break

                cache_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['cloudphish']['cache_dir'], 
                                         file_observable.sha256_hash.lower()[0:2])

                if not os.path.isdir(cache_dir):
                    try:
                        os.makedirs(cache_dir)
                    except Exception as e:
                        logging.error("unable to create directory {}: {}".format(cache_dir, e))
                        report_exception()
                        break

                cache_path = os.path.join(cache_dir, file_observable.sha256_hash.lower())

                if not os.path.exists(cache_path):
                    src = os.path.join(self.root.storage_dir, file_observable.value)
                    logging.debug("copying {} to {}".format(src, cache_path))

                    try:
                        shutil.copy(src, cache_path)
                    except Exception as e:
                        logging.error("unable to copy {} to {}: {}".format(src, cache_path, e))

                sha256_content = file_observable.sha256_hash
                file_name = os.path.basename(file_observable.value).encode('unicode_internal')

            break

        update_cloudphish_result(sha256_url, 
                                 http_result_code=http_result_code,
                                 http_message=http_message,
                                 result=scan_result,
                                 sha256_content=sha256_content,
                                 status=STATUS_ANALYZED)

        if sha256_content:
            update_content_metadata(sha256_content, saq.SAQ_NODE, file_name)
