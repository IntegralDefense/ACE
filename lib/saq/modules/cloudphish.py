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

import saq
from saq.analysis import Analysis, RootAnalysis
from saq.cloudphish import *
from saq.constants import *
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

    @property
    def generate_alert(self):
        return self.config.getboolean('generate_alert')

    @property
    def local_cache_dir(self):
        return os.path.join(saq.SAQ_HOME, self.config['local_cache_dir'])

    def verify_environment(self):
        self.verify_config_exists('timeout')
        self.verify_config_exists('use_proxy')
        self.verify_config_exists('frequency')
        self.verify_config_exists('local_cache_dir')
        
        if not os.path.isdir(self.local_cache_dir):
            try:
                os.makedirs(self.local_cache_dir)
            except Exception as e:
                logging.error("unable to create local cache directory {}: {}".format(self.local_cache_dir, e))
                report_exception()

        self.verify_path_exists(self.local_cache_dir)

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

    def get_submit_url(self):
        return '{}/submit'.format(self._get_next_url())

    def get_download_url(self):
        return '{}/download'.format(self._get_next_url())

    def get_download_alert_url(self):
        return '{}/download_alert'.format(self._get_next_url())

    def execute_analysis(self, url):

        analysis = url.get_analysis(CloudphishAnalysis)
        if analysis is None:
            analysis = self.create_analysis(url)

        try:
            parsed_url = urlparse(url.value)
            if parsed_url.hostname and '.' not in parsed_url.hostname:
                logging.debug("ignoring invalid FQDN {} in url {}".format(parsed_url.hostname, url.value))
                return False

            # only analyze http, https and ftp schemes
            if parsed_url.scheme not in [ 'http', 'https', 'ftp' ]:
                logging.debug("{} is not a supported scheme for cloudphish".format(parsed_url.scheme))
                return False
            
        except:
            pass

        # start the clock
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
        cache_dir = os.path.join(self.local_cache_dir, sha256_url[0:2])
        cache_path = os.path.join(cache_dir, sha256_url)
        alert_cache_path = '{}.ace.tar.gz'.format(cache_path)
        used_cache = False
        json_result = None

        # XXX need to fix this correctly
        #if os.path.exists(cache_path):
        if False:
            logging.debug("using local cache results for {}".format(url.value))
            try:
                with open(cache_path, 'r') as fp:
                    json_result = json.load(fp)

                used_cache = True

            except Exception as e:
                logging.warning("unable to load local cache result for {} from {}: {}".format(url.value, cache_path, e))
                #report_exception()
        else:
            logging.debug("making cloudphish query for {}".format(url.value))

            try:
                response = requests.request('POST', self.get_submit_url(), params = { 
                       'url': url.value, 
                       'c': self.root.uuid, # context
                       'i': self.root.company_name if self.root.company_name else saq.CONFIG['global']['company_name'],
                       'd': self.root.company_id if self.root.company_id else saq.CONFIG['global'].getint('company_id'),
                       'a': '1' if self.generate_alert else '0',
                       's': self.engine.name, },
                    data = { 
                        't': json.dumps(self.engine.get_tracking_information(self.root)), },
                    timeout=self.timeout,
                    proxies=saq.PROXIES if self.use_proxy else {},
                    verify=saq.CA_CHAIN_PATH,
                    stream=False)

            except Exception as e:
                logging.warning("cloudphish request failed: {}".format(e))
                analysis.result = RESULT_ERROR
                analysis.result_details = 'REQUEST FAILED ({})'.format(e)
                return False

            if response.status_code != 200:
                logging.error("cloudphish returned status {} for {} - {}".format(response.status_code, 
                                                                                 url.value,
                                                                                 response.reason))
                analysis.result = RESULT_ERROR
                analysis.result_details = 'REQUEST FAILED ({}:{})'.format(response.status_code, response.reason)
                return False

            # check the results first
            # if the analysis isn't ready yet then we come back later
            json_result = response.json()
            if json_result[KEY_RESULT] == RESULT_OK:
                if json_result[KEY_STATUS] == STATUS_ANALYZING or json_result[KEY_STATUS] == STATUS_NEW:
                    # deal with the possibility that cloudphish messed up
                    if json_result[KEY_ANALYSIS_RESULT] != SCAN_RESULT_ALERT:
                        # has the clock expired?
                        if int(time.time()) - analysis.query_start > self.query_timeout:
                            logging.warning("cloudphish query for {} has timed out".format(url.value))
                            analysis.result = RESULT_ERROR
                            analysis.result_details = 'QUERY TIMED OUT'
                            return False

                        # otherwise we delay analysis
                        logging.info("waiting for cloudphish analysis of {} ({})".format(
                                     url.value, json_result[KEY_STATUS]))
                        return self.delay_analysis(url, analysis, seconds=self.frequency)

            # cache the analysis results if we didn't load it from cache
            while True:
                if not os.path.isdir(cache_dir):
                    try:
                        os.mkdir(cache_dir)
                    except Exception as e:
                        logging.error("unable to create directory {}: {}".format(cache_dir, e))
                        report_exception()
                        break

                cache_path = os.path.join(cache_dir, sha256_url)
                if os.path.exists(cache_path):
                    logging.debug("cloudphish cache entry {} already exists".format(cache_path))
                    #break
                
                try:
                    logging.debug("saving cloudphish cache entry {} for {}".format(cache_path, url.value))
                    with open(cache_path, 'wb') as fp:
                        fp.write(response.content)
                except Exception as e:
                    logging.error("unable to save cloudphish cache entry for {} at {}: {}".format(
                                  url.value, cache_path, e))
                    report_exception()
                    cache_path = None
                    break

                break

        # save the analysis results
        analysis.query_result = json_result

        # sha256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 is the hash for the empty string
        # we ignore this case
        if analysis.sha256_content and analysis.sha256_content.upper() == 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855':
            logging.debug("ignoring result of 0 length data for {}".format(url.value))
            return False

        # what did cloudphish see?
        if analysis.analysis_result == SCAN_RESULT_ALERT:
            temp_dir = None
            try:
                # create a temporary directory to load the alert into
                temp_dir = tempfile.mkdtemp(prefix='cloudphish_', 
                                            dir=os.path.join(saq.SAQ_HOME, saq.CONFIG['global']['tmp_dir']))

                # is the alert cached?
                if os.path.exists(alert_cache_path):
                    logging.debug("using alert cache {} for url {}".format(alert_cache_path, url.value))
                    p = Popen(['tar', 'zxf', alert_cache_path, '-C', temp_dir], stdout=PIPE, stderr=PIPE)
                else:
                    # grab the alert it created
                    logging.info("downloading alert info for {}".format(url.value))
                    response = requests.request('GET', self.get_download_alert_url(), 
                                                params={ 's': analysis.sha256_content },
                                                timeout=self.timeout,
                                                proxies=saq.PROXIES if self.use_proxy else {},
                                                verify=saq.CA_CHAIN_PATH,
                                                stream=True)


                    p = Popen(['tar', 'zxf', '-', '-C', temp_dir], stdin=PIPE, stdout=PIPE, stderr=PIPE)

                    alert_cache_fp = None
                    try:
                        alert_cache_fp = open(alert_cache_path, 'wb')
                    except Exception as e:
                        logging.error("unable to cache alert data for {} at {}: {}".format(
                                      url.value, alert_cache_path, e))
                        report_exception()
                    
                    for chunk in response.iter_content(chunk_size=None):
                        if alert_cache_fp:
                            try:
                                alert_cache_fp.write(chunk)
                            except Exception as e:
                                logging.error("error writing data to cache alert data for {} at {}: {}".format(
                                              url.value, alert_cache_path, e))
                                report_exception()

                                try:
                                    alert_cache_fp.close()
                                except:
                                    pass
                                finally:
                                    alert_cache_fp = None

                        p.stdin.write(chunk)

                    if alert_cache_fp:
                        try:
                            alert_cache_fp.close()
                        except:
                            pass

                stdout, stderr = p.communicate()

                if stderr:
                    logging.warning("tar produced output on stderr for {}: {}".format(url.value, stderr))

                # load the new alert
                cloudphish_alert = RootAnalysis()
                cloudphish_alert.storage_dir = temp_dir
                try:
                    cloudphish_alert.load()
                except Exception as e:
                    logging.warning("unable to load cloudphish alert for {}: {}".format(url.value, e))
                    # XXX there is a reason for this but I forget what it was

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
            target_file = os.path.join(self.root.storage_dir, analysis.file_name)
            if os.path.exists(target_file):
                logging.warning("target file {} exists".format(target_file))
                return

            try:
                logging.info("downloading file {} from {}".format(target_file, url.value))
                response = requests.request('GET', self.get_download_url(), 
                                            params={ 's': analysis.sha256_content },
                                            timeout=self.timeout,
                                            proxies=saq.PROXIES if self.use_proxy else {},
                                            verify=saq.CA_CHAIN_PATH,
                                            stream=True)

                with open(target_file, 'wb') as fp:
                    for chunk in response.iter_content(chunk_size=io.DEFAULT_BUFFER_SIZE):
                        if chunk:
                            fp.write(chunk)

                analysis.add_observable(F_FILE, os.path.relpath(target_file, start=self.root.storage_dir))

            except Exception as e:
                logging.error("unable to download file {} for url {} from cloudphish: {}".format(
                              target_file, url.value, e))
                report_exception()

        return True
