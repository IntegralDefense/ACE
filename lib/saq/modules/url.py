# vim: sw=4:ts=4:et
import datetime
import io
import logging
import math
import os
import os.path
import re
import tempfile
import zipfile

from subprocess import Popen, PIPE
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from werkzeug.utils import secure_filename

import saq

from saq.analysis import Analysis
from saq.constants import *
from saq.brocess import add_httplog
from saq.crawlphish import CrawlphishURLFilter
from saq.database import get_db_connection
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.util import is_ipv4

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

KEY_STATUS_CODE = 'status_code'
KEY_REASON = 'reason' # "status_code_reason"
KEY_FILE_NAME = 'file_name'
KEY_CRAWLABLE = 'crawlable' # "filtered_status"
KEY_FILTERED_STATUS_REASON = 'filtered_status_reason'
KEY_NETWORK_ERROR = 'network_error' # "error_reason"
KEY_HEADERS = 'headers'
KEY_HISTORY = 'history'
KEY_REQUESTED_URL = 'requested_url'
KEY_FINAL_URL = 'final_url'
KEY_DOWNLOADED = 'downloaded'
KEY_PROXY = 'proxy'
KEY_PROXY_NAME = 'proxy_name'

class CrawlphishAnalysis(Analysis):

    def initialize_details(self):
        # TODO actually initialize it lol
        self.details = { }
        
    @property
    def status_code(self):
        """The HTTP status code received from the host."""
        if self.details is None:
            return None

        if KEY_STATUS_CODE not in self.details:
            return None

        return self.details[KEY_STATUS_CODE]

    @status_code.setter
    def status_code(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_STATUS_CODE] = value

    @property
    def status_code_reason(self):
        """The reason given by the web server for the status code."""
        if self.details is None:
            return None

        if KEY_REASON not in self.details:
            return None

        return self.details[KEY_REASON]

    @status_code_reason.setter
    def status_code_reason(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_REASON] = value

    @property
    def file_name(self):
        if self.details is None:
            return None

        if KEY_FILE_NAME not in self.details:
            return None

        return self.details[KEY_FILE_NAME]

    @file_name.setter
    def file_name(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_FILE_NAME] = value

    @property
    def filtered_status(self):
        """Was this URL filtered?  Did we NOT attempt to crawl it?"""
        if self.details is None:
            return None

        if KEY_CRAWLABLE not in self.details:
            return None

        return self.details[KEY_CRAWLABLE]

    @filtered_status.setter
    def filtered_status(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_CRAWLABLE] = value

    @property
    def filtered_status_reason(self):
        """What is the reason for the filtered status?"""
        if self.details is None:
            return None

        if KEY_FILTERED_STATUS_REASON not in self.details:
            return None

        return self.details[KEY_FILTERED_STATUS_REASON]

    @filtered_status_reason.setter
    def filtered_status_reason(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_FILTERED_STATUS_REASON] = value

    @property
    def error_reason(self):
        """Returns the details of any error in processing of the URL."""
        if self.details is None:
            return None

        if KEY_NETWORK_ERROR not in self.details:
            return None

        return self.details[KEY_NETWORK_ERROR]

    @error_reason.setter
    def error_reason(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_NETWORK_ERROR] = value

    @property
    def headers(self):
        if self.details is None:
            return None

        if KEY_HEADERS not in self.details:
            return None

        return self.details[KEY_HEADERS]

    @headers.setter
    def headers(self, value):
        assert value is None or isinstance(value, dict)

        if self.details is None:
            self.initialize_details()

        self.details[KEY_HEADERS] = value

    @property
    def history(self):
        if self.details is None:
            return None

        if KEY_HISTORY not in self.details:
            return None

        return self.details[KEY_HISTORY]

    @history.setter
    def history(self, value):
        assert value is None or isinstance(value, list)

        if self.details is None:
            self.initialize_details()

        self.details[KEY_HISTORY] = value

    @property
    def requested_url(self):
        if self.details is None:
            return None

        if KEY_REQUESTED_URL not in self.details:
            return None

        return self.details[KEY_REQUESTED_URL]

    @requested_url.setter
    def requested_url(self, value):
        assert isinstance(value, str)

        if self.details is None:
            self.initialize_details()

        self.details[KEY_REQUESTED_URL] = value

    @property
    def final_url(self):
        if self.details is None:
            return None

        if KEY_FINAL_URL not in self.details:
            return None

        return self.details[KEY_FINAL_URL]

    @final_url.setter
    def final_url(self, value):
        assert isinstance(value, str)

        if self.details is None:
            self.initialize_details()

        self.details[KEY_FINAL_URL] = value

    @property
    def downloaded(self):
        """Was the download of the URL successful?"""
        if self.details is None:
            return None

        if KEY_DOWNLOADED not in self.details:
            return self.file_name is not None

        return self.details[KEY_DOWNLOADED]

    @downloaded.setter
    def downloaded(self, value):
        if self.details is None:
            self.initialize_details()

        self.details[KEY_DOWNLOADED] = value

    def generate_summary(self):
        if self.details is None:
            return None

        if self.filtered_status:
            return "Crawlphish PASS: {}".format(self.filtered_status_reason)

        if not self.downloaded:
            return "Crawlphish: Error: {}".format(self.error_reason)

        result = "Crawlphish Download ({} - {}) - {}".format(
                self.status_code,
                self.status_code_reason,
                self.file_name)

        return result

class CloudphishProxyResult(object):
    """Represents the result of the request for a URL against a given proxy."""

    def __init__(self, json=None):
        if json:
            self.details = json
        else:
            self.details = {
                KEY_PROXY_NAME: None,
                KEY_STATUS_CODE: None,
                KEY_REASON: None,
                KEY_NETWORK_ERROR: None,
                KEY_HEADERS: {},
                KEY_HISTORY: [],
            }

    @property
    def json(self):
        return self.details

    @property
    def proxy_name(self):
        """The name of the proxy that was used."""
        return self.details[KEY_PROXY_NAME]

    @proxy_name.setter
    def proxy_name(self, value):
        assert isinstance(value, str)
        self.details[KEY_PROXY_NAME] = value

    @property
    def status_code(self):
        """The HTTP status code received from the host."""
        return self.details[KEY_STATUS_CODE]

    @status_code.setter
    def status_code(self, value):
        self.details[KEY_STATUS_CODE] = value

    @property
    def status_code_reason(self):
        """The reason given by the web server for the status code."""
        return self.details[KEY_REASON]

    @status_code_reason.setter
    def status_code_reason(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_REASON] = value

    @property
    def error_reason(self):
        """Returns the details of any error in processing of the URL."""
        return self.details[KEY_NETWORK_ERROR]

    @error_reason.setter
    def error_reason(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_NETWORK_ERROR] = value

    @property
    def headers(self):
        return self.details[KEY_HEADERS]

    @headers.setter
    def headers(self, value):
        assert value is None or isinstance(value, dict)
        self.details[KEY_HEADERS] = value

    @property
    def history(self):
        return self.details[KEY_HISTORY]

    @history.setter
    def history(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_HISTORY] = value

KEY_PROXIES = 'proxies'
KEY_PROXY_RESULTS = 'proxy_results'

class CrawlphishAnalysisV2(Analysis):

    def initialize_details(self):
        self.details = { 
            KEY_CRAWLABLE: None,
            KEY_FILTERED_STATUS_REASON: None,
            KEY_FILE_NAME: None,
            KEY_FINAL_URL: None,
            KEY_REQUESTED_URL: None,
            KEY_DOWNLOADED: None,
            KEY_PROXIES: [],
            KEY_PROXY_RESULTS: {},
        }

    @property
    def filtered_status(self):
        """Was this URL filtered?  Did we NOT attempt to crawl it?"""
        return self.details_property(KEY_CRAWLABLE)

    @filtered_status.setter
    def filtered_status(self, value):
        self.details[KEY_CRAWLABLE] = value

    @property
    def filtered_status_reason(self):
        """What is the reason for the filtered status?"""
        return self.details_property(KEY_FILTERED_STATUS_REASON)

    @filtered_status_reason.setter
    def filtered_status_reason(self, value):
        self.details[KEY_FILTERED_STATUS_REASON] = value

    @property
    def file_name(self):
        return self.details_property(KEY_FILE_NAME)

    @file_name.setter
    def file_name(self, value):
        self.details[KEY_FILE_NAME] = value

    @property
    def final_url(self):
        return self.details_property(KEY_FINAL_URL)

    @final_url.setter
    def final_url(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_FINAL_URL] = value

    @property
    def requested_url(self):
        return self.details_property(KEY_REQUESTED_URL)

    @requested_url.setter
    def requested_url(self, value):
        assert isinstance(value, str)
        self.details[KEY_REQUESTED_URL] = value

    @property
    def downloaded(self):
        """Was the download of the URL successful?"""
        return self.details_property(KEY_DOWNLOADED)

    @downloaded.setter
    def downloaded(self, value):
        self.details[KEY_DOWNLOADED] = value

    @property
    def proxies(self):
        """Returns a list of the names of the proxies used to try to download the url.
           These are the keys to the proxy_results property."""

        # NOTE we do NOT return the keys() property of the proxy_results
        # these are in the order that the proxy was attempted to be used
        return self.details_property(KEY_PROXIES)

    @proxies.setter
    def proxies(self, value):
        assert isinstance(value, list)
        self.details[KEY_PROXIES] = value

    @property
    def proxy_results(self):
        result = self.details_property(KEY_PROXY_RESULTS)
        for proxy_name, proxy_result in result.items():
            if isinstance(result[proxy_name], dict):
                result[proxy_name] = CloudphishProxyResult(json=result[proxy_name])

        return result

    @proxy_results.setter
    def proxy_results(self, value):
        assert isinstance(value, dict)
        self.details[KEY_PROXY_RESULTS] = value

    #
    # read only properties that return the values from the last proxy result in the list

    @property
    def proxy_name(self):
        """The name of the last proxy that was attempted."""
        if self.proxies:
            return self.proxies[-1]
        else:
            return None

    @property
    def status_code(self):
        """The status code obtained from the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].status_code
        else:
            return None

    @property
    def status_code_reason(self):
        """The status code reason obtained from the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].status_code_reason
        else:
            return None

    @property
    def error_reason(self):
        """The error reason set on the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].error_reason
        else:
            return None

    @property
    def headers(self):
        """The headers returned by the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].headers
        else:
            return None

    @property
    def history(self):
        """The history (chain) of requests at the last proxy used."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].history
        else:
            return None

    def generate_summary(self):
        if self.details is None:
            return None

        if self.filtered_status:
            return "Crawlphish PASS: {}".format(self.filtered_status_reason)

        # were we not able to download it?
        if not self.downloaded:
            # list the error for each proxy
            result = "Crawlphish: Error: "
        else:
            # we were able to download something
            result = "Crawlphish Download ({}): ".format(self.file_name)

        for proxy in self.proxies:
            proxy_result = self.proxy_results[proxy]
            result += "({}: {}) ".format(proxy, 
                                         proxy_result.error_reason if proxy_result.error_reason else '{} - {}'.format(
                                         proxy_result.status_code, proxy_result.status_code_reason))

        return result

class CrawlphishAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.headers = {
            'User-Agent': self.config['user-agent']
        }

        self._initialized = False

    def verify_environment(self):
        self.verify_config_exists('whitelist_path')
        self.verify_path_exists(self.config['whitelist_path'])
        self.verify_config_exists('regex_path')
        self.verify_path_exists(self.config['regex_path'])
        self.verify_config_exists('blacklist_path')
        self.verify_path_exists(self.config['blacklist_path'])
        self.verify_config_exists('uncommon_network_threshold')
        self.verify_config_exists('user-agent')
        self.verify_config_exists('timeout')
        self.verify_config_exists('max_download_size')
        self.verify_config_exists('max_file_name_length')
        self.verify_config_exists('cooldown_period')
        self.verify_config_exists('update_brocess')
        self.verify_config_exists('proxies')
        
        for name in self.config['proxies'].split(','):
            if name == 'GLOBAL':
                continue

            if 'proxy_{}'.format(name) not in saq.CONFIG:
                logging.critical("invalid proxy name {} in crawlphish config".format(name))

    @property
    def whitelist_path(self):
        return self.url_filter.whitelist_path

    @property
    def regex_path(self):
        return self.url_filter.regex_path

    @property
    def blacklist_path(self):
        return self.url_filter.blacklist_path

    @property
    def uncommon_network_threshold(self):
        """How many connections decides that a given fqdn or ip address is an "uncommon network"? """
        return self.config.getint('uncommon_network_threshold')

    @property
    def user_agent(self):
        return self.config['user-agent']

    @property
    def timeout(self):
        """How long to wait for an HTTP request to time out (in seconds)."""
        return self.config.getint('timeout')

    @property
    def max_download_size(self):
        """Maximum download size (in MB)."""
        return self.config.getint('max_download_size') * 1024 * 1024

    @property
    def max_file_name_length(self):
        """Maximum file name length (in bytes) to use for download file path."""
        return self.config.getint('max_file_name_length')

    @property
    def update_brocess(self):
        """Are we updating brocess when we make a request?"""
        return self.config.getboolean('update_brocess')

    @property
    def proxies(self):
        """The list of proxies we'll use to download URLs, attepted in order."""
        return self.config['proxies']

    @property
    def generated_analysis_type(self):
        return CrawlphishAnalysisV2

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def required_directives(self):
        return [ DIRECTIVE_CRAWL ]

    def execute_analysis(self, url):

        if not self._initialized:
            # used to decide what URLs to actually crawl
            self.url_filter = CrawlphishURLFilter()

            # a whitelist of sites we'll always crawl
            self.watch_file(self.url_filter.whitelist_path, self.url_filter.load_whitelist)
            self.watch_file(self.url_filter.blacklist_path, self.url_filter.load_blacklist)
            self.watch_file(self.url_filter.regex_path, self.url_filter.load_path_regexes)

            self._initialized = True

        analysis = self.create_analysis(url)
        # are we able to download it?
        analysis.downloaded = False
        # if not, why?
        #analysis.error_reason = None

        # is this URL crawlable?
        filter_result = self.url_filter.filter(url.value)
        analysis.filtered_status = filter_result.filtered
        analysis.filtered_status_reason = filter_result.reason

        if analysis.filtered_status:
            logging.debug("{} is not crawlable: {}".format(url.value, analysis.filtered_status_reason))
            return False

        parsed_url = filter_result.parsed_url
        if parsed_url is None:
            logging.debug("unable to parse url {}".format(url.value))
            return False

        formatted_url = urlunparse(parsed_url)

        # update brocess if we're configured to do so
        if self.update_brocess and parsed_url.hostname and not is_ipv4(parsed_url.hostname):
            logging.debug("updating brocess with crawlphish request for {}".format(parsed_url.hostname))
            add_httplog(parsed_url.hostname)

        # what proxies are we going to use to attempt to download the url?
        # these are attempted in the order specified in the configuration setting
        proxy_configs = []
        for name in self.proxies.split(','):
            if name == 'GLOBAL':
                proxy_configs.append(( name, saq.PROXIES ))
            else:
                proxy_configs.append(( name, saq.OTHER_PROXIES[name] ))
                
        proxy_result = None

        for index, proxy_config in enumerate(proxy_configs):
            proxy_name, proxy_config = proxy_config

            proxy_result = CloudphishProxyResult()
            proxy_result.proxy_name = proxy_name
            analysis.proxies.append(proxy_name)
            analysis.proxy_results[proxy_name] = proxy_result
            session = requests.Session()
            session.proxies = proxy_config

            try:
                logging.info("requesting url {} via {}".format(formatted_url, proxy_name))
                response = session.request('GET', formatted_url,
                                           headers=self.headers,
                                           timeout=self.timeout,
                                           allow_redirects=True,
                                           verify=False,
                                           stream=True)

                proxy_result.status_code = response.status_code
                proxy_result.status_code_reason = response.reason
                logging.info("url request result {} ({}) for {}".format(response.status_code,
                                                                        response.reason,
                                                                        formatted_url))

                for header in response.headers.keys():
                    proxy_result.headers[header] = response.headers[header]

                for part in response.history:
                    proxy_result.history.append(part.url)

                # did we get an error code?
                if math.floor(response.status_code / 100) in [ 4, 5 ]:
                    proxy_result.error_reason = '({}) {}'.format(proxy_result.status_code, 
                                                                 proxy_result.status_code_reason)
                    continue

                # all is well -- break out and download the content
                break

            except requests.Timeout as e:
                proxy_result.error_reason = "request timed out"
                continue
            except Exception as e:
                proxy_result.error_reason = str(e)
                #report_exception()
                continue

            # we should never get here
            logging.error("executed invalid branch?")
            break

        # did we successfully start a download?
        if proxy_result.error_reason is not None:
            logging.info("unable to download {}: {}".format(formatted_url, proxy_result.error_reason))
            return True

        path_components = [x for x in parsed_url.path.split('/') if x.strip()]

        # need to figure out what to call it
        file_name = None
        # content-disposition header is the official way
        if 'content-disposition' in response.headers:
            file_name = response.headers['content-disposition']
            # we could potentially see there here: attachment; filename="blah..."
            content_file_match = re.search('attachment; filename*?="?(?P<real_filename>[^"]+)"?',
                                            response.headers['content-disposition'] )
            if content_file_match:
                file_name = content_file_match.group('real_filename')

                # handle rfc5987 which allows utf-8 encoding and url-encoding
                if file_name.lower().startswith("utf-8''"):
                    file_name = file_name[7:]
                    file_name = urllib.unquote(file_name).decode('utf8')

        # otherwise we use the last element of the path
        if not file_name and parsed_url.path and not parsed_url.path.endswith('/'):
            file_name = path_components[-1]

        # default if we can't figure it out
        if not file_name:
            file_name = 'unknown.crawlphish'

        # truncate if too long
        if len(file_name) > self.max_file_name_length:
            file_name = file_name[len(file_name) - self.max_file_name_length:]

        # replace invalid filesystem characters
        file_name = secure_filename(file_name)

        # make the crawlphish dir
        dest_dir = os.path.join(self.root.storage_dir, 'crawlphish')
        try:
            if not os.path.isdir(dest_dir):
                os.makedirs(dest_dir)
        except Exception as e:
            logging.error("unable to create directory {}: {}".format(dest_dir, e))
        file_path = os.path.join(dest_dir, file_name)

        # prevent file path collision
        if os.path.isfile(file_path):
            duplicate_count = 1
            file_path = os.path.join(dest_dir, "{}_{}".format(duplicate_count, file_name))
            while os.path.isfile(file_path):
                duplicate_count = duplicate_count + 1
                file_path = os.path.join(dest_dir, "{}_{}".format(duplicate_count, file_name))

        # download the results up to the limit
        try:
            bytes_downloaded = 0
            with open(file_path, 'wb') as fp:
                for chunk in response.iter_content(io.DEFAULT_BUFFER_SIZE):
                    bytes_downloaded += len(chunk)
                    fp.write(chunk)

                    if bytes_downloaded >= self.max_download_size:
                        logging.debug("exceeded max download size for {}".format(url))
                        response.close()

            logging.debug("downloaded {} bytes for {}".format(bytes_downloaded, file_path))

        except Exception as e:
            analysis.downloaded = False
            proxy_result.error_reason = "data transfer interrupted: {}".format(e)
            logging.debug("url {} transfer failed: {}".format(url, e))
            return True

        # record all the details of the transaction
        analysis.downloaded = True
        analysis.file_name = file_name
        analysis.requested_url = formatted_url
        analysis.final_url = response.url

        # if the final url is different than the original url, record that url as an observable
        final_url = None
        if analysis.final_url and analysis.final_url != url.value:
            final_url = analysis.add_observable(F_URL, analysis.final_url, o_time=url.time)
            if final_url:
                final_url.add_tag('redirection_target')
                final_url.add_relationship(R_REDIRECTED_FROM, url)

        #if len(response.history) > 1:
            #url.add_tag('redirection')

        # and add the file for processing
        download = analysis.add_observable(F_FILE, os.path.relpath(file_path, start=self.root.storage_dir))
        if download: 
            download.add_relationship(R_DOWNLOADED_FROM, final_url if final_url else url)
            # only extract if non-error http response
            if response.status_code >= 200 and response.status_code <= 299:
                download.add_directive(DIRECTIVE_EXTRACT_URLS)

        return True

class LiveBrowserAnalysis(Analysis):

    KEY_TITLE = 'title'
    KEY_STDOUT = 'stdout'
    KEY_STDERR = 'stderr'
    KEY_ERROR = 'error'

    def initialize_details(self):   
        self.details = {
            LiveBrowserAnalysis.KEY_TITLE: None,
            LiveBrowserAnalysis.KEY_STDOUT: None,
            LiveBrowserAnalysis.KEY_STDERR: None,
            LiveBrowserAnalysis.KEY_ERROR: None,
        }

    @property
    def title(self):
        return self.details_property(LiveBrowserAnalysis.KEY_TITLE)

    @title.setter
    def title(self, value):
        self.details[LiveBrowserAnalysis.KEY_TITLE] = value

    @property
    def stdout(self):
        return self.details_property(LiveBrowserAnalysis.KEY_STDOUT)

    @stdout.setter
    def stdout(self, value):
        self.details[LiveBrowserAnalysis.KEY_STDOUT] = value

    @property
    def stderr(self):
        return self.details_property(LiveBrowserAnalysis.KEY_STDERR)

    @stderr.setter
    def stderr(self, value):
        self.details[LiveBrowserAnalysis.KEY_STDERR] = value

    @property
    def error(self):
        return self.details_property(LiveBrowserAnalysis.KEY_ERROR)
       
    @error.setter
    def error(self, value):
        self.details[LiveBrowserAnalysis.KEY_ERROR] = value

    def generate_summary(self):
        if self.details is None:
            return None

        if self.stdout is None:
            return None

        result = 'Live Browser Analysis'

        if self.error:
            result = '{}: ERROR DOWNLOADING'
        elif self.title:
            result = '{}: {}'.format(result, self.title)

        return result

class LiveBrowserAnalyzer(AnalysisModule):
    """What does this look like in a web browser?"""

    def verify_environment(self):
        self.verify_config_exists('get_screenshot_path')
        self.verify_path_exists(self.config['get_screenshot_path'])

    @property
    def get_screenshot_path(self):
        path = self.config['get_screenshot_path']
        if os.path.isabs(path):
            return path
        return os.path.join(saq.SAQ_HOME, path)

    @property
    def remote_server(self):
        return self.config['remote_server']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def generated_analysis_type(self):
        return LiveBrowserAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    #def execute_analysis(self, *args, **kwargs):
        #return True

    def execute_analysis(self, _file):

        # is this an html file?
        if _file.mime_type != 'text/html':
            #logging.info("MARKER: file {} has invalid mime type {}".format(_file.value, _file.mime_type))
            return False

        # this is what we ultimately want to render
        # it will either be a URL or a local HTML file
        target = None

        # if this file was downloaded from a URL then we want to render the URL
        url = None
        parsed_url = None

        if _file.has_relationship(R_DOWNLOADED_FROM):

            url = _file.get_relationship_by_type(R_DOWNLOADED_FROM).target

            # NOTE we do not call wait_for_analysis because the crawlphish module only runs inside the
            # cloudphish engine so it probably won't be available for waiting
            # but at this point you should already have it

            # did we get an error response from the web server?
            crawlphish_analysis = url.get_analysis(CrawlphishAnalysisV2)
            if not crawlphish_analysis:
                logging.error("unable to get CrawlphishAnalysisV2 for {}".format(url))
                return False

            if crawlphish_analysis.status_code < 200 or crawlphish_analysis.status_code > 299:
                logging.debug("url {} has status code {} (skipping live browser analysis)".format(url,
                              crawlphish_analysis.status_code))
                return False

            try:
                parsed_url = urlparse(url.value)
            except Exception as e:
                logging.error("unable to parse url {}: {}".format(url.value, e))
                return False

            target = url.value

        else:
            from saq.modules.email import EmailAnalysis
            # if this file was part of an Email then we just render the HTML
            if not [a for a in _file.parents if isinstance(a, EmailAnalysis)]:
                #logging.info("MARKER: no email analysis found for {}".format(_file))
                return False

            # we exclude rendering some content based on tags generated by yara rules
            from saq.modules.file_analysis import YaraScanResults_v3_4
            self.wait_for_analysis(_file, YaraScanResults_v3_4)
            
            if _file.has_tag('no_render'):
                logging.debug("file {} has tag no_render: skipping live browser analysis")
                return False

            target = os.path.join(self.root.storage_dir, _file.value)

        output_file = None
        output_path = None
        count = 0

        while True:
            output_file = '{}_{:03}.png'.format(parsed_url.hostname if url else os.path.basename(_file.value), count)
            output_file = output_file.replace(" ", "_")
            output_path = os.path.join(self.root.storage_dir, os.path.dirname(_file.value), output_file)
            if os.path.exists(output_path):
                count += 1
                continue

            break

        logging.info("downloading screenshot for {} to {}".format(target, output_file))
        analysis = self.create_analysis(_file)

        new_target = None

        try:
            # make sure the file ends with .html
            # otherwise the browser will render the html as text
            if not target.lower().endswith('.html'):
                new_target = '{}.html'.format(target)
                if not os.path.islink(new_target):
                    try:
                        os.symlink(os.path.basename(target), new_target)
                        target = new_target
                    except Exception as e:
                        logging.error("unable to create symlink {}: {}".format(new_target, e))
                        
            p = Popen([self.get_screenshot_path, target, output_path, self.remote_server], 
                      stdout=PIPE, stderr=PIPE, universal_newlines=True)
            _stderr, _stdout = p.communicate(timeout=self.timeout)

            analysis.error = False

            for line in _stdout:
                if line.startswith('Title:'):
                    analysis.title = line.split(':', 1)[1].strip()
                    continue

                # did our request fail?
                if line.startswith('Traceback (most recent call last):'):
                    analysis.error = True
                    break

            analysis.stdout = _stdout
            analysis.stderr = _stderr

            if os.path.exists(output_path):
                screen_shot = analysis.add_observable(F_FILE, os.path.relpath(output_path, 
                                                                              start=self.root.storage_dir))
                if screen_shot:
                    screen_shot.add_tag('screenshot')
                    # we don't want to analyze this image at all
                    screen_shot.add_directive(DIRECTIVE_EXCLUDE_ALL)
            else:
                logging.error("missing {}".format(output_path))

        except Exception as e:
            logging.warning("unable to browse to {}: {}".format(target, e))
            #report_exception()
            return False

        finally:
            # make sure we remove the symlink we created, if we created one
            if new_target:
                try:
                    os.remove(new_target)
                except Exception as e:
                    logging.error("unable to delete temp symlink {}: {}".format(new_target, e))

        return True

KEY_PROTECTION_TYPE = 'protection_type'
KEY_EXTRACTED_URL = 'extracted_url'

class ProtectedURLAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_PROTECTION_TYPE: None,
            KEY_EXTRACTED_URL: None }

    @property
    def protection_type(self):
        return self.details_property(KEY_PROTECTION_TYPE)

    @protection_type.setter
    def protection_type(self, value):
        self.details[KEY_PROTECTION_TYPE] = value

    @property
    def extracted_url(self):
        return self.details_property(KEY_EXTRACTED_URL)

    @extracted_url.setter
    def extracted_url(self, value):
        self.details[KEY_EXTRACTED_URL] = value

    def generate_summary(self):
        if not self.protection_type:
            return None

        if not self.extracted_url:
            return None

        return "Protected URL Analysis: detected type {}".format(self.protection_type)

PROTECTION_TYPE_OUTLOOK_SAFELINKS = 'outlook safelinks'
PROTECTION_TYPE_DROPBOX = 'dropbox'
PROTECTION_TYPE_ONE_DRIVE = 'one drive'
PROTECTION_TYPE_GOOGLE_DRIVE = 'google drive'
PROTECTION_TYPE_SHAREPOINT = 'sharepoint'

REGEX_GOOGLE_DRIVE = re.compile(r'drive\.google\.com/file/d/([^/]+)/view')
REGEX_SHAREPOINT = re.compile(r'^/:b:/g/(.+)/([^/]+)$')

class ProtectedURLAnalyzer(AnalysisModule):
    """Is this URL protected by another company by wrapping it inside another URL they check first?"""
    
    @property
    def generated_analysis_type(self):
        return ProtectedURLAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, url):

        protection_type = None
        extracted_url = None

        try:
            parsed_url = urlparse(url.value)
        except Exception as e:
            logging.error("unable to parse url {}: {}".format(url.value, e))
            return False

        # "safelinks" by outlook
        if parsed_url.netloc.lower().endswith('safelinks.protection.outlook.com'):
            qs = parse_qs(parsed_url.query)
            if 'url' in qs:
                protection_type = PROTECTION_TYPE_OUTLOOK_SAFELINKS
                extracted_url = qs['url'][0]

        # dropbox links
        if parsed_url.netloc.lower().endswith('.dropbox.com'):
            qs = parse_qs(parsed_url.query)
            modified = False
            if 'dl' in qs:
                if qs['dl'] == ['0']:
                    qs['dl'] = '1'
                    modified = True
            else:
                qs['dl'] = '1'
                modified = True

            if modified:
                # rebuild the query
                protection_type = PROTECTION_TYPE_DROPBOX
                extracted_url = urlunparse((parsed_url.scheme, 
                                           parsed_url.netloc,
                                           parsed_url.path,
                                           parsed_url.params,
                                           urlencode(qs),
                                           parsed_url.fragment))

        # one drive links
        if parsed_url.netloc.lower().endswith('1drv.ms'):
            # need to wait for the redirection information
            crawlphish_analysis = self.wait_for_analysis(url, CrawlphishAnalysisV2)
            if not crawlphish_analysis:
                logging.debug("one drive url {} requires unavailable crawlphish analysis".format(url.value))
                return False

            # https://1drv.ms/b/s!AvqIO0JVRziVa0IWW7c6GG3YkdU
            # redirects to https://onedrive.live.com/redir?resid=95384755423B88FA!107&authkey=!AEIWW7c6GG3YkdU&ithint=file%2cpdf
            # transform to https://onedrive.live.com/download?authkey=!AEIWW7c6GG3YkdU&cid=95384755423B88FA&resid=95384755423B88FA!107&parId=root&o=OneUp

            # the final url should be the redirection target
            if not crawlphish_analysis.final_url:
                logging.debug("one drive url {} missing final url".format(url.value))
                return False

            try:
                parsed_final_url = urlparse(crawlphish_analysis.final_url)
                _qs = parse_qs(parsed_final_url.query)
                #logging.info("MARKER: {}".format(crawlphish_analysis.final_url))
                #logging.info("MARKER: {}".format(_qs))
            except Exception as e:
                logging.error("unable to parse final url {}: {}".format(crawlphish_analysis.final_url, e))
                return False

            protection_type = PROTECTION_TYPE_ONE_DRIVE
            extracted_url = 'https://onedrive.live.com/download?authkey={}&resid={}&parId=root&o=OneUp'.format(
                            _qs['authkey'][0], _qs['resid'][0])

            logging.info("translated one drive url {} to {}".format(url.value, extracted_url))

        # google drive links
        m = REGEX_GOOGLE_DRIVE.search(url.value)
        if m:
            # sample
            # https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view
            # turns into
            # https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download

            google_id = m.group(1)

            protection_type = PROTECTION_TYPE_GOOGLE_DRIVE
            extracted_url = 'https://drive.google.com/uc?authuser=0&id={}&export=download'.format(google_id)
            logging.info("translated google drive url {} to {}".format(url.value, extracted_url))

        # sharepoint download links
        if parsed_url.netloc.lower().endswith('.sharepoint.com'):
            # user gets this link in an email
            # https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD
            # needs to turn into this link
            # https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ

            # so the URL format seems to be this
            # https://SITE.shareponit.com/:b:/g/PATH/ID?e=DATA
            # not sure if NAME can contain subdirectories so we'll assume it can
            m = REGEX_SHAREPOINT.match(parsed_url.path)
            parsed_qs = parse_qs(parsed_url.query)
            if m and 'e' in parsed_qs:
                protection_type = PROTECTION_TYPE_SHAREPOINT
                extracted_url = urlunparse((parsed_url.scheme,
                                            parsed_url.netloc,
                                            '/{}/_layouts/15/download.aspx'.format(m.group(1)),
                                            parsed_url.params,
                                            urlencode({'e': parsed_qs['e'][0], 'share': m.group(2)}),
                                            parsed_url.fragment))

                logging.info("translated sharepoint url {} to {}".format(url.value, extracted_url))
                
        # do others here...

        if not extracted_url or not protection_type:
            return False

        analysis = self.create_analysis(url)
        analysis.protection_type = protection_type
        analysis.extracted_url = extracted_url
        extracted_url = analysis.add_observable(F_URL, extracted_url)

        # don't analyze the extracted url with this module again
        extracted_url.exclude_analysis(self)
        
        # copy any directives so they apply to the extracted one
        url.copy_directives_to(extracted_url)
        return True
