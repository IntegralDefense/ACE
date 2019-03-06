# vim: sw=4:ts=4:et:cc=120

import datetime
import logging
import os.path
import re

from subprocess import Popen, PIPE

import saq

from saq.constants import *
from saq.analysis import Analysis
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.whitelist import BrotexWhitelist, \
    WHITELIST_TYPE_HTTP_SRC_IP, WHITELIST_TYPE_HTTP_HOST, WHITELIST_TYPE_HTTP_DEST_IP

_pattern_brotex_package = re.compile(r'(C[^\.]+)\.http\.tar$')
_pattern_message_dir = re.compile(r'^message_([0-9]+)$')

KEY_REQUESTS = 'requests'

KEY_TIME = 'time'
KEY_SRC_IP = 'src_ip'
KEY_SRC_PORT = 'src_port'
KEY_DEST_IP = 'dest_ip'
KEY_DEST_PORT = 'dest_port'
KEY_METHOD = 'method'
KEY_HOST = 'host'
KEY_URI = 'uri'
KEY_REFERRER = 'referrer'
KEY_USER_AGENT = 'user_agent'
KEY_STATUS_CODE = 'status_code'
KEY_FILES = 'files'

# XXX new stuff below
REGEX_CONNECTION_ID = re.compile(r'^(C[^\.]+\.\d+)\.ready$')
HTTP_DETAILS_REQUEST = 'request'
HTTP_DETAILS_REPLY = 'reply'
HTTP_DETAILS_READY = 'ready'

class BroHTTPStreamAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # http whitelist
        self.whitelist = None

        # path to the whitelist file
        self.whitelist_path = os.path.join(saq.SAQ_HOME, self.config['whitelist_path'])

    def execute_pre_analysis(self):
        if self.root.alert_type != ANALYSIS_TYPE_BRO_HTTP:
            return False

        # process the .ready file
        # file format is as follows
        #
        # C7kebl1wNwKQ1qOPck.1.ready
        # time = 1537467014.49546
        # interrupted = F
        # finish_msg = message ends normally
        # body_length = 433994
        # content_gap_length = 0
        # header_length = 494
        #

        self.root.details = {
            HTTP_DETAILS_REQUEST: [],
            HTTP_DETAILS_REPLY: [],
            HTTP_DETAILS_READY: [],
        }

        stream_prefix = None
        ready_path = None
        request_path = None
        request_entity_path = None
        reply_path = None
        reply_entity_path = None

        for file_observable in self.root.observables:
            m = REGEX_CONNECTION_ID.match(file_observable.value)
            if m:
                stream_prefix = m.group(1)
                # the ready file contains stream summary info
                ready_path = os.path.join(self.root.storage_dir, file_observable.value)
            elif file_observable.value.endswith('.request'):
                # http request headers
                request_path = os.path.join(self.root.storage_dir, file_observable.value)
            elif file_observable.value.endswith('request.entity'):
                # http request content (POST content for example)
                request_entity_path = os.path.join(self.root.storage_dir, file_observable.value)
            elif file_observable.value.endswith('.reply'):
                # http response headers
                reply_path = os.path.join(self.root.storage_dir, file_observable.value)
            elif file_observable.value.endswith('.reply.entity'):
                # http response content
                reply_entity_path = os.path.join(self.root.storage_dir, file_observable.value)

        if stream_prefix is None:
            logging.error("unable to find .ready file for http submission in {}".format(self.root))
            return False

        # make sure we have at least the files we expect (summary, and request headers)
        for path in [ ready_path, request_path ]:
            if not os.path.exists(path):
                logging.error("missing expected file {}".format(path))
                return False

        # parse the ready file
        stream_time = None
        interrupted = False
        content_gap_length = 0

        with open(ready_path, 'r') as fp:
            for line in fp:
                self.root.details[HTTP_DETAILS_READY].append(line.strip())
                key, value = [_.strip() for _ in line.split(' = ')]
                
                if key == 'time':
                    stream_time = datetime.datetime.fromtimestamp(float(value))
                elif key == 'interrupted':
                    interrupted = value == 'T'
                elif key == 'content_gap_length':
                    content_gap_length = int(value)

        # parse the request
        request_headers = [] # of tuples of key, value
        request_headers_lookup = {} # key = key.lower()

        with open(request_path, 'r') as fp:
            request_ipv4 = fp.readline().strip()
            request_method = fp.readline().strip()
            request_original_uri = fp.readline().strip()
            request_unescaped_uri = fp.readline().strip()
            request_version = fp.readline().strip()

            logging.info("processing {} ipv4 {} method {} uri {}".format(stream_prefix, request_ipv4,
                                                                         request_method, request_original_uri))

            self.root.details[HTTP_DETAILS_REQUEST].append(request_ipv4)
            self.root.details[HTTP_DETAILS_REQUEST].append(request_method)
            self.root.details[HTTP_DETAILS_REQUEST].append(request_original_uri)
            self.root.details[HTTP_DETAILS_REQUEST].append(request_unescaped_uri)
            self.root.details[HTTP_DETAILS_REQUEST].append(request_version)

            for line in fp:
                self.root.details[HTTP_DETAILS_REQUEST].append(line.strip())
                key, value = [_.strip() for _ in line.split('\t')]
                request_headers.append((key, value))
                request_headers_lookup[key.lower()] = value

        # parse the response if it exists
        reply_headers = [] # of tuples of key, value
        reply_headers_lookup = {} # key = key.lower()
        reply_version = None
        reply_code = None
        reply_reason = None
        reply_ipv4 = None
        reply_port = None

        if os.path.exists(reply_path):
            try:
                with open(reply_path, 'r') as fp:
                    first_line = fp.readline()
                    self.root.details[HTTP_DETAILS_REPLY].append(first_line)
                    reply_ipv4, reply_port = [_.strip() for _ in first_line.split('\t')]
                    reply_port = int(reply_port)
                    reply_version = fp.readline().strip()
                    reply_code = fp.readline().strip()
                    reply_reason = fp.readline().strip()

                    self.root.details[HTTP_DETAILS_REPLY].append(reply_version)
                    self.root.details[HTTP_DETAILS_REPLY].append(reply_code)
                    self.root.details[HTTP_DETAILS_REPLY].append(reply_reason)

                    for line in fp:
                        self.root.details[HTTP_DETAILS_REPLY].append(line.strip())
                        key, value = [_.strip() for _ in line.split('\t')]
                        reply_headers.append((key, value))
                        reply_headers_lookup[key.lower()] = value
            except UnicodeDecodeError as e:
                logging.info(f"{stream_prefix} contains binary content in headers - skipping")
                return False

        self.root.description = 'BRO HTTP Scanner Detection - {} {}'.format(request_method, request_original_uri)
        self.root.event_time = datetime.datetime.now() if stream_time is None else stream_time

        self.root.add_observable(F_IPV4, request_ipv4)
        if reply_ipv4:
            self.root.add_observable(F_IPV4, reply_ipv4)
            self.root.add_observable(F_IPV4_CONVERSATION, create_ipv4_conversation(request_ipv4, reply_ipv4))

        if 'host' in request_headers_lookup:
            self.root.add_observable(F_FQDN, request_headers_lookup['host'])

        uri = request_original_uri[:]
        if 'host' in request_headers_lookup:
            # I don't think we'll ever see https here as that gets parsed as a different protocol in bro
            # we should only be seeing HTTP traffic
            uri = '{}://{}{}{}'.format('https' if reply_port == 443 else 'http', 
                                       request_headers_lookup['host'], 
                                       # if the default port is used then leave it out, otherwise include it in the url
                                       '' if reply_port == 80 else ':{}'.format(reply_port), 
                                       uri)
            self.root.add_observable(F_URL, uri)

        if request_original_uri != request_unescaped_uri:
            uri = request_unescaped_uri[:]
            if 'host' in request_headers_lookup:
                uri = '{}:{}'.format(request_headers_lookup['host'], uri)
                self.root.add_observable(F_URL, uri)

        # has the destination host been whitelisted?
        if self.whitelist is None:
            self.whitelist = BrotexWhitelist(self.whitelist_path)
            self.whitelist.load_whitelist()
        else:
            self.whitelist.check_whitelist()

        if 'host' in request_headers_lookup and request_headers_lookup['host']:
            if self.whitelist.is_whitelisted_fqdn(request_headers_lookup['host']):
                logging.debug("stream {} whitelisted by fqdn {}".format(stream_prefix, request_headers_lookup['host']))
                self.root.whitelisted = True
                return

class BrotexHTTPPackageAnalysis(Analysis):

    def initialize_details(self):
        self.details = {
            KEY_REQUESTS: []
        }

    @property
    def requests(self):
        if not self.details:
            return []

        return self.details[KEY_REQUESTS]

    def generate_summary(self):
        if not self.details:
            return None

        return "Brotex HTTP Package Analysis - {} requests".format(len(self.requests))

class BrotexHTTPPackageAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('whitelist_path')
        self.verify_config_exists('maximum_http_requests')
        self.verify_path_exists(self.config['whitelist_path'])

    def load_config(self):
        self.whitelist = BrotexWhitelist(os.path.join(saq.SAQ_HOME, self.config['whitelist_path']))
        self.auto_reload()

    @property
    def generated_analysis_type(self):
        return BrotexHTTPPackageAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def auto_reload(self):
        # make sure the whitelist if up-to-date
        self.whitelist.check_whitelist()

    def execute_analysis(self, _file):
        # is this a brotex package?
        if not _pattern_brotex_package.match(_file.value):
            logging.debug("{} does not appear to be a brotex http package".format(_file))
            return False

        analysis = self.create_analysis(_file)
        logging.debug("{} is a valid brotex http package".format(_file))

        # extract the contents of the pacakge
        file_path = os.path.join(self.root.storage_dir, _file.value)

        brotex_dir = '{}.brotex'.format(os.path.join(self.root.storage_dir, _file.value))
        if not os.path.isdir(brotex_dir):
            try:
                os.mkdir(brotex_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(brotex_dir, e))
                return False

        # extract all the things into the brotex_dir
        p = Popen(['tar', 'xf', file_path, '-C', brotex_dir], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        p.wait()

        if p.returncode:
                logging.warning("unable to extract files from {} (tar returned error code {}".format(
                                _file, p.returncode))
                return False

        if stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, stderr))

        # iterate over all the extracted files
        message_dirs = {}
        for dirpath, dirnames, filenames in os.walk(brotex_dir):
            for dirname in dirnames:
                m = _pattern_message_dir.match(dirname)
                if m:
                    message_number = m.group(1)
                    if message_number not in message_dirs:
                        message_dirs[message_number] = os.path.relpath(os.path.join(dirpath, dirname), start=brotex_dir)
                        logging.debug("found message number {} in {}".format(message_number, _file))
                        continue

        count = 0
        maximum_http_requests = self.config.getint('maximum_http_requests')

        for message_number in message_dirs.keys():
            if maximum_http_requests:
                count += 1
                if count > maximum_http_requests:
                    logging.debug("{} exceeded maximum_http_requests".format(_file))
                    break

            message_dir = os.path.join(brotex_dir, message_dirs[message_number])
            # there should be a file called protocol.http in this directory
            protocol_path = os.path.join(message_dir, 'protocol.http')
            if not os.path.exists(protocol_path):
                logging.error("missing {} for message {} for {}".format(protocol_path, message_number, _file))
                continue

            is_whitelisted = False
            http_request = {
                KEY_TIME: None,
                KEY_SRC_IP: None,
                KEY_SRC_PORT: None,
                KEY_DEST_IP: None,
                KEY_DEST_PORT: None,
                KEY_METHOD: None,
                KEY_HOST: None,
                KEY_URI: None,
                KEY_REFERRER: None,
                KEY_USER_AGENT: None,
                KEY_STATUS_CODE: None,
                KEY_FILES: [] 
            }

            # parse this file for the http protocol information
            with open(protocol_path, 'rb') as fp:
                for line in fp:
                    if line.startswith(b'ts:'):
                        http_request[KEY_TIME] = float(line.decode().strip()[len('ts:'):])
                        logging.debug("parsed event time {} from protocol file".format(http_request[KEY_TIME]))
                        continue

                    if line.startswith(b'host:'):
                        http_request[KEY_HOST] = line.decode().strip()[len('host:'):].strip()
                        if self.whitelist.is_whitelisted(WHITELIST_TYPE_HTTP_HOST, http_request[KEY_HOST]):
                            logging.debug("http {} message_number {} whitelisted by {} {}".format(
                                          _file, message_number, WHITELIST_TYPE_HTTP_HOST, http_request[KEY_HOST]))
                            is_whitelisted = True

                        continue

                    if line.startswith(b'method:'):
                        http_request[KEY_METHOD] = line.decode().strip()[len('method:'):].strip()
                        continue

                    if line.startswith(b'uri:'):
                        http_request[KEY_URI] = line.decode(errors='ignore').strip()[len('uri:'):].strip()
                        continue

                    if line.startswith(b'referrer:'):
                        http_request[KEY_REFERRER] = line.decode().strip()[len('referrer:'):].strip()
                        continue

                    if line.startswith(b'user_agent:'):
                        http_request[KEY_USER_AGENT] = line.decode().strip()[len('user_agent:'):].strip()
                        continue

                    if line.startswith(b'status_code:'):
                        http_request[KEY_STATUS_CODE] = line.decode().strip()[len('status_code:'):].strip()
                        continue

                    if line.startswith(b'id:'):
                        http_connection_details = line.decode().strip()[len('id:'):]
                        m = re.match(r'^\[orig_h=([^,]+?), orig_p=([^,]+?), resp_h=([^,]+?), resp_p=([^\]]+?)\]$', 
                                     http_connection_details.strip())
                        if m:
                            http_request[KEY_SRC_IP], http_request[KEY_SRC_PORT], http_request[KEY_DEST_IP], http_request[KEY_DEST_PORT] = m.groups()

                            if self.whitelist.is_whitelisted(WHITELIST_TYPE_HTTP_SRC_IP, http_request[KEY_SRC_IP]):
                                is_whitelisted = True
                                logging.debug("http {} message_number {} whitelisted by {} {}".format(
                                              _file, message_number, WHITELIST_TYPE_HTTP_SRC_IP, http_request[KEY_SRC_IP]))
                            if self.whitelist.is_whitelisted(WHITELIST_TYPE_HTTP_DEST_IP, http_request[KEY_DEST_IP]):
                                is_whitelisted = True
                                logging.debug("http {} message_number {} whitelisted by {} {}".format(
                                              _file, message_number, WHITELIST_TYPE_HTTP_DEST_IP, http_request[KEY_DEST_IP]))
                        else:
                            logging.debug("could not determine IP addresses for {}".format(http_connection_details))

            if is_whitelisted:
                logging.debug("message_number {} is whitelisted".format(message_number))
                continue

            # then add any files you can find in this directory
            http_request[KEY_FILES] = []
            for file_name in os.listdir(message_dir):
                # skip these generated protocol files we've already parsed
                if file_name == 'protocol.http':
                    continue

                file_path = os.path.relpath(os.path.join(message_dir, file_name), start=self.root.storage_dir)
                http_request[KEY_FILES].append(file_path)
                analysis.add_observable(F_FILE, file_path)

            if http_request[KEY_SRC_IP]:
                analysis.add_observable(F_IPV4, http_request[KEY_SRC_IP])

            if http_request[KEY_DEST_IP]:
                analysis.add_observable(F_IPV4, http_request[KEY_DEST_IP])

            if http_request[KEY_SRC_IP] and http_request[KEY_DEST_IP]:
                analysis.add_observable(F_IPV4_CONVERSATION, create_ipv4_conversation(
                                        http_request[KEY_SRC_IP], http_request[KEY_DEST_IP]))

            if http_request[KEY_HOST]:
                analysis.add_observable(F_FQDN, http_request[KEY_HOST])

            if http_request[KEY_URI]:
                analysis.add_observable(F_URL, http_request[KEY_URI])

            analysis.requests.append(http_request)

        # if we didn't get any requests then we whitelist the whole thing
        if not analysis.requests:
            logging.debug("no requests available from {} -- whitelisting".format(_file))
            _file.mark_as_whitelisted()

        return True
