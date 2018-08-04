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
