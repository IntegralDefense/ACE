# vim: sw=4:ts=4:et:cc=120
import datetime
import email.header
import email.parser
import email.utils
import gzip
import hashlib
import json
import logging
import os, os.path
import quopri
import re
import shutil
import socket
import subprocess
import uuid

#from subprocess import Popen, PIPE

import saq

from saq.analysis import Analysis, Observable, ProfilePointTarget, recurse_tree
from saq.brocess import query_brocess_by_email_conversation, query_brocess_by_source_email
from saq.constants import *
from saq.crypto import encrypt, decrypt
from saq.database import get_db_connection, execute_with_retry, Alert, use_db
from saq.email import normalize_email_address, search_archive, get_email_archive_sections
from saq.error import report_exception
from saq.modules import AnalysisModule, SplunkAnalysisModule, AnalysisModule
from saq.modules.util import get_email
from saq.process_server import Popen, PIPE
from saq.whitelist import BrotexWhitelist, WHITELIST_TYPE_SMTP_FROM, WHITELIST_TYPE_SMTP_TO

from msoffice_decrypt import MSOfficeDecryptor, UnsupportedAlgorithm
from html2text import html2text

_pattern_brotex_connection = re.compile(r'^connection\.([0-9]+)\.parsed$')
_pattern_brotex_package = re.compile(r'(C[^\.]+)\.smtp\.tar$')
_pattern_brotex_missing_stream_package = re.compile(r'(C[^\.]+)\.smtp\.tar\.[0-9]+\.missing_stream$')
# _162.128.171.76:58771-162.128.125.36:25_.stream
_pattern_brotex_stream = re.compile(
r'^_[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}'
'-'
'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}_\.stream$')

KEY_COUNT = 'count'
KEY_DECODED_SUBJECT = 'decoded_subject'
KEY_EMAIL = 'email'
KEY_EMAILS = 'emails'
KEY_ENVELOPES = 'envelopes'
KEY_ENVELOPES_MAIL_FROM = 'mail_from'
KEY_ENVELOPES_RCPT_TO = 'rcpt_to'
KEY_ENV_MAIL_FROM = 'env_mail_from'
KEY_ENV_RCPT_TO = 'env_rcpt_to'
KEY_FROM = 'from'
KEY_HEADERS = 'headers'
KEY_LOG_ENTRY = 'log_entry'
KEY_MESSAGE_ID = 'message-id'
KEY_O365_DETECTIONS = 'o365_detections'
KEY_ORIGINATING_IP = 'originating_ip'
KEY_PARSING_ERROR = 'parsing_error'
KEY_REPLY_TO = 'reply_to'
KEY_RESULT = 'result'
KEY_SENDER = 'sender'
KEY_SMTP_FILES = 'smtp_files'
KEY_SUBJECT = 'subject'
KEY_TIMED_OUT = 'timed_out'
KEY_TO = 'to'
KEY_UUIDS = 'uuids'
KEY_CONNECTION_ID = 'connection_id'
KEY_SOURCE_IPV4 = 'source_ipv4'
KEY_SOURCE_PORT = 'source_port'

TAG_OUTBOUND_EMAIL = 'outbound_email'

# regex to match an email header line
RE_EMAIL_HEADER = re.compile(r'^[^:]+:\s.*$')
# regex to match an email header continuation line
RE_EMAIL_HEADER_CONTINUE = re.compile(r'^\s.*$')

MAILBOX_ALERT_PREFIX = 'ACE Mailbox Scanner Detection -'
class MailboxEmailAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        return None

class MailboxEmailAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return MailboxEmailAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_ORIGINAL_EMAIL ]

    # TODO I think this maybe should be a post analysis thing?
    def execute_analysis(self, _file):
        # this is ONLY for analysis of type "mailbox"
        if self.root.alert_type != ANALYSIS_TYPE_MAILBOX:
            return False

        # did we end up whitelisting the email?
        # this actually shouldn't even fire because if the email is whitelisted then the work queue is ignored
        # for this analysis
        if self.root.whitelisted:
            return False

        email_analysis = self.wait_for_analysis(_file, EmailAnalysis)

        analysis = self.create_analysis(_file)

        if email_analysis is None or isinstance(email_analysis, bool):
            self.root.description = '{} unparsable email'.format(MAILBOX_ALERT_PREFIX)
        else:
            if email_analysis.decoded_subject:
                self.root.description = '{} {}'.format(MAILBOX_ALERT_PREFIX, email_analysis.decoded_subject)
            elif email_analysis.subject:
                self.root.description = '{} {}'.format(MAILBOX_ALERT_PREFIX, email_analysis.subject)
            else:
                self.root.description = '{} (no subject)'.format(MAILBOX_ALERT_PREFIX)

            # merge the email analysis into the details of the root analysis
            # XXX remove this
            self.root.details.update(email_analysis.details)

        return True

class BroSMTPStreamAnalysis(Analysis):
    def initialize_details(self):
        self.details = { }

    def generate_summary(self):
        result = "BRO SMTP Stream Analysis - "
        if not self.details:
            result += 'no email extracted'
        else:
            if KEY_CONNECTION_ID in self.details:
                result += '({}) '.format(self.details[KEY_CONNECTION_ID])
            if KEY_ENV_MAIL_FROM in self.details:
                result += 'MAIL FROM {} '.format(self.details[KEY_ENV_MAIL_FROM])
            if KEY_ENV_RCPT_TO in self.details:
                result += 'RCPT TO {} '.format(','.join(self.details[KEY_ENV_RCPT_TO]))

        return result

# regular expressions for parsing smtp files generated by bro extraction (see bro/ directory)
REGEX_BRO_SMTP_SOURCE_IPV4 = re.compile(r'^([^:]+):(\d+).*$')
REGEX_BRO_SMTP_MAIL_FROM = re.compile(r'^> MAIL FROM:<([^>]+)>.*$')
REGEX_BRO_SMTP_RCPT_TO = re.compile(r'^> RCPT TO:<([^>]+)>.*$')
REGEX_BRO_SMTP_DATA = re.compile(r'^< DATA 354.*$')

class BroSMTPStreamAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return BroSMTPStreamAnalysis

    @property
    def required_directives(self):
        return [ DIRECTIVE_ORIGINAL_SMTP ]

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        # this is ONLY for analysis of type "bro - smtp"
        if self.root.alert_type != ANALYSIS_TYPE_BRO_SMTP:
            return False

        # did we end up whitelisting the email?
        # this actually shouldn't even fire because if the email is whitelisted then the work queue is ignored
        # for this analysis
        if self.root.whitelisted:
            return False

        analysis = self.create_analysis(_file)
        path = os.path.join(self.root.storage_dir, _file.value)

        try:
            with open(path, 'r', errors='ignore') as fp:
                source_ipv4 = None
                source_port = None
                envelope_from = None
                envelope_to = []

                # the first line of the file has the source IP address of the smtp connection
                # in the following format: 172.16.139.143:38668/tcp

                line = fp.readline()
                m = REGEX_BRO_SMTP_SOURCE_IPV4.match(line)

                if not m:
                    raise ValueError("unable to parse soure address from {} ({})".format(path, line.strip()))
                else:
                    source_ipv4 = m.group(1)
                    source_port = m.group(2)

                    logging.debug("got source ipv4 {} port {} for {}".format(source_ipv4, source_port, path))

                # the second line is the time (in epoch UTC) that bro received the file
                line = fp.readline()
                self.root.event_time = datetime.datetime.utcfromtimestamp(int(line.strip()))
                logging.debug("got event time {} for {}".format(self.root.event_time, path))

                STATE_SMTP = 1
                STATE_DATA = 2

                state = STATE_SMTP
                rfc822_path = None
                rfc822_fp = None

                def _finalize():
                    # called when we detect the end of an SMTP stream OR the end of the file (data)
                    nonlocal rfc822_fp, source_ipv4, source_port, envelope_from, envelope_to, state

                    rfc822_fp.close()

                    logging.info("finished parsing {} from {}".format(rfc822_path, path))

                    # submit this for analysis...
                    email_file = analysis.add_observable(F_FILE, os.path.relpath(rfc822_path, 
                                                                                  start=self.root.storage_dir))
                    if email_file:
                        email_file.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                        # we don't scan the email as a whole because of all the random base64 data
                        # that randomly matches various indicators from crits
                        # instead we rely on all the extraction that we do and scan the output of those processes
                        email_file.add_directive(DIRECTIVE_NO_SCAN)
                        # make sure we archive it
                        email_file.add_directive(DIRECTIVE_ARCHIVE)

                    analysis.details = {
                        # the name of the file will equal the bro connection id
                        KEY_CONNECTION_ID: os.path.basename(path),
                        KEY_SOURCE_IPV4: source_ipv4,
                        KEY_SOURCE_PORT: source_port,
                        KEY_ENV_MAIL_FROM: envelope_from,
                        KEY_ENV_RCPT_TO: envelope_to,
                    }

                    self.root.description = 'BRO SMTP Scanner Detection - ' 

                    if source_ipv4:
                        observable = analysis.add_observable(F_IPV4, source_ipv4)

                    if envelope_from:
                        observable = analysis.add_observable(F_EMAIL_ADDRESS, envelope_from)
                        self.root.description += 'From {} '.format(envelope_from)

                    if envelope_to:
                        for to in envelope_to:
                            observable = analysis.add_observable(F_EMAIL_ADDRESS, to)
                            if envelope_from:
                                observable = analysis.add_observable(F_EMAIL_CONVERSATION, 
                                                                     create_email_conversation(envelope_from, to))

                        self.root.description += 'To {} '.format(','.join(envelope_to))

                    rfc822_fp = None
                    source_ipv4 = None
                    source_port = None
                    envelope_from = None
                    envelope_to = []

                    state = STATE_SMTP

                # smtp is pretty much line oriented
                while True:
                    line = fp.readline()
                    if line == '':
                        break

                    if state == STATE_SMTP:
                        m = REGEX_BRO_SMTP_MAIL_FROM.match(line)
                        if m:
                            envelope_from = m.group(1)
                            logging.debug("got envelope_from {} for {}".format(envelope_from, path))
                            continue

                        m = REGEX_BRO_SMTP_RCPT_TO.match(line)
                        if m:
                            envelope_to.append(m.group(1))
                            logging.debug("got envelope_to {} for {}".format(envelope_to, path))
                            continue

                        m = REGEX_BRO_SMTP_DATA.match(line)
                        if m:
                            state = STATE_DATA
                            rfc822_path = os.path.join(self.root.storage_dir, 'email.rfc822')
                            rfc822_fp = open(rfc822_path, 'w')
                            logging.debug("created {} for {}".format(rfc822_path, path))
                            continue

                        # any other command we skip
                        continue

                    # otherwise we're reading DATA and looking for the end of that
                    if line.strip() == ('> . .'):
                        _finalize()
                        continue

                    rfc822_fp.write(line)
                    continue

                # did the file end while we were reading SMTP data?
                if state == STATE_DATA:
                    _finalize()

            return True

        except Exception as e:
            logging.error("unable to parse smtp stream {}: {}".format(_file.value, e))
            #report_exception()
            shutil.copy(os.path.join(self.root.storage_dir, _file.value), os.path.join(saq.DATA_DIR, 'review', 'smtp'))
            return False

    def execute_post_analysis(self):
        if self.root.alert_type != ANALYSIS_TYPE_BRO_SMTP:
            return True

        # find the email we extracted from the stmp stream
        email_observable = self.root.find_observable(lambda o: o.has_directive(DIRECTIVE_ORIGINAL_EMAIL))
        if email_observable is None:
            return True

        email_analysis = email_observable.get_analysis(EmailAnalysis)
        if email_analysis is None or isinstance(email_analysis, bool):
            return True

        if email_analysis.decoded_subject is not None:
            self.root.description += ' Subject: {}'.format(email_analysis.decoded_subject)
        elif email_analysis.subject is not None:
            self.root.decoded_subject += ' Subject: {}'.format(email_analysis.subject)

        return True

class EncryptedArchiveAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    @property
    def decrypted_file(self):
        return self.details

    def generate_summary(self):
        if not self.details:
            return None

        return "Encrypted Archive Analysis - {}".format(self.details)

class EncryptedArchiveAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_program_exists('zcat')

    @property
    def generated_analysis_type(self):
        return EncryptedArchiveAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        # do we have the decryption password available?
        if not saq.ENCRYPTION_PASSWORD:
            return False

        # encrypted archives end with .gz.e
        if not _file.value.endswith('.gz.e'):
            return False

        file_path = os.path.join(self.root.storage_dir, _file.value)
        gzip_path = '{}.rfc822.gz'.format(file_path[:-len('.gz.e')])
        dest_path = '{}.rfc822'.format(file_path[:-len('.gz.e')])

        # decrypt and decompress the archive file
        try:
            decrypt(file_path, gzip_path)
            with gzip.open(gzip_path, 'rb') as fp_in:
                with open(dest_path, 'wb') as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

        except Exception as e:
            logging.error("unable to decrypt {}: {}".format(file_path, e))
            report_exception()
            return False

        analysis = self.create_analysis(_file)

        # add the resulting file as an observable
        file_observable = analysis.add_observable(F_FILE, os.path.relpath(dest_path, start=self.root.storage_dir))
        if file_observable:
            #file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
            file_observable.add_tag('decrypted_email')
        analysis.details = dest_path
        return True

class BrotexSMTPStreamArchiveResults(Analysis):
    def initialize_details(self):
        self.details = None

    @property
    def archive_path(self):
        return self.details

    def generate_summary(self):
        if not self.details:
            return None

        return "Archive Path - {}".format(self.details)

class BrotexSMTPStreamArchiveAction(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = socket.gethostname().lower()

    def verify_environment(self):
        self.verify_config_exists('archive_dir')
        self.verify_path_exists(self.config['archive_dir'])

    @property
    def generated_analysis_type(self):
        return BrotexSMTPStreamArchiveResults

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_ARCHIVE ]

    def execute_analysis(self, _file):
        # is this a brotex package?
        m = _pattern_brotex_package.match(_file.value)
        if not m:
            logging.debug("{} does not appear to be a brotex smtp package".format(_file))
            return False

        connection_id = m.group(1)
        logging.debug("archiving bro smtp connection {} from {}".format(connection_id, _file))

        # where do we put the file?
        archive_dir = os.path.join(saq.DATA_DIR, self.config['archive_dir'], self.hostname, connection_id[0:3])
        if not os.path.isdir(archive_dir):
            logging.debug("creating archive directory {}".format(archive_dir))

            try:
                os.makedirs(archive_dir)
            except:
                # it might have already been created by another process
                # mkdir is an atomic operation (FYI)
                if not os.path.isdir(archive_dir):
                    raise Exception("unable to create archive directory {}: {}".format(archive_dir, str(e)))

        analysis = self.create_analysis(_file)
        source_path = os.path.join(self.root.storage_dir, _file.value)
        archive_path = os.path.join(archive_dir, _file.value)
        if os.path.exists('{}.gz.e'.format(archive_path)):
            logging.warning("archive path {} already exists".format('{}.gz.e'.format(archive_path)))
            analysis.details = archive_path
            return True
        else:
            shutil.copy2(source_path, archive_path)

        archive_path += '.gz'

        # compress the data
        logging.debug("compressing {}".format(archive_path))
        try:
            with open(source_path, 'rb') as fp_in:
                with gzip.open(archive_path, 'wb') as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

        except Exception as e:
            logging.error("compression failed for {}: {}".format(archive_path, e))

        if not os.path.exists(archive_path):
            raise Exception("compression failed for {}".format(archive_path))

        # encrypt the archive file
        encrypted_file = '{}.e'.format(archive_path)

        try:
            encrypt(archive_path, encrypted_file)
        except Exception as e:
            logging.error("unable to encrypt archived stream {}: {}".format(archive_path, e))

        if os.path.exists(encrypted_file):
            logging.debug("encrypted {}".format(archive_path))
            try:
                os.remove(archive_path)
            except Exception as e:
                logging.error("unable to delete unencrypted archive file {}: {}".format(archive_path, e))
                raise e
        else:
            raise Exception("expected encrypted output file {} does not exist".format(encrypted_file))

        logging.debug("archived stream {} to {}".format(source_path, encrypted_file))

        analysis.details = archive_path
        return True

class BrotexSMTPPackageAnalysis(Analysis):

    KEY_CONNECTION_ID = 'connection_id'
    KEY_SMTP_STREAM = 'smtp_stream'
    KEY_MESSAGE_COUNT = 'message_count'

    def initialize_details(self):
        self.details = {
            BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID: None,
            BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM: None,
            BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT: 0 }

    @property
    def connection_id(self):
        if self.details and BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID in self.details:
            return self.details[BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID]

        return None

    @connection_id.setter
    def connection_id(self, value):
        self.details[BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID] = value

    @property
    def smtp_stream(self):
        if self.details and BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM in self.details:
            return self.details[BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM]

        return None

    @smtp_stream.setter
    def smtp_stream(self, value):
        self.details[BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM] = value

    @property
    def message_count(self):
        if self.details and BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT in self.details:
            return self.details[BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT]

        return 0

    @message_count.setter
    def message_count(self, value):
        assert isinstance(value, int)
        self.details[BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT] = value

    def generate_summary(self):
        if not self.details:
            return None

        prefix = "Brotex SMTP Package Analysis -"

        if self.smtp_stream:
            return "{} {}".format(prefix, self.smtp_stream)

        return "{} missing stream ({} emails detected)".format(prefix, self.message_count)

class BrotexSMTPPackageAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BrotexSMTPPackageAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        # is this a brotex package?
        m = _pattern_brotex_package.match(_file.value)
        if not m:
            logging.debug("{} does not appear to be a brotex smtp package".format(_file))
            return False

        logging.debug("{} is a valid brotex smtp package".format(_file))
        analysis = self.create_analysis(_file)
        analysis.connection_id = m.group(1)

        # view the contents of the package
        file_path = os.path.join(self.root.storage_dir, _file.value)
        _stdout = _stderr = None

        try:
            p = Popen(['tar', 'tf', file_path], stdout=PIPE, stderr=PIPE, universal_newlines=True)
            _stdout, _stderr = p.communicate() # meh
            p.wait()
        except Exception as e:
            logging.error("unable to view brotex package {}: {}".format(_file, e))
            report_exception()
            return False

        if _stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, _stderr)) # TODO fold stderr newlines

        #
        # basically the issue here is that bro sometimes does not record the TCP stream like we want it to
        # but it's still able to parse the SMTP data and extract the files
        # we want to do the best with what we've got
        #
            
        # parse the tar file listing to see if it has an smtp stream file
        smtp_stream_file = None

        for relative_path in _stdout.split('\n'):
            if _pattern_brotex_stream.match(os.path.basename(relative_path)):
                smtp_stream_file = relative_path
                break # this is all we need
            
            if _pattern_brotex_connection.match(os.path.basename(relative_path)):
                connection_file = relative_path
                continue

        # did we get the stream data?
        #while False: #smtp_stream_file:
        while smtp_stream_file:
            # extract *only* that file
            p = Popen(['tar', 'xf', file_path, '-C', self.root.storage_dir, smtp_stream_file], 
                      stdout=PIPE, stderr=PIPE, universal_newlines=True)
            stdout, stderr = p.communicate()
            p.wait()

            if p.returncode:
                logging.warning("unable to extract {} from {} (tar returned error code {}".format(
                                smtp_stream_file, _file, p.returncode))
                smtp_stream_file = None
                break

            if stderr:
                logging.warning("tar reported errors on {}: {}".format(_file, stderr))

            # add the extracted smtp stream file as an observable and let the SMTPStreamAnalysis module do it's work
            analysis.add_observable(F_FILE, os.path.relpath(
                                    os.path.join(self.root.storage_dir, smtp_stream_file), 
                                    start=self.root.storage_dir))

            analysis.smtp_stream = smtp_stream_file
            return True

        # -----------------------------------------------------------------------------------------------------------
        # 
        # otherwise bro didn't get the stream file so we need to make do with what we've got
        #

        logging.debug("stream file was not detected in {}".format(_file))

        brotex_dir = '{}.brotex'.format(os.path.join(self.root.storage_dir, _file.value))
        if not os.path.isdir(brotex_dir):
            try:
                os.mkdir(brotex_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(brotex_dir, e))
                return False

        # extract all the things into the brotex_dir
        p = Popen(['tar', 'xf', file_path, '-C', brotex_dir], 
                  stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()
        p.wait()

        if p.returncode:
                logging.warning("unable to extract files from {} (tar returned error code {}".format(
                                _file, p.returncode))
                return False

        if stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, stderr))

        # iterate over all the extracted files
        # map message numbers to the connection file
        connection_files = {} # key = message_number, value = path to connection file
        for dirpath, dirnames, filenames in os.walk(brotex_dir):
            for file_name in filenames:
                m = _pattern_brotex_connection.match(file_name)
                if m:
                    # keep track of the largest trans_depth
                    trans_depth = m.group(1)
                    connection_files[trans_depth] = os.path.join(dirpath, file_name)

        # create a new tar file for each individual message (to be parsed by EmailAnalyzer)
        for message_number in connection_files.keys():
            missing_stream_file = '{}.{}.missing_stream'.format(_file.value, message_number)
            missing_stream_path = os.path.join(self.root.storage_dir, missing_stream_file)
            logging.debug("creating missing stream archive {}".format(missing_stream_path))
            if os.path.exists(missing_stream_path):
                logging.warning("missing stream file {} already exists".format(missing_stream_path))
                continue

            relative_dir = os.path.dirname(connection_files[message_number])
            logging.debug("relative_dir = {}".format(relative_dir))

            # we tar up the connection info file and any files under the message_N subdirectory
            p = Popen(['tar', '-C', relative_dir, '-c', '-f', missing_stream_path, 
                        os.path.basename(connection_files[message_number]), 
                       'message_{}/'.format(message_number)], stdout=PIPE, stderr=PIPE)
            _stdout, _stderr = p.communicate()
            p.wait()

            if p.returncode != 0:
                logging.error("tar returned error code {} when creating {}".format(p.returncode, missing_stream_path))
                continue

            if _stderr:
                logging.warning("tar printing output to stderr when creating {}: {}".format(missing_stream_path, _stderr))

            # this by itself gets added as a file observable that will later get parsed by EmailAnalyzer
            observable = analysis.add_observable(F_FILE, missing_stream_file)
            if observable: observable.limited_analysis = [ EmailAnalyzer.__name__ ]
            analysis.message_count += 1 

        return True

class SMTPStreamAnalysis(Analysis):
    """What are the emails contained in this SMTP stream?"""
    def initialize_details(self):
        self.details = {
            KEY_SMTP_FILES: [],
            KEY_ENVELOPES: {}, # key = smtp_file, value = {} (keys = env_mail_from, [env_rcpt_to])
        }

    @property
    def smtp_files(self):
        if not self.details:
            return None

        if KEY_SMTP_FILES not in self.details:
            return None

        return self.details[KEY_SMTP_FILES]

    @property
    def envelopes(self):
        if not self.details:
            return None

        if KEY_ENVELOPES not in self.details:
            return None

        return self.details[KEY_ENVELOPES]

    def generate_summary(self):
        if not self.smtp_files:
            return None

        return "SMTP Stream Analysis ({} emails)".format(len(self.smtp_files))

class SMTPStreamAnalyzer(AnalysisModule):
    """Parses SMTP protocol traffic for RFC 822 messages."""
    def verify_environment(self):
        self.verify_config_exists('protocol_scan_line_count')

    @property
    def generated_analysis_type(self):
        return SMTPStreamAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # is this not a brotex file?
        if _pattern_brotex_package.match(os.path.basename(_file.value)):
            return False

        # is this a smtp protocol session?
        _path = os.path.join(self.root.storage_dir, _file.value)
        line_number = 1
        has_mail_from = False
        has_rcpt_to = False
        has_data = False

        if not os.path.exists(_path):
            logging.warning("file {} does not exist".format(_path))
            return False

        # read the first N lines looking for required SMTP protocol data
        with open(_path, 'rb') as fp:
            while line_number < self.config.getint('protocol_scan_line_count'):
                line = fp.readline()
                has_mail_from |= line.startswith(b'MAIL FROM:')
                has_rcpt_to |= line.startswith(b'RCPT TO:')
                has_data |= line.strip() == b'DATA'
                line_number += 1

                if has_mail_from and has_rcpt_to and has_data:
                    break

        if not (has_mail_from and has_rcpt_to and has_data):
            logging.debug("{} does not appear to be an smtp stream".format(_file))
            return False

        analysis = self.create_analysis(_file)

        # if this is an SMTP stream then we want to archive it
        _file.add_directive(DIRECTIVE_ARCHIVE)

        logging.debug("parsing smtp stream file {}".format(_file))

        # parse the SMTP stream(s)
        env_mail_from = None
        env_rcpt_to = []
        rfc822_index = 0
        current_fp = None
        current_rfc822_path = None

        def _complete_stream():
            nonlocal current_fp, current_rfc822_path, rfc822_index, env_mail_from, env_rcpt_to # TIL? :-D
            current_fp.close()
            current_fp = None
            logging.debug("finished writing {}".format(current_rfc822_path))

            rel_path = os.path.relpath(current_rfc822_path, start=self.root.storage_dir)
            analysis.smtp_files.append(rel_path)
            analysis.add_observable(F_FILE, rel_path)
            analysis.envelopes[rel_path] = {}
            analysis.envelopes[rel_path][KEY_ENVELOPES_MAIL_FROM] = env_mail_from
            analysis.envelopes[rel_path][KEY_ENVELOPES_RCPT_TO] = env_rcpt_to

            current_rfc822_path = None
            env_mail_from = None
            env_rcpt_to = []
            rfc822_index += 1

        with open(_path, 'rb') as fp:
            while True:
                line = fp.readline()
                if line == b'':
                    if current_fp:
                        logging.info("incomplete smtp stream file {}".format(_file))
                        _complete_stream()

                    break

                # are we saving a mail to disk?
                if current_fp:
                    if line.strip() == b'.':
                        _complete_stream()
                        continue
                        
                    # see https://www.ietf.org/rfc/rfc2821.txt section 4.5.2
                    if line.startswith(b'.') and line.strip() != b'.':
                        line = line[1:]

                    current_fp.write(line)
                    continue

                if not env_mail_from:
                    if line.startswith(b'MAIL FROM:'):
                        _, env_mail_from = line.decode().strip().split(':', 1)
                        logging.debug("got env_mail_from {} from {}".format(env_mail_from, _file))
                        continue

                if not env_rcpt_to:
                    if line.startswith(b'RCPT TO:'):
                        _, _env_rcpt_to = line.decode().strip().split(':', 1)
                        logging.debug("got env_rcpt_to {} from {}".format(_env_rcpt_to, _file))
                        env_rcpt_to.append(_env_rcpt_to)
                        continue

                if not current_fp:
                    if line.strip() != b'DATA':
                        continue

                # at this point we're at the DATA command
                if not env_mail_from:
                    logging.warning("missing MAIL FROM in {} for message {}".format(_file, rfc822_index))

                if not env_rcpt_to:
                    logging.warning("missing RCPT TO in {} for message {}".format(_file, rfc822_index))

                current_rfc822_path = os.path.join(self.root.storage_dir, '{}.rfc822_{:03}'.format(
                                                   os.path.basename(_file.value), rfc822_index))
                current_fp = open(current_rfc822_path, 'wb')
                logging.debug("saving smtp stream {} from {}".format(current_rfc822_path, _file))

                # is the next line the expected 354 message?
                line = fp.readline()
                if line.startswith(b'354'):
                    # this is skipped
                    continue

                current_fp.write(line)
                continue

        return True

class EmailAnalysis(Analysis):
    """What are all the contents of this email?"""
    def initialize_details(self):
        self.details = {
            KEY_PARSING_ERROR: None,
            KEY_EMAIL: None
        }
        
    @property
    def parsing_error(self):
        return self.details[KEY_PARSING_ERROR]

    @parsing_error.setter
    def parsing_error(self, value):
        self.details[KEY_PARSING_ERROR] = value

    @property
    def email(self):
        if not self.details:
            return {}

        if KEY_EMAIL not in self.details:
            return {}

        return self.details[KEY_EMAIL]

    @email.setter
    def email(self, value):
        self.details[KEY_EMAIL] = value

    @property
    def env_mail_from(self):
        if self.email and KEY_ENV_MAIL_FROM in self.email:
            return self.email[KEY_ENV_MAIL_FROM]

        return None

    @env_mail_from.setter
    def env_mail_from(self, value):
        self.email[KEY_ENV_MAIL_FROM] = value

    @property
    def env_rcpt_to(self):
        if self.email and KEY_ENV_RCPT_TO in self.email:
            return self.email[KEY_ENV_RCPT_TO]

        return None

    @env_rcpt_to.setter
    def env_rcpt_to(self, value):
        self.email[KEY_ENV_RCPT_TO] = value

    @property
    def mail_from(self):
        if self.email and KEY_FROM in self.email:
            return self.email[KEY_FROM]

        return None

    @property
    def mail_to(self):
        if self.email and KEY_TO in self.email:
            return self.email[KEY_TO]

        return None

    @property
    def reply_to(self):
        if self.email and KEY_REPLY_TO in self.email:
            return self.email[KEY_REPLY_TO]

        return None

    @property
    def subject(self):
        if self.email and KEY_SUBJECT in self.email:
            return self.email[KEY_SUBJECT]

        return None

    @property
    def decoded_subject(self):
        if self.email and KEY_DECODED_SUBJECT in self.email:
            return self.email[KEY_DECODED_SUBJECT]

        return None

    @property
    def message_id(self):
        if self.email and KEY_MESSAGE_ID in self.email:
            if self.email[KEY_MESSAGE_ID]:
                return self.email[KEY_MESSAGE_ID].strip()
            else:
                return self.email[KEY_MESSAGE_ID] 

        return None

    @property
    def originating_ip(self):
        if self.email and KEY_ORIGINATING_IP in self.email:
            return self.email[KEY_ORIGINATING_IP]

        return None

    @property
    def received(self):
        """Returns the list of Received: headers of the email, or None if the headers are not available."""
        if not self.headers:
            return None

        result = []

        for key, value in self.headers:
            if key == 'Received':
                result.append(value)

        return result

    @property
    def headers(self):
        if self.email and KEY_HEADERS in self.email:
            return self.email[KEY_HEADERS]

        return None

    @property
    def log_entry(self):
        if not self.email:
            return None

        if KEY_LOG_ENTRY in self.email:
            return self.email[KEY_LOG_ENTRY]

        return None

    @property
    def x_mailer(self):
        """Returns the x-mailer field if available, None otherwise."""
        if not self.headers:
            return None

        for key, value in self.headers:
            if key.lower() == 'x-mailer':
                return value

        return None
    
    @property
    def body(self):
        """Returns the file observable that should be considered the body of the email, or None if one cannot be found."""

        if hasattr(self, '_body'):
            return self._body

        # keep track of the first plain text and html files we find
        first_html = None
        first_plain_text = None

        for _file in self.observables:
            if _file.type != F_FILE:
                continue

            if 'rfc822.unknown_' not in os.path.basename(_file.value):
                continue

            # we always skip this one
            if '.rfc822.unknown_text_plain_000' in _file.value:
                continue

            if first_html is None and 'unknown_text_html' in os.path.basename(_file.value):
                first_html = _file
                continue

            if first_plain_text is None and 'unknown_text_plain' in os.path.basename(_file.value):
                first_plain_text = _file
                continue

        # if we found html then we return that as the body
        if first_html:
            self._body = first_html
        else:
            # otherwise we return the plain text
            self._body = first_plain_text # if there isn't one then it returns None anyways

        return self._body

    @property
    def attachments(self):
        """Returns the list of F_FILE observables that were attachments to the email (not considered the body.)"""
        result = []

        for _file in self.observables:
            if _file.type != F_FILE:
                continue

            # skip any file with an auto-generated name (these are typically part of the body)
            if os.path.basename(_file.value).startswith('email.rfc822.'):
                continue

            result.append(_file)

        return result

    @property
    def targets(self):
        if self.received:
            yield ProfilePointTarget(TARGET_EMAIL_RECEIVED, '\n'.join(self.received))
        if self.x_mailer:
            yield ProfilePointTarget(TARGET_EMAIL_XMAILER, self.x_mailer)
        if self.message_id:
            yield ProfilePointTarget(TARGET_EMAIL_MESSAGE_ID, self.message_id)
        if self.env_rcpt_to:
            for rcpt_to in self.env_rcpt_to:
                yield ProfilePointTarget(TARGET_EMAIL_RCPT_TO, rcpt_to)

        body = self.body
        if body:
            with open(os.path.join(self.storage_dir, body.value), 'rb') as fp:
                body_content = fp.read()

            yield ProfilePointTarget(TARGET_EMAIL_BODY, body_content)

    @property
    def jinja_template_path(self):
        return "analysis/email_analysis.html"
        
    def generate_summary(self):
        if self.parsing_error:
            return self.parsing_error

        if self.observable.has_tag('whitelisted'):
            return "Email Analysis - (whitelisted email)"

        if self.email:
            result = "Email Analysis -"
            if KEY_FROM in self.email:
                result = "{} From {}".format(result, self.email[KEY_FROM])
            if KEY_ENV_RCPT_TO in self.email and self.email[KEY_ENV_RCPT_TO]:
                result = "{} To {}".format(result, self.email[KEY_ENV_RCPT_TO][0])
            elif KEY_TO in self.email and self.email[KEY_TO]:
                result = "{} To {}".format(result, self.email[KEY_TO][0])
            if KEY_DECODED_SUBJECT in self.email:
                result = "{} Subject {}".format(result, self.email[KEY_DECODED_SUBJECT])
            elif KEY_SUBJECT in self.email:
                result = "{} Subject {}".format(result, self.email[KEY_SUBJECT])

            return result

        return None

# example
#Received: from BN6PR1601CA0006.namprd16.prod.outlook.com (10.172.104.144) by
 #BN6PR1601MB1156.namprd16.prod.outlook.com (10.172.107.18) with Microsoft SMTP
 #Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384) id
 #15.1.707.6; Thu, 10 Nov 2016 15:47:33 +0000

_PATTERN_RECEIVED_IPADDR = re.compile(r'from\s\S+\s\(([^)]+)\)\s', re.M)
class EmailAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('whitelist_path')
        self.verify_path_exists(self.config['whitelist_path'])
        self.verify_config_exists('scan_inbound_only')

    def load_config(self):
        self.whitelist = BrotexWhitelist(os.path.join(saq.SAQ_HOME, self.config['whitelist_path']))
        self.auto_reload()

    def auto_reload(self):
        # make sure the whitelist if up-to-date
        self.whitelist.check_whitelist()
        
    @property
    def generated_analysis_type(self):
        return EmailAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def analyze_rfc822(self, _file):

        # if this is a headers file then we skip it
        # this will look like a legit email file
        # XXX take this out an add an exclusion when we add it
        if _file.value.endswith('.headers'):
            return False

        # parse the email
        unparsed_email = None
        parsed_email = None

        # sometimes the actual email we want will be an attachment
        # this will point to a MIME part
        target_email = None

        try:
            logging.debug("parsing email file {}".format(_file))
            with open(os.path.join(self.root.storage_dir, _file.value), 'r', errors='ignore') as fp:
                unparsed_email = fp.read()
            
            # by default we target the parsed email (see NOTE A)
            target_email = parsed_email = email.parser.Parser().parsestr(unparsed_email)

        except Exception as e:
            logging.error("unable to parse email {}: {}".format(_file, e))
            #report_exception()

            try:
                src_path = os.path.join(self.root.storage_dir, _file.value)
                dst_path = os.path.join(saq.DATA_DIR, 'review', 'rfc822', str(uuid.uuid4()))
                shutil.copy(src_path, dst_path)

                with open('{}.unparsed'.format(dst_path), 'w') as fp:
                    fp.write(unparsed_email)

            except Exception as e:
                logging.error("unable to save file for review: {}".format(e))

            return False

        email_details = {}
        target_message_id = None # the message-id we've identified as the main one
        is_office365 = False # is this an office365 journaled message?

        # NOTE A
        # find the email we actually want to target
        # by default we target the entire email itself
        for part in parsed_email.walk():
            # look for office365 header indicating a parent message-id
            if 'X-MS-Exchange-Parent-Message-Id' in part:
                is_office365 = True # we use this to identify this is an office365 journaled message
                target_message_id = part['X-MS-Exchange-Parent-Message-Id'].strip()
                logging.debug("found office365 parent message-id {}".format(target_message_id))
                continue

            if 'message-id' in part:
                # if we are looking for a specific message-id...
                if target_message_id:
                    if part['message-id'].strip() == target_message_id:
                        # found the part we're looking for
                        target_email = part
                        logging.debug("found target email using message-id{}".format(target_message_id))
                        break

        # at this point target_email either points at the original parse email
        # or it points to a MIME part (an attachment inside the email)

        # START WHITELISTING

        # for office365 we check to see if this email is inbound
        # this only applies to the original email, not email attachments
        if _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
            if 'X-MS-Exchange-Organization-MessageDirectionality' in target_email:
                if target_email['X-MS-Exchange-Organization-MessageDirectionality'] != 'Incoming':
                    _file.add_tag(TAG_OUTBOUND_EMAIL)
                    # are we scanning inbound only?
                    if self.config.getboolean('scan_inbound_only'):
                        logging.debug("skipping outbound office365 email {}".format(_file))
                        _file.mark_as_whitelisted()
                        return False

        # check to see if the sender or receiver has been whitelisted
        # this is useful to filter out internally sourced garbage
        if 'from' in target_email:
            name, address = email.utils.parseaddr(target_email['from'])
            if address != '':
                if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, address):
                    _file.mark_as_whitelisted()
                    return False

        header_tos = [] # list of header-to addresses
        env_rcpt_to = [] # list of env-to addresses (should be a list of one)

        # if this is an office365 email then we know who the email was actually delivered to
        if 'X-MS-Exchange-Organization-OriginalEnvelopeRecipients' in target_email:
            name, address = email.utils.parseaddr(target_email['X-MS-Exchange-Organization-OriginalEnvelopeRecipients'])
            if address:
                env_rcpt_to = [ address ]

        # we also have what To: addrsses are in the headers
        for mail_to in target_email.get_all('to', []):
            name, address = email.utils.parseaddr(mail_to)
            if address:
                header_tos.append(address)

        for address in header_tos + env_rcpt_to:
            if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address):
                _file.mark_as_whitelisted()
                return False

        # END WHITELISTING

        analysis = self.create_analysis(_file)

        # if it's not whitelisted we'll want to archive it
        #_file.add_directive(DIRECTIVE_ARCHIVE)

        # parse out important email header information and add observables

        # capture all email headers
        email_details[KEY_HEADERS] = []
        for header, value in target_email.items():
            email_details[KEY_HEADERS].append([header, value])

        # who did the email come from?
        # with office365 journaling all you have is the header from
        mail_from = None

        if 'from' in target_email:
            email_details[KEY_FROM] = target_email['from']
            name, address = email.utils.parseaddr(email_details[KEY_FROM])
            if address != '':
                mail_from = address
                from_address = analysis.add_observable(F_EMAIL_ADDRESS, address)
                if from_address:
                    from_address.add_tag('mail_from')

        if 'reply-to' in target_email:
            email_details[KEY_REPLY_TO] = target_email['reply-to']
            name, address = email.utils.parseaddr(target_email['reply-to'])
            if address != '':
                reply_to = analysis.add_observable(F_EMAIL_ADDRESS, address)
                if reply_to:
                    reply_to.add_tag('reply_to')
                    if mail_from:
                        analysis.add_observable(F_EMAIL_CONVERSATION, create_email_conversation(mail_from, address))

        # do we know who this was actually delivered to?
        if 'X-MS-Exchange-Organization-OriginalEnvelopeRecipients' in target_email:
            email_details[KEY_ENV_RCPT_TO] = [target_email['X-MS-Exchange-Organization-OriginalEnvelopeRecipients']]
            name, address = email.utils.parseaddr(email_details[KEY_ENV_RCPT_TO][0])
            if address:
                mail_to = analysis.add_observable(F_EMAIL_ADDRESS, address)
                if mail_to:
                    mail_to.add_tag('delivered_to')
                    if mail_from:
                        analysis.add_observable(F_EMAIL_CONVERSATION, create_email_conversation(mail_from, address))

        email_details[KEY_TO] = target_email.get_all('to', [])
        for mail_to in email_details[KEY_TO]:
            name, address = email.utils.parseaddr(mail_to)
            if address:
                mail_to = analysis.add_observable(F_EMAIL_ADDRESS, address)
                if mail_to:
                    mail_to.add_tag('mail_to')
                    if mail_from:
                        analysis.add_observable(F_EMAIL_CONVERSATION, create_email_conversation(mail_from, address))

        
        if 'subject' in target_email:
            email_details[KEY_SUBJECT] = target_email['subject']

        if 'message-id' in target_email:
            email_details[KEY_MESSAGE_ID] = target_email['message-id']
            message_id_observable = analysis.add_observable(F_MESSAGE_ID, target_email['message-id'].strip())
            if message_id_observable: 
                # this module will extract an email from the archives based on the message-id
                # we don't want to do that here so we exclude that analysis
                message_id_observable.exclude_analysis(MessageIDAnalyzer)

        # the rest of these details are for the generate logging output

        # extract CC and BCC recipients
        cc = []
        if 'cc' in target_email:
            cc = [e.strip() for e in target_email['cc'].split(',')]

        bcc = []
        if 'bcc' in target_email:
            bcc = [e.strip() for e in target_email['bcc'].split(',')]

        path = []
        for header in target_email.get_all('received', []):
            m = _PATTERN_RECEIVED_IPADDR.match(header)
            if not m:
                continue

            path_item = m.group(1)
            path.append(path_item)

        user_agent = None
        if 'user-agent' in target_email:
            user_agent = target_email['user-agent']

        x_mailer = None
        if 'x-mailer' in target_email:
            x_mailer = target_email['x-mailer']

        # sender IP address (office365)
        if 'x-originating-ip' in target_email:
            value = target_email['x-originating-ip']
            value = re.sub(r'[^0-9\.]', '', value) # these seem to have extra characters added
            email_details[KEY_ORIGINATING_IP] = value
            ipv4 = analysis.add_observable(F_IPV4, value)
            if ipv4: 
                ipv4.add_tag('sender_ip')

        # is the subject rfc2822 encoded?
        if KEY_SUBJECT in email_details:
            decoded_subject = []
            for binary_subject, charset in email.header.decode_header(email_details[KEY_SUBJECT]):
                decoded_part = None
                if charset is not None:
                    try:
                        decoded_part = binary_subject.decode(charset, errors='replace')
                    except Exception as e:
                        pass

                if decoded_part is None:
                    if isinstance(binary_subject, str):
                        decoded_part = binary_subject
                    else:
                        decoded_part = binary_subject.decode('utf8', errors='replace')

                decoded_subject.append(decoded_part)

            email_details[KEY_DECODED_SUBJECT] = ''.join(decoded_subject)

        # get the first and last received header values
        last_received = None
        first_received = None
        path = None
        for header, value in email_details[KEY_HEADERS]:
            if header.lower().startswith('received'):
                if not last_received:
                    last_received = value
                first_received = value

        # START ATTACHMENT PARSING

        unknown_index = 0

        # we use this later when we write the log message
        attachments = [] # of ( size, type, name, sha256 )

        def __recursive_parser(target):
            nonlocal target_message_id

            # if this attachment is an email and it's not the target email
            # OR this attachment is not a multipart attachment (is a single file)
            # THEN we want to extract it as a another file for analysis

            # is this another email or a single file attachment?
            if target.get_content_type() == 'message/rfc822' or not target.is_multipart():

                file_name = None

                # do not extract the target email
                if target.get_content_type() == 'message/rfc822':
                    # the actual message-id will be in one of the payloads of the email
                    for payload in target.get_payload():
                        if 'message-id' in payload and payload['message-id'].strip() == target_message_id:
                            return

                    # if we are going to extract it then we name it here
                    file_name = '{}.email.rfc822'.format(_file.value)

                # extract it
                if not file_name:
                    file_name = target.get_filename()

                if file_name:
                    decoded_header = email.header.decode_header(file_name)
                    if decoded_header:
                        decoded_header, charset = decoded_header[0]
                        if charset:
                            try:
                                file_name = decoded_header.decode(charset, errors='replace')
                            except LookupError as e:
                                logging.warning(str(e))

                    file_name = re.sub(r'[\r\n]', '', file_name)

                else:
                    file_name = '{}.unknown_{}_{}_000'.format(_file.value, target.get_content_maintype(), 
                                                                           target.get_content_subtype())

                # sanitize the file name
                sanitized_file_name = re.sub(r'_+', '_', re.sub(r'\.\.', '_', re.sub(r'/', '_', file_name)))
                if file_name != sanitized_file_name:
                    logging.debug("changed file name from {} to {}".format(file_name, sanitized_file_name))
                    file_name = sanitized_file_name

                if not file_name:
                    file_name = '{}.unknown_{}_{}_000'.format(_file.value, target.get_content_maintype(), 
                                                                           target.get_content_subtype())

                # make sure the file name isn't too long
                if len(file_name) > 120:
                    logging.debug("file name {} is too long".format(file_name))
                    _file_name, _file_ext = os.path.splitext(file_name)
                    # this can be wrong too
                    if len(_file_ext) > 40:
                        _file_ext = '.unknown'
                    file_name = '{}{}'.format(file_name[:120], _file_ext)

                # make sure it's unique
                file_path = os.path.join(self.root.storage_dir, file_name)
                while True:
                    if not os.path.exists(file_path):
                        break

                    _file_name, _file_ext = os.path.splitext(os.path.basename(file_path))
                    m = re.match('(.+)_([0-9]{3})$', _file_name)
                    if m:
                        _file_name = m.group(1)
                        index = int(m.group(2)) + 1
                    else:
                        index = 0

                    _file_name = '{}_{:03}'.format(_file_name, index)
                    file_path = '{}{}'.format(_file_name, _file_ext)
                    file_path = os.path.join(self.root.storage_dir, file_path)

                # figure out what the payload should be
                if target.get_content_type() == 'message/rfc822':
                    part = target.get_payload()
                    part = part[0]
                    payload = part.as_bytes()
                elif target.is_multipart():
                    # in the case of email attachments we need the whole things (including headers)
                    payload = target.as_bytes()
                else:
                    # otherwise we just need the decoded contents as bytes
                    payload = target.get_payload(decode=True)

                with open(file_path, 'wb') as fp:
                    fp.write(payload)

                logging.debug("extracted {} from {}".format(file_path, _file.value))

                extracted_file = analysis.add_observable(
                F_FILE, os.path.relpath(file_path, start=self.root.storage_dir))

                if extracted_file: 
                    extracted_file.add_directive(DIRECTIVE_EXTRACT_URLS)

                # XXX I can't remember why we are still doing the attachment thing
                attachments.append((len(payload), target.get_content_type(), 
                                    file_name, hashlib.sha256(payload).hexdigest()))
                 
            # otherwise, if it's a multi-part then we want to recurse into it
            elif target.is_multipart():
                for part in target.get_payload():
                    _recursive_parser(part)

            else:
                raise RuntimeError("parsing logic error: {}".format(_file.value))

        def _recursive_parser(*args, **kwargs):
            try:
                return __recursive_parser(*args, **kwargs)
            except Exception as e:
                logging.warning("recursive parsing failed on {}: {}".format(_file.value, e))
                #report_exception()
                target_path = os.path.join(saq.DATA_DIR, 'review', 'rfc822', '{}.{}'.format(
                                           _file.value, datetime.datetime.now().strftime('%Y%m%d%H%M%S')))
                shutil.copy(os.path.join(self.root.storage_dir, _file.value), target_path)

        _recursive_parser(target_email)

        # END ATTACHMENT PARSING

        # generate data suitable for logging
        log_entry = {
            'date': saq.LOCAL_TIMEZONE.localize(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S.%f %z'),
            'first_received': first_received,
            'last_received': last_received,
            'env_mail_from': email_details[KEY_ENV_MAIL_FROM] if KEY_ENV_MAIL_FROM in email_details else None,
            'env_rcpt_to': email_details[KEY_ENV_RCPT_TO] if KEY_ENV_RCPT_TO in email_details else [],
            'mail_from': email_details[KEY_FROM] if KEY_FROM in email_details else None,
            'mail_to': email_details[KEY_TO] if KEY_TO in email_details else [],
            'reply_to': email_details[KEY_REPLY_TO] if KEY_REPLY_TO in email_details else None,
            'cc': cc,
            'bcc': bcc,
            'message_id': email_details[KEY_MESSAGE_ID] if KEY_MESSAGE_ID in email_details else None,
            'subject': email_details[KEY_SUBJECT] if KEY_SUBJECT in email_details else None,
            'path': path,
            'size': _file.size,
            'user_agent': user_agent,
            'x_mailer': x_mailer,
            'originating_ip': email_details[KEY_ORIGINATING_IP] if KEY_ORIGINATING_IP in email_details else None,
            'headers': ['{}: {}'.format(h[0], re.sub('[\t\n]', '', h[1])) for h in email_details[KEY_HEADERS] if not h[0].lower().startswith('x-ms-exchange-')] if KEY_HEADERS in email_details else None,
            'attachment_count': len(attachments),
            'attachment_sizes': [a[0] for a in attachments],
            'attachment_types': [a[1] for a in attachments],
            'attachment_names': [a[2] for a in attachments],
            'attachment_hashes': [a[3] for a in attachments],
            'thread_topic': target_email['thread-topic'] if 'thread-topic' in target_email else None,
            'thread_index': target_email['thread-index'] if 'thread-index' in target_email else None,
            'refereneces': target_email['references'] if 'references' in target_email else None,
            'x_sender': target_email['x-sender'] if 'x-sender' in target_email else None,
        }

        email_details[KEY_LOG_ENTRY] = log_entry
        analysis.email = email_details

        # create a file with just the header information and scan that separately
        if KEY_HEADERS in email_details:
            headers_path = os.path.join(self.root.storage_dir, '{}.headers'.format(_file.value))
            if os.path.exists(headers_path):
                logging.warning("headers file {} already exists".format(headers_path))
            else:
                with open(headers_path, 'w') as fp:
                    fp.write('\n'.join(['{}: {}'.format(h[0], h[1]) for h in email_details[KEY_HEADERS]]))

                headers_file = analysis.add_observable(F_FILE, os.path.relpath(
                                                       headers_path, start=self.root.storage_dir))

                # we don't want to analyze this with the email analyzer
                if headers_file: 
                    headers_file.exclude_analysis(self)

        logging.info("scanning email [{}] {} from {} to {} subject {}".format(
                     self.root.uuid,
                     log_entry['message_id'], log_entry['mail_from'], log_entry['env_rcpt_to'],
                     log_entry['subject']))

        return True

    def analyze_missing_stream(self, _file):
        """Analyzes the output of bro failing to capture the stream data but still extracted protocol meta and files."""

        file_path = os.path.join(self.root.storage_dir, _file.value)
        extracted_dir = '{}.extracted'.format(file_path)
        if not os.path.isdir(extracted_dir):
            try:
                os.mkdir(extracted_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(extracted_dir, e))
                return False

        analysis = self.create_analysis(_file)

        # extract all the things into the brotex_dir
        p = Popen(['tar', 'xf', file_path, '-C', extracted_dir], 
                  stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()
        p.wait()

        if p.returncode:
                logging.warning("unable to extract files from {} (tar returned error code {}".format(
                                _file, p.returncode))
                return False

        if stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, stderr))

        # iterate over all the extracted files
        # map message numbers to the connection file
        connection_files = {} # key = message_number, value = path to connection file
        for dirpath, dirnames, filenames in os.walk(extracted_dir):
            for file_name in filenames:
                m = _pattern_brotex_connection.match(file_name)
                if m:
                    # keep track of the largest trans_depth
                    trans_depth = m.group(1)
                    connection_files[trans_depth] = os.path.join(dirpath, file_name)

                full_path = os.path.join(dirpath, file_name)
                # go ahead and add every file to be scanned
                _file = analysis.add_observable(F_FILE, os.path.relpath(full_path, start=self.root.storage_dir))
                if _file: _file.add_directive(DIRECTIVE_EXTRACT_URLS)

        def _parse_bro_mv(value):
            """Parse bro multivalue field."""
            # interpreting what I see here...
            if not value.startswith('{^J^I') and value.endswith('^J}'):
                return [ value ]

            return value[len('{^J^I]')-1:-len('^J}')].split(',^J^I')

        # parse each message
        for message_number in connection_files.keys():
            details = { }

            # parse the connection file
            logging.debug("parsing bro connection file {}".format(connection_files[message_number]))
            with open(connection_files[message_number], 'r') as fp:
                # these files are generated by the brotex.bro script in the brotex git repo
                # they are stored in the following order
                uid = fp.readline().split(' = ', 1)[1].strip()
                mailfrom = fp.readline().split(' = ', 1)[1].strip()
                rcptto = fp.readline().split(' = ', 1)[1].strip()
                from_ = fp.readline().split(' = ', 1)[1].strip()
                to_ = fp.readline().split(' = ', 1)[1].strip()
                reply_to = fp.readline().split(' = ', 1)[1].strip()
                in_reply_to = fp.readline().split(' = ', 1)[1].strip()
                msg_id = fp.readline().split(' = ', 1)[1].strip()
                subject= fp.readline().split(' = ', 1)[1].strip()
                x_originating_ip = fp.readline().split(' = ', 1)[1].strip()

            # some of these fields are multi value fields
            rcptto = _parse_bro_mv(rcptto)
            to_ = _parse_bro_mv(to_)

            details[KEY_ENV_MAIL_FROM] = mailfrom
            details[KEY_ENV_RCPT_TO] = rcptto
            details[KEY_FROM] = from_
            details[KEY_TO] = to_
            details[KEY_SUBJECT] = subject
            details[KEY_REPLY_TO] = reply_to
            #details[KEY_IN_REPLY_TO] = in_reply_to
            details[KEY_MESSAGE_ID] = msg_id
            details[KEY_ORIGINATING_IP] = x_originating_ip

            analysis.email = details

            # add the appropriate observables
            mailfrom_n = None
            if mailfrom:
                mailfrom_n = normalize_email_address(mailfrom)
                if mailfrom_n:
                    analysis.add_observable(F_EMAIL_ADDRESS, mailfrom_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, mailfrom_n):
                        _file.mark_as_whitelisted()
            
            for address in rcptto:
                if address:
                    address_n = normalize_email_address(address)
                    if address_n:
                        analysis.add_observable(F_EMAIL_ADDRESS, address_n)
                        if mailfrom_n:
                            analysis.add_observable(F_EMAIL_CONVERSATION, create_email_conversation(mailfrom,
                                                    address_n))
                            if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address_n):
                                _file.mark_as_whitelisted()

            from_n = None
            if from_:
                from_n = normalize_email_address(from_)
                if from_n:
                    analysis.add_observable(F_EMAIL_ADDRESS, from_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, from_n):
                        _file.mark_as_whitelisted()

            for address in to_:
                address_n = normalize_email_address(address_n)
                if address_n:
                    analysis.add_observable(F_EMAIL_ADDRESS, address_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address_n):
                        _file.mark_as_whitelisted()

                if from_:
                    analysis.add_observable(F_EMAIL_CONVERSATION, create_email_conversation(
                                            normalize_email_address(from_),
                                            normalize_email_address(address)))

            if x_originating_ip:
                analysis.add_observable(F_IPV4, x_originating_ip)

        return True


    def execute_analysis(self, _file):

        from saq.modules.file_analysis import FileTypeAnalysis

        # is this a "missing stream archive" that gets generated by the BrotexSMTPPackageAnalyzer module?
        if _pattern_brotex_missing_stream_package.match(os.path.basename(_file.value)):
            return self.analyze_missing_stream(_file)

        # is this an RFC 822 email?
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis or not file_type_analysis.file_type:
            logging.debug("missing file type analysis for {}:".format(_file))
            return False

        is_email = 'RFC 822 mail' in file_type_analysis.file_type
        is_email |= 'message/rfc822' in file_type_analysis.file_type
        is_email |= 'message/rfc822' in file_type_analysis.mime_type
        is_email |= _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL)

        #if not is_email:
            #header_count = 0
            #try:
                #with open(os.path.join(self.root.storage_dir, _file.value), 'r') as fp:
                    #while True:
                        #line = fp.readline(1024)
                        #m = RE_EMAIL_HEADER.match(line)
                        #if m:
                            #header_count += 1
                            ##logging.info("MARKER: header")
                            #continue

                        ## have we reached the end of the headers?
                        #if line.strip() == '':
                            ##logging.info("MARKER: headers end")
                            #break

                        #m = RE_EMAIL_HEADER_CONTINUE.match(line)
                        #if m:
                            ##logging.info("MARKER: header continuation")
                            #continue

                        ## we read some non-email header content
                        ##logging.info("MARKER: non header: [{}]".format(line.strip()))
                        #header_count = 0
                        #break

                #if header_count > 5: # completely arbitrary value
                    #logging.debug("detected email file {} by inspecting contents".format(_file.value))
                    #is_email = True

            #except Exception as e:
                #logging.debug("unable to determine if {} is an email: {}".format(_file.value, e))

        if not is_email:
            logging.debug("unsupported file type for email analysis: {} {}".format(
                          file_type_analysis.file_type,
                          file_type_analysis.mime_type))
            return False

        return self.analyze_rfc822(_file)

class EmailArchiveResults(Analysis):
    def initialize_details(self):
        self.details = None

    @property
    def archive_path(self):
        return self.details

    def generate_summary(self):
        if not self.details:
            return None

        return "Archive Path - {}".format(self.details)

class EmailArchiveAction(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
        # the server_id value of the archive_server table
        # this will get set once
        self.hostname = socket.gethostname().lower()
        self.server_id = None

    def verify_environment(self):
        if saq.ENCRYPTION_PASSWORD is None:
            raise RuntimeError("email archiving is enabled but you have not set the encryption password")

        self.verify_config_exists('archive_dir')
        self.create_required_directory(self.config['archive_dir'])

    @property
    def valid_observable_types(self):
        return [ F_FILE ]

    @property
    def required_directives(self):
        return [ DIRECTIVE_ARCHIVE, DIRECTIVE_ORIGINAL_EMAIL ]

    @property
    def generated_analysis_type(self):
        return EmailArchiveResults

    def execute_analysis(self, _file):
        # has this been whitelisted?
        if _file.whitelisted:
            logging.debug("{} has been whitelisted - not archiving".format(_file.value))
            return False

        # if this file has been decrypted from the archives then we obviously don't need to process any further
        if _file.has_tag('decrypted_email'):
            # this should not happen now
            logging.warning("detected decrypted email {} as original email".format(_file))
            return False

        # we'll wait until the end of analysis
        return True

    def execute_final_analysis(self, _file):
        from saq.modules.file_analysis import FileHashAnalysis
        email_analysis = _file.get_analysis(EmailAnalysis)
        if not email_analysis:
            logging.warning("cannot find EmailAnalysis for {}".format(_file))
            return False

        _file.compute_hashes()
        email_md5 = _file.md5_hash

        if not email_md5:
            logging.error("email file {} missing md5?".format(_file))
            return False

        analysis = self.create_analysis(_file)

        email_md5 = email_md5.lower()

        # archive the email...
        archive_dir = os.path.join(saq.DATA_DIR, self.config['archive_dir'], self.hostname, email_md5[0:3])
        if not os.path.isdir(archive_dir):
            logging.debug("creating archive directory {}".format(archive_dir))

            try:
                os.makedirs(archive_dir)
            except:
                # it might have already been created by another process
                # mkdir is an atomic operation (FYI)
                if not os.path.isdir(archive_dir):
                    raise Exception("unable to create archive directory {}: {}".format(archive_dir, e))

        source_path = os.path.join(self.root.storage_dir, _file.value)
        archive_path = '{}.gz'.format(os.path.join(archive_dir, email_md5))
        if os.path.exists('{}.e'.format(archive_path)):
            logging.warning("archive path {} already exists".format('{}.e'.format(archive_path)))
            analysis.details = archive_path
            return True
            
        # compress the data
        logging.debug("compressing {}".format(archive_path))
        try:
            with open(source_path, 'rb') as fp_in:
                with gzip.open(archive_path, 'wb') as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

        except Exception as e:
            logging.error("compression failed for {}: {}".format(archive_path, e))
            return False

        # encrypt the archive file
        encrypted_file = '{}.e'.format(archive_path)

        try:
            encrypt(archive_path, encrypted_file)
        except Exception as e:
            logging.error("unable to encrypt archived email {}: {}".format(archive_path, e))

        logging.info("archived email {} to {}".format(archive_path, encrypted_file))

        # delete the unencrypted copy
        if os.path.exists(encrypted_file):
            try:
                os.remove(archive_path)
            except Exception as e:
                logging.error("unable to delete unencrypted archive file {}: {}".format(archive_path, e))
        else:
            logging.error("expected encrypted output file {} does not exist".format(encrypted_file))
            return False

        with get_db_connection('email_archive') as db:
            c = db.cursor()

            # do we have our server_id yet?
            if not self.server_id:
                c.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (self.hostname,))
                try:
                    row = c.fetchone() 
                    self.server_id = row[0]
                    logging.debug("got server_id {} for {}".format(self.server_id, self.hostname))
                except:
                    # create the server_id if it does not exist yet
                    execute_with_retry(db, c, "INSERT IGNORE INTO archive_server ( hostname ) VALUES ( %s )", 
                                      (self.hostname,))
                    db.commit()

                    c.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (self.hostname,))
                    row = c.fetchone() 
                    self.server_id = row[0]
                    logging.debug("created server_id {} for {}".format(self.server_id, self.hostname))

            execute_with_retry(db, c, "INSERT INTO archive ( server_id, md5 ) VALUES ( %s, UNHEX(%s) )", 
                              (self.server_id, email_md5))
            archive_id = c.lastrowid

            if not archive_id:
                logging.error("c.lastrowid returned None for {}".format(_file))
                return

            logging.debug("got archive_id {} for email {}".format(archive_id, _file))

            transactions = []

            #env_from = normalize_email_address(email_analysis.env_mail_from)
            #if env_from:
                #transactions.append(('env_from', env_from))

            if email_analysis.env_rcpt_to:
                env_to = normalize_email_address(email_analysis.env_rcpt_to[0])
                if env_to:
                    transactions.append(('env_to', env_to))

            body_from = normalize_email_address(email_analysis.mail_from)
            if body_from:
                transactions.append(('body_from', body_from))

            body_to = normalize_email_address(email_analysis.mail_to)
            if body_to:
                transactions.append(('body_to', body_to))

            if email_analysis.subject:
                transactions.append(('subject', email_analysis.subject))

            if email_analysis.decoded_subject:
                transactions.append(('decoded_subject', email_analysis.decoded_subject))

            if email_analysis.message_id:
                transactions.append(('message_id', email_analysis.message_id))

            def _callback(target):
                if isinstance(target, Observable) and target.type == F_URL:
                    transactions.append(('url', target.value))

                if isinstance(target, FileHashAnalysis):
                    transactions.append(('content', target.md5))
                    
            recurse_tree(_file, _callback)

            # update the fast search indexes
            for field, email_property in transactions:
                hasher = hashlib.md5()
                hasher.update(email_property.encode('ascii', errors='ignore'))
                property_md5 = hasher.hexdigest()

                execute_with_retry(db, c, 
                    "INSERT IGNORE INTO archive_index ( field, hash, archive_id ) VALUES ( %s, UNHEX(%s), %s )",
                    (field, property_md5, archive_id))
                execute_with_retry(db, c, 
                    "INSERT IGNORE INTO archive_search ( field, value, archive_id ) VALUES ( %s, %s, %s )", 
                    (field, email_property[:2083], archive_id))

            db.commit()

        analysis.details = archive_path
        return True

    @property
    def maintenance_frequency(self):
        return 60 # execute every 60 seconds

    def execute_maintenance(self):
        from saq.email import maintain_archive
        maintain_archive()

class EmailConversationFrequencyAnalysis(Analysis):
    """How often does this external person email this internal person?"""
    def initialize_details(self):
        self.details = { }

    def generate_summary(self):
        if self.details is None:
            return None

        if 'source_count' not in self.details:
            return None

        result = 'Email Conversation Frequency Analysis -'
        if not self.details['source_count']:
            return '{} first time received'.format(result)

        return '{} {} emails received before, {} to this user'.format(result, 
            self.details['source_count'],
            self.details['dest_count'])

class EmailConversationFrequencyAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('cooldown_period')
        self.verify_config_exists('conversation_count_threshold')

    @property
    def conversation_count_threshold(self):
        # when two people email each other frequently we want to know that
        # this is the minimum number of times we've seen this email address email this other email address
        # that we consider to be "frequent"
        return self.config.getint('conversation_count_threshold')

    @property
    def generated_analysis_type(self):
        return EmailConversationFrequencyAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_CONVERSATION

    def execute_analysis(self, email_conversation):
        # are we on cooldown?
        # XXX this should be done from the engine!
        if self.cooldown_timeout:
            logging.debug("{} on cooldown - not checking".format(self))
            return False

        mail_from, rcpt_to = parse_email_conversation(email_conversation.value)

        # how often do we see this email address sending us emails?
        source_count = 0
        try:
            source_count = query_brocess_by_source_email(mail_from)
        except Exception as e:
            logging.error("unable to query brocess: {}".format(e))
            report_exception()
            self.enter_cooldown()
            return False

        if not source_count:
            email_conversation.add_tag('new_sender')

        analysis = self.create_analysis(email_conversation)
        analysis.details = { 'source_count': source_count }

        # if this is the first time we've ever seen this email address then we don't need to do any
        # more frequency analysis
        if source_count:
            # how often do these guys talk?
            conversation_count = 0
            try:
                conversation_count = query_brocess_by_email_conversation(mail_from, rcpt_to)

                # do these guys talk a lot?
                if conversation_count >= self.conversation_count_threshold:
                    email_conversation.add_tag('frequent_conversation')

                analysis.details['dest_count'] = conversation_count
                return True

            except Exception as e:
                logging.error("unable to query brocess: {}".format(e))
                report_exception()
                self.enter_cooldown()
                return False

        return True

class EmailConversationAttachmentAnalysis(Analysis):
    """Has someone who has never sent us an email before sent us an attachment used in attacks?"""
    def initialize_details(self):
        self.details = None # not used

class EmailConversationAttachmentAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailConversationAttachmentAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        from saq.modules.file_analysis import FileTypeAnalysis

        # the file that we are looking at is word documents and the like
        file_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_analysis is None:
            return False

        # this is really only valid for email scanning
        # look for a file with EmailAnalysis
        if len(self.root.get_analysis_by_type(EmailAnalysis)) == 0:
            return False

        if not file_analysis.is_office_document:
            return False

        # is there a macro anywhere?
        if not _file.search_tree(tags='macro'):
            return False

        # wait for email conversation analysis to complete
        is_new_sender = False
        for ec_observable in self.root.get_observables_by_type(F_EMAIL_CONVERSATION):
            if ec_observable.get_analysis(EmailConversationFrequencyAnalysis) is None:
                continue

            # is this tagged as new_sender?
            if not ec_observable.has_tag('new_sender'):
                continue

            is_new_sender = True
            break

        if not is_new_sender:
            return False

        #_file.add_tag('suspect')
        _file.add_directive(DIRECTIVE_SANDBOX)
        _file.add_detection_point("An email from a new sender contained a macro.")

        analysis = self.create_analysis(_file)
        return True

# DEPRECATED
class EmailHistoryAnalysis_v1(Analysis):
    """How many emails did this user receive?  What is the general summary of them?"""

    def initialize_details(self):
        self.details = {
            KEY_EMAILS: None,
        }

    @property
    def emails(self):
        return self.details[KEY_EMAILS]

    @emails.setter
    def emails(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_EMAILS] = value

    @property
    def jinja_template_path(self):
        return 'analysis/email_history.html'

    def generate_summary(self):
        if self.emails is None:
            return None

        if not isinstance(self.emails, list):
            logging.error("self.emails should be a list but it is a {0}".format(str(type(self.emails))))
            return None

        return "Bro Email History ({0} recevied emails)".format(len(self.emails))

class EmailHistoryAnalyzer_v1(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailHistoryAnalysis_v1

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def execute_analysis(self, email_address):

        self.splunk_query('index=bro sourcetype=bro_smtp {0} | search rcptto = "*{0}*" | sort _time | fields *'.format(email_address.value), 
            self.root.event_time_datetime if email_address.time_datetime is None else email_address.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(email_address)
        analysis.emails = self.json()

class EmailHistoryRecord(object):
    """Utility class to add extra fields not present in the splunk logs."""

    def __init__(self, details):
        self.details = details

    #def __getattr__(self, name):
        #return self.details[name]
    
    def __getitem__(self, key):
        return self.details[key]

    @property
    def md5(self):
        file_name = os.path.basename(self.details['archive_path'])
        md5, ext = os.path.splitext(file_name)
        return md5

class EmailHistoryAnalysis_v2(Analysis):
    """How many emails did this user receive?  What is the general summary of them?"""

    def initialize_details(self):
        self.details = {
            KEY_EMAILS: None,
        }

    @property
    def emails(self):
        if not self.details:
            return []

        if not self.details[KEY_EMAILS]:
            return []
        
        return [EmailHistoryRecord(email) for email in self.details[KEY_EMAILS]]

    @emails.setter
    def emails(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_EMAILS] = value

    @property
    def jinja_template_path(self):
        return 'analysis/email_history_v2.html'

    def generate_summary(self):
        if not self.emails:
            return None

        if not isinstance(self.emails, list):
            logging.error("self.emails should be a list but it is a {}".format(str(type(self.emails))))
            return None

        return "Scanned Email History ({} recevied emails)".format(len(self.emails))

class EmailHistoryAnalyzer_v2(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailHistoryAnalysis_v2

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def execute_analysis(self, email_address):

        alias_groups = [] # list of lists of domains
        for config_item in self.config.keys():
            if config_item.startswith('map_'):
                domains = [x.strip().lower() for x in self.config[config_item].split(',')]
                if domains:
                    logging.debug("adding alias group {} ({})".format(config_item, domains))
                    alias_groups.append(domains)

        initial_search_query = []
        specific_search_query = []

        # does the domain match an alias?
        try:
            user, domain = email_address.value.lower().split('@', 1)
        except ValueError:
            logging.warning("{} does not appear to be a valid email address".format(email_address.value))
            return False

        for alias_group in alias_groups:
            if domain in alias_group:
                logging.debug("email address {} matches alias group {}".format(email_address.value, alias_group))
                for alias_domain in alias_group:
                    initial_search_query.append('"{}@{}"'.format(user, alias_domain))
                    specific_search_query.append('env_rcpt_to = "*{}@{}*"'.format(user, alias_domain))

        # did not match an alias?
        if not initial_search_query:
            initial_search_query = [ email_address.value ]
            specific_search_query = [ "*{}*".format(email_address.value) ]

        self.splunk_query('index=email_* {} | search {} | sort _time | fields *'.format(
            ' OR '.join(initial_search_query),
            ' OR '.join(specific_search_query)),
            self.root.event_time_datetime if email_address.time_datetime is None else email_address.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(email_address)
        analysis.emails = self.json()
        return True

class EmailLoggingAnalysis(Analysis):
    def initialize_details(self):
        pass # not used

class EmailLoggingAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # splunk log settings
        self.splunk_log_enabled = self.config.getboolean('splunk_log_enabled')
        self.splunk_log_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['splunk_logging']['splunk_log_dir'], 
                                           self.config['splunk_log_subdir'])

        # JSON log settings (for elasticsearch)
        self.json_log_enabled = self.config.getboolean('json_log_enabled')
        self.json_log_path_format = self.config['json_log_path_format']

        # brocess log settings
        self.update_brocess = self.config.getboolean('update_brocess')

    def verify_environment(self):
        self.verify_config_exists('splunk_log_subdir')
        self.create_required_directory(self.splunk_log_dir)
        
    @property
    def generated_analysis_type(self):
        return EmailLoggingAnalysis

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, target):
        return False

    def execute_post_analysis(self):

        from saq.modules.file_analysis import URLExtractionAnalysis

        # process each "original email" in the analysis
        for f in self.root.get_observables_by_type(F_FILE):
            if not f.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
                continue

            self.process_email(f)

        return True

    def process_email(self, email_file):

        analysis = email_file.get_analysis(EmailAnalysis)
        if not analysis:
            # XXX hack - make MUCH better support for whitelisting :-(
            if not email_file.has_tag('whitelisted'):
                logging.warn("missing EmailAnalysis for {} - not logging".format(email_file.value))
            return

        if not analysis.email:
            logging.warn("missing analysis.email for {} - not logging".format(email_file.value))
            return

        # has this been whitelisted?
        if email_file.has_tag('whitelisted'):
            return

        if not analysis.log_entry:
            logging.warning("missing log entry for {}".format(email_file.value))
            return

        logging.debug("creating export logging for {}".format(email_file.value))

        # look for url extracted as well
        extracted_urls = []

        # find all urls starting from this analysis
        def _callback(target):
            nonlocal extracted_urls
            if isinstance(target, Observable) and target.type == F_URL:
                extracted_urls.append(target.value)

        recurse_tree(analysis, _callback)
        # remove duplicates
        extracted_urls = list(set(extracted_urls))

        # since we only extract urls from emails we just find them all in the entire analysis tree
        #for url_extraction in self.root.all_analysis:
            #if not isinstance(url_extraction, URLExtractionAnalysis):
                #continue

            #if url_extraction.details is not None:
                #extracted_urls.extend(url_extraction.details)

        # log where we ended up archiving the email
        archive_path = None
        archive_results = email_file.get_analysis(EmailArchiveResults)
        if archive_results:
            archive_path = archive_results.archive_path

        #url_extraction = email_file.get_analysis(URLExtractionAnalysis)
        #if url_extraction and url_extraction.details:
            # get all the URLs extracted
            #extracted_urls = url_extraction.details

        # so all we need to do now is figure out how to write the data from
        # multiple processes to the same place without collision
        entry = analysis.log_entry.copy()
        entry.update({'extracted_urls': extracted_urls})
        entry.update({'archive_path': None if archive_path is None else os.path.relpath(archive_path, start=saq.SAQ_HOME)})

        try:
            self.export_to_splunk(entry.copy())
        except Exception as e:
            logging.error("unable to create splunk log export for {}: {}".format(email_file, e))

        try:
            self.export_to_es(entry.copy())
        except Exception as e:
            logging.error("unable to create elasticsearch log export for {}: {}".format(email_file, e))

        try:
            self.export_to_brocess(entry.copy())
        except Exception as e:
            logging.error("unable to create brocess data export for {}: {}".format(email_file, e))

        return True

    def export_to_splunk(self, entry):
        """Exports the logging information to a directory where splunk can pick it up."""
        if not self.splunk_log_enabled:
            return

        entry_data = []

        # we have to have splunk extracted urls into a separate index
        extracted_urls = entry['extracted_urls']
        entry['extracted_urls'] = []
        entry['headers'] = 'temporarily removed'

        # remove the timezone info for splunk
        entry['date'] = entry['date'][:-6]

        # for splunk we need to sort the keys alphabetically
        entry_keys = list(entry.keys())

        # there's a couple fields WE don't log to splunk because of internal splunk issues
        # date,attachment_count,attachment_hashes,attachment_names,attachment_sizes,attachment_types,bcc,cc
        # env_mail_from,env_rcpt_to,extracted_urls,first_received,headers,last_received,mail_from,mail_to
        # message_id,originating_ip,path,reply_to,size,subject,user_agent,archive_path,x_mailer
        entry_keys.remove('thread_topic')
        entry_keys.remove('thread_index')
        entry_keys.remove('refereneces')
        entry_keys.remove('x_sender')

        # NOTE we need to make the date first
        # NOTE we also need to make archive_path last :(
        entry_keys.remove('date')
        entry_keys.remove('archive_path')
        entry_keys.remove('x_mailer')
        entry_keys = sorted(entry_keys)
        entry_keys.insert(0, 'date')
        entry_keys.append('archive_path')
        entry_keys.append('x_mailer')

        # we essentially document the fields in this file
        # XXX do we need to do this?
        fields_file = os.path.join(self.splunk_log_dir, 'fields')
        if not os.path.exists(fields_file):
            with open(fields_file, 'w') as fp:
                fp.write(','.join(entry_keys))

        for field in entry_keys:
            # items that are lists are combined with UNIT SEPARATOR
            if isinstance(entry[field], list):
                entry_data.append('\x1F'.join(map(str, entry[field])))
            else:
                entry_data.append(str(entry[field]) if entry[field] else '')

        def _esc(s):
            return str(s).replace('\n', '').replace('\r', '')

        # fields are separated with RECORD SEPARATOR and saved to files with pid appended
        with open(os.path.join(self.splunk_log_dir, 'smtp-{}.{}.log'.format(
                               datetime.datetime.now().strftime('%Y-%m-%d-%H'),
                               os.getpid())), 'a') as fp:
            fp.write('{}\n'.format(_esc('\x1e'.join(entry_data))))

        # we write extracted URLs into a separate log source in splunk
        # each URL gets it's own log entry

        if entry['message_id']:
            with open(os.path.join(self.splunk_log_dir, 'url-{}.{}.log'.format(
                                   datetime.datetime.now().strftime('%Y-%m-%d-%H'),
                                   os.getpid())), 'a') as fp:

                logged_urls = set()
                for url in extracted_urls:
                    # don't log dupes
                    if url in logged_urls:
                        continue

                    logged_urls.add(url)
                    entry_data = [ entry['date'], entry['message_id'], url ]
                    fp.write('{}\n'.format(_esc('\x1e'.join(entry_data))))

    def export_to_es(self, entry):
        """Create the ElasticSearch log entry."""

        if not self.json_log_enabled:
            return

        target_path = os.path.join(saq.DATA_DIR, saq.CONFIG['elk_logging']['elk_log_dir'], 
                                   datetime.datetime.now().strftime(self.json_log_path_format)).format(pid=os.getpid())

        # has the current JSON path
        target_dir = os.path.dirname(target_path)
        if not os.path.exists(target_dir):
            try:
                logging.debug("creating json logging directory {}".format(target_dir))
                os.makedirs(target_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(target_dir, e))
                return

        with open(target_path, 'a') as fp:
            fp.write(json.dumps(entry))
            fp.write('\n')

    @use_db(name='brocess')
    def export_to_brocess(self, entry, db, c):

        if not self.update_brocess:
            return

        # are we updating the brocess database?
        mail_from = normalize_email_address(entry['mail_from'])
        logging.debug("updating brocess for {}".format(mail_from))

        try:
            for email_address in entry['env_rcpt_to']:
                email_address = normalize_email_address(email_address)
                if not email_address:
                    continue

                sql = """INSERT INTO smtplog ( source, destination, numconnections, firstconnectdate )
                         VALUES (%s, %s, 1, UNIX_TIMESTAMP(NOW()))
                         ON DUPLICATE KEY UPDATE numconnections = numconnections + 1"""
                params = (mail_from, email_address)
                execute_with_retry(db, c, sql, params)

            db.commit()

        except Exception as e:
            logging.error("unable to update brocess: {}".format(e))
            report_exception()

    def OLD_execute_post_analysis(self):

        from saq.modules.file_analysis import URLExtractionAnalysis

        # is this analysis a supported type for email logging?
        if self.root.alert_type != 'mailbox' and self.root.alert_type != 'brotex - smtp - v2':
            return False

        # find the file with the EmailAnalysis attached to it
        analysis = None
        email_file = None
        for o in self.root.all_observables:
            if o.type != F_FILE:
                continue

            analysis = o.get_analysis(EmailAnalysis)
            if not analysis:
                continue

            try:
                if not analysis.email:
                    analysis = None
                    continue
            except Exception as e:
                logging.error("unexpected error when accessing email property of {}".format(analysis))
                report_exception()
                analysis = None
                continue

            email_file = o
            break

        if not analysis:
            return False

        # has this been whitelisted?
        if email_file.has_tag('whitelisted'):
            return False

        if not analysis.log_entry:
            logging.warning("missing log entry for {} in {}".format(email_file, self.root))
            return False

        logging.debug("creating logging for {}".format(email_file))

        # look for url extracted as well
        extracted_urls = []

        # since we only extract urls from emails we just find them all in the entire analysis tree
        for url_extraction in self.root.all_analysis:
            if not isinstance(url_extraction, URLExtractionAnalysis):
                continue

            if url_extraction.details is not None:
                extracted_urls.extend(url_extraction.details)

        # log where we ended up archiving the email
        archive_path = None
        archive_results = email_file.get_analysis(EmailArchiveResults)
        if archive_results:
            archive_path = archive_results.archive_path

        url_extraction = email_file.get_analysis(URLExtractionAnalysis)
        if url_extraction and url_extraction.details:
            # get all the URLs extracted
            extracted_urls = url_extraction.details

        # so all we need to do now is figure out how to write the data from
        # multiple processes to the same place without collision
        entry = analysis.log_entry.copy()
        entry.update({'extracted_urls': []})
        entry.update({'archive_path': None if archive_path is None else os.path.relpath(archive_path, start=saq.SAQ_HOME)})

        entry_data = []

        # sort the keys alphabetically
        # NOTE we need to make the date first
        # NOTE we also need to make archive_path last :(
        entry_keys = list(entry.keys())
        entry_keys.remove('date')
        entry_keys.remove('archive_path')
        entry_keys.remove('x_mailer')
        entry_keys = sorted(entry_keys)
        entry_keys.insert(0, 'date')
        entry_keys.append('archive_path')
        entry_keys.append('x_mailer')

        # we essentially document the fields in this file
        # XXX do we need to do this?
        fields_file = os.path.join(self.splunk_log_dir, 'fields')
        if not os.path.exists(fields_file):
            with open(fields_file, 'w') as fp:
                fp.write(','.join(entry_keys))

        for field in entry_keys:
            # items that are lists are combined with UNIT SEPARATOR
            if isinstance(entry[field], list):
                entry_data.append('\x1F'.join(map(str, entry[field])))
            else:
                entry_data.append(str(entry[field]) if entry[field] else '')

        def _esc(s):
            return str(s).replace('\n', '').replace('\r', '')

        # fields are separated with RECORD SEPARATOR and saved to files with pid appended
        with open(os.path.join(self.splunk_log_dir, 'smtp-{}.{}.log'.format(
                               datetime.datetime.now().strftime('%Y-%m-%d-%H'), 
                               os.getpid())), 'a') as fp:
            fp.write('{}\n'.format(_esc('\x1e'.join(entry_data))))

        # we write extracted URLs into a separate log source in splunk
        # each URL gets it's own log entry

        if entry['message_id']:
            with open(os.path.join(self.splunk_log_dir, 'url-{}.{}.log'.format(
                                   datetime.datetime.now().strftime('%Y-%m-%d-%H'), 
                                   os.getpid())), 'a') as fp:

                logged_urls = set()
                for url in extracted_urls:
                    # don't log dupes
                    if url in logged_urls:
                        continue

                    logged_urls.add(url)
                    entry_data = [ entry['date'], entry['message_id'], url ]
                    fp.write('{}\n'.format(_esc('\x1e'.join(entry_data))))

        # are we updating the brocess database?
        mail_from = normalize_email_address(entry['mail_from'])
        if self.config.getboolean('update_brocess') and mail_from:
            logging.debug("updating brocess for {}".format(mail_from))
            try:
                with get_db_connection('brocess') as db:
                    c = db.cursor()
                    for email_address in entry['env_rcpt_to']:
                        email_address = normalize_email_address(email_address)
                        if not email_address:
                            continue

                        sql = """INSERT INTO smtplog ( source, destination, numconnections, firstconnectdate )
                                 VALUES (%s, %s, 1, UNIX_TIMESTAMP(NOW())) 
                                 ON DUPLICATE KEY UPDATE numconnections = numconnections + 1"""
                        params = (mail_from, email_address)
                        execute_with_retry(c, sql, params)

                    db.commit()

            except Exception as e:
                logging.error("unable to update brocess: {}".format(e))
                report_exception()

        return True

class MessageIDAnalysis(Analysis):
    """Is there an email with this Message-ID available anywhere?"""
    
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        if not self.details:
            return None

        return "Message ID Analysis - archive file extracted"

class MessageIDAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return MessageIDAnalysis

    @property
    def valid_observable_types(self):
        return F_MESSAGE_ID

    def execute_analysis(self, message_id):

        analysis = message_id.get_analysis(MessageIDAnalysis)
        if analysis is None:
            analysis = self.create_analysis(message_id)

        result = []
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            query = """
SELECT
    archive_server.hostname, HEX(archive.md5)
FROM
    archive JOIN archive_server ON archive.server_id = archive_server.server_id
    JOIN archive_index ON archive.archive_id = archive_index.archive_id
WHERE 
    archive_index.field = 'message_id' AND archive_index.hash = UNHEX(MD5(%s))
"""

            c.execute(query, (message_id.value,))

            for server, md5 in c:
                result.append((server, md5))

        if not result and message_id.has_directive(DIRECTIVE_DELAY):
            # otherwise we wait for a bit and try again later...
            return self.delay_analysis(message_id, analysis, seconds=3, timeout_seconds=10) # XXX

        for server, md5 in result:
            # does this archive file exist?
            archive_base_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['analysis_module_email_archiver']['archive_dir'])
            if not os.path.isdir(archive_base_dir):
                logging.warning("archive directory {} does not exist".format(archive_base_dir))
                continue

            archive_path = os.path.join(archive_base_dir, server.lower(), md5.lower()[0:3], 
                                        '{}.gz.e'.format(md5.lower()))

            if not os.path.exists(archive_path):
                logging.warning("archive email {} does not exist at {}".format(md5, archive_path))
                continue

            # just add the encrypted file as-is
            target_path = os.path.join(self.root.storage_dir, '{}.gz.e'.format(message_id.value))
            if os.path.exists(target_path):
                logging.warning("target file {} already exists".format(target_path))

            try:
                shutil.copy(archive_path, target_path)
            except Exception as e:
                logging.warning("unable to copy {} to {}: {}".format(archive_path, target_path, e))
                continue

            file_observable = analysis.add_observable(F_FILE, 
                                                        os.path.relpath(target_path, start=self.root.storage_dir))
            if file_observable:
                file_observable.add_tag('encrypted_email')
                analysis.details = file_observable.value

        return True

# DEPRECATED
class URLEmailPivotAnalysis(Analysis):

    def initialize_details(self):
        self.details = {} # free form from result

    def generate_summary(self):
        if self.details is None:
            return None

        if len(self.details) == 0:
            return None

        return "URL Email Pivot ({} emails matched)".format(len(self.details))

class URLEmailPivotAnalysis_v2(Analysis):

    def initialize_details(self):
        self.details = {
            KEY_COUNT: None,
            KEY_EMAILS: None,
        }

    @property
    def count(self):
        return self.details_property(KEY_COUNT)

    @count.setter
    def count(self, value):
        self.details[KEY_COUNT] = value

    @property
    def emails(self):
        return self.details_property(KEY_EMAILS)

    @emails.setter
    def emails(self, value):
        self.details[KEY_EMAILS] = value

    def generate_summary(self):
        if not self.count:
            return None

        return "URL Email Pivot ({} emails matched)".format(self.count)

class URLEmailPivotAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return URLEmailPivotAnalysis_v2

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def result_limit(self):
        return self.config.getint('result_limit')

    def execute_analysis(self, url):

        # at the minimum we look up all the emails that have this url in them
        url_md5 = hashlib.md5(url.value.encode()).hexdigest()
        db_sections = get_email_archive_sections()
        emails = {}
        count = 0

        for section in db_sections:
            with get_db_connection(section) as db:
                c = db.cursor()
                c.execute("""
SELECT 
    COUNT(DISTINCT(asrch.archive_id))
FROM 
    archive_search asrch JOIN archive a ON asrch.archive_id = a.archive_id
    JOIN archive_index ai ON a.archive_id = ai.archive_id
WHERE 
    ai.field = 'url' AND ai.hash = UNHEX(%s)""", ( url_md5, ))

                # first we check to see how many of these we've got
                row = c.fetchone()
                if row:
                    count += row[0]

        # didn't find anything?
        if not count:
            logging.debug("did not find anything matching {}".format(url.value))
            return False

        # if there are too many then we just report the number of them
        if count >= self.result_limit:
            analysis = self.create_analysis(url)
            analysis.count = count
            return True
            
        # otherwise we get the details of the emails that match
        for section in db_sections:
            with get_db_connection(section) as db:
                c = db.cursor()
                c.execute("""
SELECT 
    DISTINCT(asrch.value)
FROM 
    archive_search asrch JOIN archive a ON asrch.archive_id = a.archive_id
    JOIN archive_index ai ON a.archive_id = ai.archive_id
WHERE 
    asrch.field = 'message_id' AND ai.field = 'url' AND ai.hash = UNHEX(%s)""", ( url_md5, ))

                message_ids = []
                for row in c:
                    message_ids.append(row[0])

                emails[section] = search_archive(section, message_ids)

        analysis = self.create_analysis(url)
        analysis.count = count
        for source in emails.keys():
            for archive_id in emails[source].keys():
                emails[source][archive_id] = emails[source][archive_id].json

        analysis.emails = emails
        return True

class CloudphishURLEmailPivotAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_MESSAGE_ID: None,
            KEY_ENV_RCPT_TO: None,
        }

    @property
    def message_id(self):
        return self.details_property(KEY_MESSAGE_ID)

    @message_id.setter
    def message_id(self, value):
        self.details[KEY_MESSAGE_ID] = value

    @property
    def recipient(self):
        return self.details_property(KEY_ENV_RCPT_TO)
    
    @recipient.setter
    def recipient(self, value):
        self.details[KEY_ENV_RCPT_TO] = value

    def generate_summary(self):
        if not self.details or not self.message_id or not self.recipient:
            return None

        return 'Cloudphish URL Email Pivot Analysis: message-id {} recipient {}'.format(
                self.message_id, self.recipient)

class CloudphishURLEmailPivotAnalyzer(AnalysisModule):
    """Was this Cloudphish alert generated by scanning an email?  What was the email?"""

    @property
    def generated_analysis_type(self):
        return CloudphishURLEmailPivotAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, url):
        if self.root.alert_type != 'cloudphish':
            return False

        if 'context' in self.root.details:
            context = self.root.details['context']
            if 't' in context:
                # tracking information is stored as a json-encoded string
                tracking = json.loads(context['t'])
                if KEY_EMAIL in tracking:
                    email = tracking[KEY_EMAIL]
                    if KEY_MESSAGE_ID in email:
                        analysis = self.create_analysis(url)
                        analysis.message_id = email[KEY_MESSAGE_ID]
                        message_id = analysis.add_observable(F_MESSAGE_ID, email[KEY_MESSAGE_ID])
                        if KEY_ENV_RCPT_TO in email:
                            analysis.recipient = email[KEY_ENV_RCPT_TO]
                        return True

        return False

_MESSAGE_ID_REGEX = re.compile(rb'^\s*Message ID:(.+)$', re.M)
_SUBJECT_REGEX = re.compile(rb'^\s*Subject:(.+)$', re.M)
_SENDER_REGEX = re.compile(rb'^\s*Sender:(.+)$', re.M)
_DETECTIONS_REGEX = re.compile(rb'Detections found:\s*(?:\r|\n|\r\n)(.+?)(?:\r|\n|\r\n)(?:\r|\n|\r\n)', re.M)

class Office365BlockAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_MESSAGE_ID: None,
            KEY_SUBJECT: None,
            KEY_SENDER: None,
            KEY_O365_DETECTIONS: None }

    @property
    def message_id(self):
        return self.details_property(KEY_MESSAGE_ID)

    @message_id.setter
    def message_id(self, value):
        self.details[KEY_MESSAGE_ID] = value

    @property
    def subject(self):
        return self.details_property(KEY_SUBJECT)
    
    @subject.setter
    def subject(self, value):
        self.details[KEY_SUBJECT] = value

    @property
    def sender(self):
        return self.details_property(KEY_SENDER)

    @sender.setter
    def sender(self, value):
        self.details[KEY_SENDER] = value

    @property
    def o365_detections(self):
        return self.details_property(KEY_O365_DETECTIONS)

    @o365_detections.setter
    def o365_detections(self, value):
        self.details[KEY_O365_DETECTIONS] = value

    def generate_summary(self):
        if not self.details:
            return None

        result = 'Office365 Blocked Phish Report'
        if self.sender:
            result = '{} From {}'.format(result, self.sender)
        if self.subject:
            result = '{} Subject {}'.format(result, self.subject)
        if self.o365_detections:
            result = '{} Detections {}'.format(result, re.sub(r'\s{2,}', ' ', self.o365_detections))

        return result

class Office365BlockAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return Office365BlockAnalysis

    @property
    def valid_observable_types(self):
        """Returns the list of addresses we expect to see these types of emails coming from."""
        return F_FILE

    def execute_analysis(self, _file):
        email_analysis = self.wait_for_analysis(_file, EmailAnalysis)
        if not email_analysis:
            return False

        # is this an email?
        if not email_analysis.email:
            #logging.debug("{} is not an email".format(_file.value))
            return False

        # is this an office365 block report?
        
        # From: Postmaster <postmaster@valvoline.com>
        # Subject: Undeliverable message
        # Auto-Submitted: auto-generated
        # not X-MS-Exchange-Generated-Message-Source: Journal Agent

        is_office365_block = True

        # check the From address
        # orignally we were checking for specific email addresses
        # but for some companies this can by many addresses (for many small companies in a conglamerate, for example)
        # so instead we just look for "postmaster" somewhere in the address
        from_address = normalize_email_address(email_analysis.mail_from)
        if not from_address:
            logging.debug("missing from address")
            is_office365_block = False
        elif 'postmaster' not in from_address.lower():
            logging.debug("from address {} does not contain postmaster".format(from_address))
            is_office365_block = False

        #if from_address not in self.valid_from_addresses:
            #logging.debug("from address {} != {}".format(from_address, self.valid_from_addresses))
            #is_office365_block = False
        
        # the subject should be "Undeliverable message"
        if email_analysis.subject != 'Undeliverable message':
            logging.debug("subject {} != Undeliverable message".format(email_analysis.subject))
            is_office365_block = False

        for key, value in email_analysis.headers:
            # X-MS-Exchange-Generated-Message-Source should have "Content Filter Agent"
            if key == 'X-MS-Exchange-Generated-Message-Source':
                if 'Content Filter Agent' not in value:
                    logging.debug("{} is not a journaled email".format(_file.value))
                    is_office365_block = False

        if not is_office365_block:
            #logging.debug("{} is not an office365 block message".format(_file.value))
            return False

        analysis = self.create_analysis(_file)

        # at this point we've decided this is a block message
        # the content of the email looks like this
        # This message was created automatically by mail delivery software. Your email message was not delivered as is to the intended recipients because malware was detected in one or more attachments included with it. All attachments were deleted.

        # --- Additional Information ---:

        # Subject: RFQ: REQ# 3636743,363744
        # Sender: erwin@anabeeb.com

        # Time received: 10/25/2017 4:51:31 AM
        # Message ID:<1508907089.06439421@emailsrvr.com>
        # Detections found: 
        # REQ# 3636743,363744.gz   Malicious Payload

        # all we really need is the Message ID so we can pull it out
        file_path = os.path.join(self.root.storage_dir, _file.value)

        try:
            with open(file_path, 'rb') as fp:
                encoded = fp.read()

            decoded = quopri.decodestring(encoded)
            m = _MESSAGE_ID_REGEX.search(decoded)
            if m:
                analysis.message_id = m.group(1).decode('utf-8').strip()

            m = _SUBJECT_REGEX.search(decoded)
            if m:
                analysis.subject = m.group(1).decode('utf-8').strip()

            m = _SENDER_REGEX.search(decoded)
            if m:
                analysis.sender = m.group(1).decode('utf-8').strip()

            m = _DETECTIONS_REGEX.search(decoded)
            if m:
                analysis.o365_detections = m.group(1).decode('utf-8').strip()

        except Exception as e:
            logging.error("unable to parse {}: {}".format(_file.value, e))
            report_exception()

        if not analysis.message_id:
            logging.error("cannot find Message ID in {}".format(_file.value))
            return True

        if not analysis.subject:
            logging.warning("cannot find Subject in {}".format(_file.value))

        if not analysis.sender:
            logging.warning("cannot find Sender in {}".format(_file.value))

        if not analysis.o365_detections:
            logging.warning("cannot find Detections in {}".format(_file.value))

        # turn this into a message_id observable and add it to the analysis
        message_id = analysis.add_observable(F_MESSAGE_ID, analysis.message_id)
        if message_id:
            message_id.add_tag('office365_block')
            message_id.add_detection_point('Office365 Block')

            # now we need to wait until this message_id becomes available in the archive
            message_id.add_directive(DIRECTIVE_DELAY)

        return True

class Office365AutoDispositionAction(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_MESSAGE_ID: None,
            KEY_TIMED_OUT: False,
            KEY_UUIDS: [], # list of alert uuids
            KEY_RESULT: None }

    @property
    def message_id(self):
        return self.details_property(KEY_MESSAGE_ID)

    @message_id.setter
    def message_id(self, value):
        assert isinstance(value, str) and value
        self.details[KEY_MESSAGE_ID] = value

    @property
    def uuids(self):
        return self.details_property(KEY_UUIDS)

    @uuids.setter
    def uuids(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_UUIDS] = value

    @property
    def result(self):
        return self.details_property(KEY_RESULT)

    @result.setter
    def result(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_RESULT] = value

    def generate_summary(self):
        if self.message_id is None:
            return None

        result = "Office365 Block Auto Disposition"

        if self.uuids:
            result = "{} - found {} alerts ({})".format(result, len(self.uuids), self.result)
        else:
            result = "{} - no matching alerts".format(result)

        return result

class Office365AutoDispositionModule(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return Office365AutoDispositionAction

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def user_id(self):
        """Returns the user_id to use when auto dispositioning alerts."""
        return self.config.getint('user_id')

    def execute_analysis(self, _file):
        analysis = _file.get_analysis(Office365AutoDispositionAction)
        if analysis is None:
            block_analysis = self.wait_for_analysis(_file, Office365BlockAnalysis)
            if not block_analysis:
                return False

            # was this an office365 block?
            if block_analysis.message_id is None:
                return False

            analysis = self.create_analysis(_file)

            # go ahead and record it here so we don't need to keep reloading the other analysis
            analysis.message_id = block_analysis.message_id

        # find all the email alerts with this message_id
        # 
        # so the issue here is you can have more than one alert for the same message ID
        # even for the same recipient email address (due to office365 oddities)
        # or for different recipients
        # so it's hard to know when to stop looking
        #

        while True:
            target_uuids = [] # list of alert UUIDs to auto disposition
            with get_db_connection() as db:
                c = db.cursor()
                execute_with_retry(c, """
SELECT 
    a.storage_dir
FROM alerts a JOIN observable_mapping om 
    ON om.alert_id = a.id 
JOIN observables o ON om.observable_id = o.id 
LEFT JOIN workload w ON w.alert_id = a.id
LEFT JOIN delayed_analysis da ON da.alert_id = a.id
WHERE 
    a.location = %s
    AND a.lock_id IS NULL AND w.alert_id IS NULL AND da.alert_id IS NULL
    AND a.disposition is NULL
    AND a.detection_count >= %s
    AND a.alert_type = 'mailbox'
    AND o.type = %s AND o.value = %s""", (saq.SAQ_NODE, self.config.getint('min_detections'), 
                                          F_MESSAGE_ID, analysis.message_id))

                for storage_dir, in c:

                    # (all processing is completed)
                    # a.lock_id IS NULL AND w.alert_id IS NULL AND da.alert_id IS NULL
                    # (and the alert is not dispositioned yet)
                    # a.disposition is NULL

                    logging.debug("auto disp found email alert @ {} for message_id {}".format(
                                  storage_dir, analysis.message_id))

                    target_alert = Alert()
                    target_alert.storage_dir = storage_dir

                    try:
                        target_alert.load()
                    except Exception as e:
                        logging.error("unable to load target alert {}: {}".format(storage_dir, e))
                        continue

                    # get the email in this alert
                    target_email = get_email(target_alert)
                    if target_email is None:
                        logging.warning("cannont find email in {}".format(target_alert))
                        continue

                    # make sure the message_id for this email alert matches what we're looking for
                    if target_email.message_id != analysis.message_id:
                        logging.warning("alert {} message_id {} != target_alert {} message_id {}".format(
                                        self.root, analysis.message_id, target_alert, target_email.message_id))
                        continue

                    # this appears to be the target alert that is ready for dispositioning
                    target_uuids.append(target_alert.uuid)

            break

        if target_uuids:
            analysis.uuids = target_uuids[:]
            try:
                with get_db_connection() as db:
                    c = db.cursor()
                    # we also want to disposition the existing alert
                    # make sure it's an alert first with a database id
                    if isinstance(self.root, Alert):
                        if self.root.id:
                            logging.info("auto disposition o365 block {}".format(self.root))
                            target_uuids.append(self.root.uuid)

                    for uuid in target_uuids:
                        logging.info("auto dispositioning {}".format(uuid))
                        c.execute("""
UPDATE alerts 
SET 
    disposition = %s, 
    disposition_user_id = %s, 
    disposition_time = NOW(),
    owner_id = %s, owner_time = NOW()
WHERE 
    uuid = %s AND (disposition IS NULL OR disposition != %s)""", (
                    DISPOSITION_WEAPONIZATION,
                    self.user_id,
                    self.user_id,
                    uuid,
                    DISPOSITION_WEAPONIZATION))

                    db.commit()
                    analysis.result = 'dispositioned'

            except Exception as e:
                logging.error("unable to auto disp: {}".format(e))
                analysis.result = "ERROR: {}".format(e)

            # nothing more to do
            return True

        # if we get this far then we need to delay analysis
        #if not self.delay_analysis(_file, analysis, minutes=1, timeout_minutes=300):
        self.delay_analysis(_file, analysis, seconds=self.config.getint('frequency'), 
                                             timeout_minutes=self.config.getint('timeout'))
        return True


class MSOfficeEncryptionAnalysis(Analysis):

    KEY_ENCRYPTION_INFO = 'encryption_info'
    KEY_EMAIL = 'email'
    KEY_EMAIL_BODY = 'email_body'
    KEY_WORD_LIST = 'word_list'
    KEY_PASSWORD = 'password'
    KEY_ERROR = 'error'

    def initialize_details(self):
        self.details = {
            MSOfficeEncryptionAnalysis.KEY_ENCRYPTION_INFO: None,
            MSOfficeEncryptionAnalysis.KEY_EMAIL: False,
            MSOfficeEncryptionAnalysis.KEY_EMAIL_BODY: None,
            MSOfficeEncryptionAnalysis.KEY_WORD_LIST: [],
            MSOfficeEncryptionAnalysis.KEY_PASSWORD: None,
            MSOfficeEncryptionAnalysis.KEY_ERROR: None
        }

    @property
    def encryption_info(self):
        return self.details_property(MSOfficeEncryptionAnalysis.KEY_ENCRYPTION_INFO)

    @encryption_info.setter
    def encryption_info(self, value):
        self.details[MSOfficeEncryptionAnalysis.KEY_ENCRYPTION_INFO] = value

    @property
    def email(self):
        return self.details_property(MSOfficeEncryptionAnalysis.KEY_EMAIL)

    @email.setter
    def email(self, value):
        self.details[MSOfficeEncryptionAnalysis.KEY_EMAIL] = value

    @property
    def email_body(self):
        return self.details_property(MSOfficeEncryptionAnalysis.KEY_EMAIL_BODY)

    @email_body.setter
    def email_body(self, value):
        self.details[MSOfficeEncryptionAnalysis.KEY_EMAIL_BODY] = value

    @property
    def word_list(self):
        return self.details_property(MSOfficeEncryptionAnalysis.KEY_WORD_LIST)

    @word_list.setter
    def word_list(self, value):
        self.details[MSOfficeEncryptionAnalysis.KEY_WORD_LIST] = value

    @property
    def password(self):
        return self.details_property(MSOfficeEncryptionAnalysis.KEY_PASSWORD)

    @password.setter
    def password(self, value):
        self.details[MSOfficeEncryptionAnalysis.KEY_PASSWORD] = value

    @property
    def error(self):
        return self.details_property(MSOfficeEncryptionAnalysis.KEY_ERROR)

    @error.setter
    def error(self, value):
        self.details[MSOfficeEncryptionAnalysis.KEY_ERROR] = value

    def generate_summary(self):
        if self.details is None:
            return None

        if self.encryption_info is None:
            return None

        result = "MSOffice Encryption Analysis"
        if self.error:
            return "{}: {}".format(result, self.error)
        elif self.password:
            return "{}: password {}".format(result, self.password)
        elif not self.email:
            return "{}: no associated email detected".format(result)
        elif not self.email_body:
            return "{}: email body cannot be determined".format(result)
        elif not self.word_list:
            return "{}: word list could not be created from email".format(result)
        elif not self.password:
            return "{}: password not available".format(result)
        else:
            return "{}: could not decrypt".format(result)

class MSOfficeEncryptionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MSOfficeEncryptionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def range_low(self):
        return self.config.getint('range_low')

    @property
    def range_high(self):
        return self.config.getint('range_high')

    @property
    def byte_limit(self):
        return self.config.getint('byte_limit')

    @property
    def list_limit(self):
        return self.config.getint('list_limit')

    def execute_analysis(self, _file):
        # does this file exist as an attachment?
        local_file_path = os.path.join(self.root.storage_dir, _file.value)
        if not os.path.exists(local_file_path):
            return False

        # is this an encrypted OLE document?
        try:
            output_file = '{}.decrypted'.format(local_file_path)
            decryptor = MSOfficeDecryptor(local_file_path, output_file)
            if not decryptor.is_decryptable:
                return False

            analysis = self.create_analysis(_file)

            _file.add_tag('encrypted_msoffice')
            analysis.encryption_info = decryptor.encryption_info._asdict() # it's a named tuple

            # first try the default password of VelvetSweatshop
            # see https://isc.sans.edu/diary/rss/23774 
            analysis.password = decryptor.guess()

            if not analysis.password:

                # OK then we've found an office document that is encrypted
                # we'll try to find the passwords by looking at the plain text and html of the email, if they exist
                email = get_email(self.root)
                if email is None:
                    logging.info("encrypted word document {} found but no associated email was found".format(_file.value))
                    return False

                analysis.email = True

                # email needs to have a body
                if not email.body:
                    logging.info("encrypted word document {} found but no associated email body was found".format(_file.value))
                    return False

                # convert html to text
                with open(os.path.join(self.root.storage_dir, email.body.value), 'r', errors='ignore') as fp:
                    logging.debug("parsing {} for html".format(email.body.value))
                    analysis.email_body = html2text(fp.read())[:self.byte_limit]

                analysis.word_list = decryptor.find_password(text_content=analysis.email_body,
                                                             range_low=self.range_low,
                                                             range_high=self.range_high,
                                                             byte_limit=self.byte_limit,
                                                             list_limit=self.list_limit)
                                                              
                if len(analysis.word_list) == 0:
                    logging.info("could not generate a word list from {}".format(email.body.value))
                    return False

                # now try to guess
                logging.info("guessing {} passwords for {}".format(len(analysis.word_list), _file.value))
                analysis.password = decryptor.guess(analysis.word_list)

                if not analysis.password:
                    logging.info("unable to guess password for {}".format(_file.value))
                    return False

            # decrypt the file
            decryptor.decrypt(analysis.password)
            
            # add the decrypted file for analysis
            decrypted_file = analysis.add_observable(F_FILE, os.path.relpath(output_file, start=self.root.storage_dir))
            if decrypted_file:
                decrypted_file.add_tag('decrypted_msoffice')
                decrypted_file.add_detection_point("Was able to decrypt based on contents of email.")

            return True

        except UnsupportedAlgorithm as e:
            analysis.error = str(e)
            return True
        except Exception as e:
            logging.debug("decryption for {} failed: {}".format(_file.value, e))
            #report_exception()
            return False
