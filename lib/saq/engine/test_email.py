# vim: sw=4:ts=4:et

import io
import logging
import os, os.path
import re
import shutil
import socket
import ssl
import tempfile

from email.message import EmailMessage
from subprocess import Popen, PIPE, DEVNULL

import saq, saq.test
from saq.constants import *
from saq.database import get_db_connection
from saq.engine.email import EmailScanningEngine
from saq.network_client import submit_alerts
from saq.test import *

def create_email_submission_dir():
    return tempfile.mkdtemp(dir=saq.test.test_dir)

def create_basic_email():
    msg = EmailMessage()
    msg.set_content('Hello, world!')
    msg['Subject'] = 'test'
    msg['From'] = 'test_from@localhost'
    msg['To'] = 'test_to@localhost'

    #logging.info("MARKER: {}".format(str(msg)))

    return bytes(msg)

def submit_emails(emails):
    assert isinstance(emails, list)
    assert emails

    config = saq.CONFIG['engine_email_scanner']
    
    context = ssl.create_default_context()
    context.load_verify_locations(config['ssl_ca_path'])
    context.load_cert_chain(config['ssl_cert_path'], keyfile=config['ssl_key_path'])
    client_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=config['ssl_hostname'])
    client_socket.connect(('localhost', config.getint('server_port')))

    tar_command = [ 'tar', 'zc' ]
    tar_command.extend(emails)

    p = Popen(tar_command, stdout=PIPE, stderr=DEVNULL)
    while True:
        data = p.stdout.read(io.DEFAULT_BUFFER_SIZE)
        if data == b'':
            break

        client_socket.sendall(data)

    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()
    p.wait()

    if p.returncode:
        raise RuntimeError("tar command returned {}".format(p.returncode))

class EmailEngineTestCase(ACEEngineTestCase):
    def test_email_engine_000_startup(self):
        """Email scanner startup and shutdown."""
        engine = EmailScanningEngine()
        self.start_engine(engine)
        engine.stop()
        self.wait_engine(engine)

    def _network_collection(self, count=1):
        engine = EmailScanningEngine()
        self.start_engine(engine)

        temp_dir = create_email_submission_dir()
        targets = []
        for i in range(count):
            target_path = os.path.join(temp_dir, '{}_email.rfc822'.format(i))
            with open(target_path, 'wb') as fp:
                fp.write(create_basic_email())

            targets.append(target_path)

        submit_emails(targets)
        
        wait_for_log_count('received network item', count)
        
        engine.stop()
        self.wait_engine(engine)
        self.assertEquals(log_count('received network item'), count)

    @clear_log
    def test_email_engine_001_network_collection(self):
        """Single email submission."""
        self._network_collection(1)

    @clear_log
    def test_email_engine_002_network_collection_multiple(self):
        """Multiple email submissions."""
        self._network_collection(10)

    @clear_log
    def test_email_engine_003_email_processing(self):
        """Testing full processing of an email."""
        engine = EmailScanningEngine()
        self.start_engine(engine)

        temp_dir = create_email_submission_dir()
        target_path = os.path.join(temp_dir, 'email.rfc822')
        with open(target_path, 'wb') as fp:
            fp.write(create_basic_email())

        submit_emails([target_path])

        # received network item /opt/saq/var/incoming/email_scanner/opt/saq/var/test/tmptoa74_xq/8_email.rfc822 
        
        def condition(e):
            match = re.match(r'^received network item (.+)$', e.getMessage())
            if not match:
                return False

            condition.file_path = match.group(1)
            return True

        wait_for_log_entry(condition)

        # make sure the received network item was deleted (moved)
        self.assertFalse(os.path.exists(condition.file_path))

        # find the workload entry being added
        def condition(e):
            match = re.match(r'^adding (.+) to sql workload EMAIL', e.getMessage())
            if not match:
                return False

            condition.file_path = match.group(1)
            return True

        wait_for_log_entry(condition)

        # find the log entry where the incoming storage directory gets moved
        incoming_file_path = condition.file_path
        uuid = os.path.basename(incoming_file_path)
        work_file_path = os.path.join(engine.work_dir, uuid[:3], uuid)
        log_message = 'moving {} to {} for work'.format(incoming_file_path, work_file_path)
        wait_for_log_count(log_message, 1)
        self.assertFalse(os.path.exists(incoming_file_path))
        # look for post analysis
        log_message = 'executing post analysis on RootAnalysis({})'.format(uuid)
        wait_for_log_count(log_message, 1)
        # look for the entry that says it deleted it
        log_message = 'deleted {}'.format(work_file_path)
        wait_for_log_count(log_message, 1)
        self.assertFalse(os.path.exists(work_file_path))
        
        engine.stop()
        self.wait_engine(engine)

    @clear_log
    def test_email_engine_004_cloudphish_tracking(self):

        # set the decryption password
        saq.ENCRYPTION_PASSWORD = 'password'

        self.reset_cloudphish()
        self.reset_correlation()
        self.reset_email_archive()
        self.start_gui_server()
        
        # reconfigure to only load certain modules
        from saq.engine.cloudphish import CloudPhishEngine
        class _custom_CloudPhishEngine(CloudPhishEngine):
            def initialize_modules(self):
                for section in saq.CONFIG.keys():
                    if section.startswith('analysis_module_'):
                        saq.CONFIG[section]['enabled'] = 'no'

                for section in [ 'crawlphish' ]:
                    saq.CONFIG['analysis_module_{}'.format(section)]['enabled'] = 'yes'
                    self.config['analysis_module_{}'.format(section)] = 'yes'

                CloudPhishEngine.initialize_modules(self)

            def should_alert(self, root):
                return True

        from saq.engine.ace import ACE
        class _custom_ACE(ACE):
            def initialize_modules(self):
                for section in saq.CONFIG.keys():
                    if section.startswith('analysis_module_'):
                        saq.CONFIG[section]['enabled'] = 'no'

                for section in [ 'cloudphish_url_email_pivot_analyzer', 
                                 'encrypted_archive_analyzer', 
                                 'message_id_analyzer' ]:
                    saq.CONFIG['analysis_module_{}'.format(section)]['enabled'] = 'yes'
                    self.config['analysis_module_{}'.format(section)] = 'yes'

                ACE.initialize_modules(self)

        class _custom_EmailScanningEngine(EmailScanningEngine):
            def initialize_modules(self):
                for section in saq.CONFIG.keys():
                    if section.startswith('analysis_module_'):
                        saq.CONFIG[section]['enabled'] = 'no'

                for section in [ 'file_type', 'email_analyzer', 'url_extraction', 'cloudphish', 'email_archiver' ]:
                    saq.CONFIG['analysis_module_{}'.format(section)]['enabled'] = 'yes'
                    self.config['analysis_module_{}'.format(section)] = 'yes'

                # set the cloudphish query timeout to 0 so we don't wait at all
                saq.CONFIG['analysis_module_cloudphish']['frequency'] = '1'
                saq.CONFIG['analysis_module_cloudphish']['query_timeout'] = '0'

                EmailScanningEngine.initialize_modules(self)

            # do not alert
            def should_alert(self, root):
                return False
            
        email_engine = _custom_EmailScanningEngine()
        self.start_engine(email_engine)

        # we use test_data/emails/splunk_logging.email.rfc822 because it contains the url
        # https://www.alienvault.com/
        temp_dir = create_email_submission_dir()
        target_path = os.path.join(temp_dir, 'email.rfc822')
        shutil.copy('test_data/emails/splunk_logging.email.rfc822', target_path)
        submit_emails([target_path])

        # look for the submission of the url to the cloudphish system
        log_message = 'executing post analysis on RootAnalysis'
        wait_for_log_count(log_message, 1)
        email_engine.stop()
        self.wait_engine(email_engine)

        # there should be one entry in the archive
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("SELECT COUNT(*) FROM archive")
            row = c.fetchone()
            self.assertIsNotNone(row)
            self.assertEquals(row[0], 1)

        # clear out everything in the cloudphish workload except for the alienvault one
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("DELETE FROM workload WHERE url != 'https://www.alienvault.com'")
            db.commit()

        # we need to go ahead and start the ACE engine so it can accept the alert cloudphish is going to generate
        ace_engine = _custom_ACE()
        self.start_engine(ace_engine)

        cloudphish_engine = _custom_CloudPhishEngine()
        self.start_engine(cloudphish_engine)

        # wait for both to finish
        wait_for_log_count(log_message, 3)
    
        cloudphish_engine.stop()
        self.wait_engine(cloudphish_engine)

        ace_engine.stop()
        self.wait_engine(ace_engine)

        # there should be a single alert in the database
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("SELECT COUNT(*) FROM alerts")
            row = c.fetchone()
            self.assertIsNotNone(row)
            self.assertEquals(row[0], 1)

            c.execute("SELECT storage_dir FROM alerts")
            row = c.fetchone()
            self.assertIsNotNone(row)
            storage_dir = row[0]

        from saq.database import Alert
        alert = Alert(storage_dir=storage_dir)
        alert.load()

        self.assertEquals(alert.alert_type, 'cloudphish')
        self.assertTrue('url' in alert.details)
        self.assertEquals(alert.details['url'], 'https://www.alienvault.com')
        self.assertTrue('context' in alert.details)
        context = alert.details['context']
        self.assertTrue('t' in context)
        tracking = context['t']
        self.assertTrue('email' in tracking)

        # find the original cloudphish url
        url = alert.get_observable_by_spec(F_URL, 'https://www.alienvault.com')
        self.assertIsNotNone(url)

        # get the cloudphish url pivot
        from saq.modules.email import CloudphishURLEmailPivotAnalysis
        pivot_analysis = url.get_analysis(CloudphishURLEmailPivotAnalysis)
        self.assertIsNotNone(pivot_analysis)
        message_id = pivot_analysis.get_observables_by_type(F_MESSAGE_ID)
        self.assertEquals(len(message_id), 1)
        message_id = message_id[0]

        # that should have analysis on the message_id
        from saq.modules.email import MessageIDAnalysis
        message_id_analysis = message_id.get_analysis(MessageIDAnalysis)
        self.assertIsNotNone(message_id_analysis)
        
        # which should generate the encrypted email file
        encrypted_email = message_id_analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(encrypted_email), 1)
        encrypted_email = encrypted_email[0]

        # that should have the EncryptedArchiveAnalysis attached to it
        from saq.modules.email import EncryptedArchiveAnalysis
        encrypted_email_analysis = encrypted_email.get_analysis(EncryptedArchiveAnalysis)
        self.assertIsNotNone(encrypted_email_analysis)
        
        # which should generate the rfc822 file
        rfc822_file = encrypted_email_analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(rfc822_file), 1)
        rfc822_file = rfc822_file[0]
