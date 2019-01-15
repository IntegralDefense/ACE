# vim: sw=4:ts=4:et

import datetime
import json
import logging
import os, os.path
import shutil
import socket
import unittest
import uuid

import pytz

import saq, saq.test
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.database import get_db_connection
from saq.test import *
from saq.util import storage_dir_from_uuid

class TestCase(ACEModuleTestCase):
    def test_mailbox(self):
        import saq.modules.email
        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_mailbox_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        
        # we should still have our old details
        self.assertTrue('hello' in root.details)
        # merged in with our email analysis
        self.assertTrue('email' in root.details)
        self.assertIsNotNone(root.details['email'])
        self.assertTrue(root.description.startswith(saq.modules.email.MAILBOX_ALERT_PREFIX))

    def test_no_mailbox(self):
        # make sure that when we analyze emails in non-mailbox analysis that we don't treat it like it came from mailbox
        root = create_root_analysis(alert_type='not-mailbox') # <-- different alert_type
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_mailbox_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        
        # we should still have our old details
        self.assertTrue('hello' in root.details)
        # and we should NOT have the email details merged in since it's not a mailbox analysis
        self.assertFalse('email' in root.details)

    def test_mailbox_whitelisted(self):
        # make sure that we do not process whitelisted emails
        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.mark_as_whitelisted()
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_mailbox_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        
        # we should still have our old details
        self.assertTrue('hello' in root.details)
        # and we should NOT have the email details merged in since it's not a mailbox analysis
        self.assertFalse('email' in root.details)
        # and we should be whitelisted at this point
        self.assertTrue(root.whitelisted)

    def test_mailbox_submission(self):
        from flask import url_for
        from saq.analysis import _JSONEncoder
        from saq.modules.email import EmailAnalysis

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime.now()).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        with open(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 'rb') as fp:
            result = self.client.post(url_for('analysis.submit'), data={
                'analysis': json.dumps({
                    'analysis_mode': 'email',
                    'tool': 'unittest',
                    'tool_instance': 'unittest_instance',
                    'type': 'mailbox',
                    'description': 'testing',
                    'event_time': t,
                    'details': { },
                    'observables': [
                        { 'type': F_FILE, 'value': 'rfc822.email', 'time': t, 'tags': [], 'directives': [ DIRECTIVE_ORIGINAL_EMAIL ], 'limited_analysis': [] },
                    ],
                    'tags': [ ],
                }, cls=_JSONEncoder),
                'file': (fp, 'rfc822.email'),
            }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)

        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        uuid = result['uuid']

        # make sure we don't clean up the anaysis so we can check it
        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'

        engine = TestEngine(local_analysis_modes=['email'])
        engine.enable_module('analysis_module_file_type', 'email')
        engine.enable_module('analysis_module_email_analyzer', 'email')
        engine.enable_module('analysis_module_mailbox_email_analyzer', 'email')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=storage_dir_from_uuid(uuid))
        root.load()
        observable = root.find_observable(lambda o: o.has_directive(DIRECTIVE_ORIGINAL_EMAIL))
        self.assertIsNotNone(observable)
        analysis = observable.get_analysis(EmailAnalysis)
        self.assertIsNotNone(analysis)

        # these should be the same
        self.assertEquals(analysis.details, root.details)

    def test_bro_smtp_stream_analysis(self):
        import saq
        import saq.modules.email

        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'
        
        root = create_root_analysis(alert_type=ANALYSIS_TYPE_BRO_SMTP, analysis_mode=ANALYSIS_MODE_EMAIL)
        root.initialize_storage()
        root.details = { }
        shutil.copy(os.path.join('test_data', 'smtp_streams', 'CBmtfvapmTMqCEUw6'), 
                    os.path.join(root.storage_dir, 'CBmtfvapmTMqCEUw6'))
        file_observable = root.add_observable(F_FILE, 'CBmtfvapmTMqCEUw6')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_SMTP)
        file_observable.add_directive(DIRECTIVE_NO_SCAN)
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=[ANALYSIS_MODE_EMAIL])
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_bro_smtp_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        analysis = file_observable.get_analysis(saq.modules.email.BroSMTPStreamAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(len(analysis.get_observables_by_type(F_FILE)), 1)
        self.assertEquals(len(analysis.get_observables_by_type(F_EMAIL_ADDRESS)), 2)
        self.assertEquals(len(analysis.get_observables_by_type(F_IPV4)), 1)
        self.assertEquals(len(analysis.get_observables_by_type(F_EMAIL_CONVERSATION)), 1)
        self.assertTrue(saq.modules.email.KEY_CONNECTION_ID in analysis.details)
        self.assertTrue(saq.modules.email.KEY_SOURCE_IPV4 in analysis.details)
        self.assertTrue(saq.modules.email.KEY_SOURCE_PORT in analysis.details)
        self.assertTrue(saq.modules.email.KEY_ENV_MAIL_FROM in analysis.details)
        self.assertTrue(saq.modules.email.KEY_ENV_RCPT_TO in analysis.details)
        email_file = analysis.find_observable(lambda o: o.type == F_FILE)
        self.assertIsNotNone(email_file)
        self.assertEquals(email_file.value, 'email.rfc822')
        email_analysis = email_file.get_analysis(saq.modules.email.EmailAnalysis)
        self.assertIsNotNone(email_analysis)

    def test_bro_smtp_stream_analysis_no_end_command(self):
        import saq
        import saq.modules.email

        # test the same thing as test_bro_smtp_stream_analysis except we remove the > . .

        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'
        
        root = create_root_analysis(alert_type=ANALYSIS_TYPE_BRO_SMTP, analysis_mode=ANALYSIS_MODE_EMAIL)
        root.initialize_storage()
        root.details = { }
        shutil.copy(os.path.join('test_data', 'smtp_streams', 'CBmtfvapmTMqCEUw6.missing_end'), 
                    os.path.join(root.storage_dir, 'CBmtfvapmTMqCEUw6'))
        
        file_observable = root.add_observable(F_FILE, 'CBmtfvapmTMqCEUw6')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_SMTP)
        file_observable.add_directive(DIRECTIVE_NO_SCAN)
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=[ANALYSIS_MODE_EMAIL])
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_bro_smtp_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        analysis = file_observable.get_analysis(saq.modules.email.BroSMTPStreamAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(len(analysis.get_observables_by_type(F_FILE)), 1)
        self.assertEquals(len(analysis.get_observables_by_type(F_EMAIL_ADDRESS)), 2)
        self.assertEquals(len(analysis.get_observables_by_type(F_IPV4)), 1)
        self.assertEquals(len(analysis.get_observables_by_type(F_EMAIL_CONVERSATION)), 1)
        self.assertTrue(saq.modules.email.KEY_CONNECTION_ID in analysis.details)
        self.assertTrue(saq.modules.email.KEY_SOURCE_IPV4 in analysis.details)
        self.assertTrue(saq.modules.email.KEY_SOURCE_PORT in analysis.details)
        self.assertTrue(saq.modules.email.KEY_ENV_MAIL_FROM in analysis.details)
        self.assertTrue(saq.modules.email.KEY_ENV_RCPT_TO in analysis.details)
        email_file = analysis.find_observable(lambda o: o.type == F_FILE)
        self.assertIsNotNone(email_file)
        self.assertEquals(email_file.value, 'email.rfc822')
        email_analysis = email_file.get_analysis(saq.modules.email.EmailAnalysis)
        self.assertIsNotNone(email_analysis)

    def test_bro_smtp_stream_submission(self):
        from flask import url_for
        from saq.analysis import _JSONEncoder
        from saq.modules.email import EmailAnalysis, BroSMTPStreamAnalysis

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime.now()).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        with open(os.path.join('test_data', 'smtp_streams', 'CBmtfvapmTMqCEUw6'), 'rb') as fp:
            result = self.client.post(url_for('analysis.submit'), data={
                'analysis': json.dumps({
                    'analysis_mode': ANALYSIS_MODE_EMAIL,
                    'tool': 'unittest',
                    'tool_instance': 'unittest_instance',
                    'type': ANALYSIS_TYPE_BRO_SMTP,
                    'description': 'BRO SMTP Scanner Detection - ',
                    'event_time': t,
                    'details': { },
                    'observables': [
                        { 'type': F_FILE, 'value': 'CBmtfvapmTMqCEUw6', 'time': t, 'tags': [], 'directives': [ DIRECTIVE_ORIGINAL_SMTP ], 'limited_analysis': [] },
                    ],
                    'tags': [ ],
                }, cls=_JSONEncoder),
                'file': (fp, 'CBmtfvapmTMqCEUw6'),
            }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)

        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        uuid = result['uuid']

        # make sure we don't clean up the anaysis so we can check it
        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'

        engine = TestEngine(local_analysis_modes=[ANALYSIS_MODE_EMAIL])
        engine.enable_module('analysis_module_file_type', 'email')
        engine.enable_module('analysis_module_email_analyzer', 'email')
        engine.enable_module('analysis_module_bro_smtp_analyzer', 'email')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=storage_dir_from_uuid(uuid))
        root.load()
        observable = root.find_observable(lambda o: o.has_directive(DIRECTIVE_ORIGINAL_SMTP))
        self.assertIsNotNone(observable)
        analysis = observable.get_analysis(BroSMTPStreamAnalysis)
        self.assertIsNotNone(analysis)

    def test_splunk_logging(self):

        # clear splunk logging directory
        splunk_log_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['splunk_logging']['splunk_log_dir'], 'smtp')
        if os.path.isdir(splunk_log_dir):
            shutil.rmtree(splunk_log_dir)
            os.mkdir(splunk_log_dir)

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_logger', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should expect three files in this directory now
        splunk_files = os.listdir(splunk_log_dir)
        self.assertEquals(len(splunk_files), 3)
        
        smtp_file = None
        url_file = None
        fields_file = None

        for _file in splunk_files:
            if _file.startswith('smtp-'):
                smtp_file = os.path.join(splunk_log_dir, _file)
            elif _file.startswith('url-'):
                url_file = os.path.join(splunk_log_dir, _file)
            elif _file == 'fields':
                fields_file = os.path.join(splunk_log_dir, _file)

        self.assertIsNotNone(smtp_file)
        self.assertIsNotNone(url_file)
        self.assertIsNotNone(fields_file)

        with open(smtp_file, 'r') as fp:
            smtp_logs = fp.read()

        with open(url_file, 'r') as fp:
            url_logs = fp.read()

        smtp_logs = [_ for _ in smtp_logs.split('\n') if _]
        url_logs = [_ for _ in url_logs.split('\n') if _]

        self.assertEquals(len(smtp_logs), 1)
        self.assertEquals(len(url_logs), 3)

        url_fields = url_logs[0].split('\x1e')
        self.assertEquals(len(url_fields), 3)

        smtp_fields = smtp_logs[0].split('\x1e')
        self.assertEquals(len(smtp_fields), 25)
        
        with open(fields_file, 'r') as fp:
            fields = fp.readline().strip()

        self.assertEquals(fields, 'date,attachment_count,attachment_hashes,attachment_names,attachment_sizes,attachment_types,bcc,'
                                  'cc,env_mail_from,env_rcpt_to,extracted_urls,first_received,headers,last_received,mail_from,'
                                  'mail_to,message_id,originating_ip,path,reply_to,size,subject,user_agent,archive_path,x_mailer')

    def test_update_brocess(self):

        # make sure we update the brocess database when we can scan email

        self.reset_brocess()

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'),
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_logger', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        file_observable = root.get_observable(file_observable.id)
        from saq.modules.email import EmailAnalysis
        analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertIsNotNone(analysis)

        # get the source and dest of the email so we can look it up in the brocess database

        from saq.email import normalize_email_address
        mail_from = normalize_email_address(analysis.mail_from)
        env_rcpt_to = normalize_email_address(analysis.env_rcpt_to[0])

        # we should see a count of 1 here

        with get_db_connection('brocess') as db:
            c = db.cursor()
            c.execute("""SELECT numconnections FROM smtplog WHERE source = %s AND destination = %s""",
                     (mail_from, env_rcpt_to))
            count = c.fetchone()
            self.assertEquals(count[0], 1)

        # and then we do it again and make sure the count increased

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'),
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_logger', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        with get_db_connection('brocess') as db:
            c = db.cursor()
            c.execute("""SELECT numconnections FROM smtplog WHERE source = %s AND destination = %s""",
                     (mail_from, env_rcpt_to))
            count = c.fetchone()
            self.assertEquals(count[0], 2)

    def test_elk_logging(self):

        # clear elk logging directory
        elk_log_dir = os.path.join(saq.SAQ_HOME, saq.CONFIG['elk_logging']['elk_log_dir'])
        if os.path.isdir(elk_log_dir):
            shutil.rmtree(elk_log_dir)
            os.mkdir(elk_log_dir)

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_logger', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        wait_for_log_count('creating json logging directory ', 1, 5)
        entry = search_log('creating json logging directory ')
        target_dir = entry[0].getMessage()[len('creating json logging directory '):]

        # we should expect three files in this directory now
        elk_files = [os.path.join(target_dir, _) for _ in os.listdir(target_dir)]
        self.assertEquals(len(elk_files), 1)

        with open(elk_files[0], 'r') as fp:
            log_entry = json.load(fp)

        for field in [ 'date', 'first_received', 'last_received', 'env_mail_from', 'env_rcpt_to', 'mail_from', 'mail_to', 'reply_to',
                       'cc', 'bcc', 'message_id', 'subject', 'path', 'size', 'user_agent', 'x_mailer', 'originating_ip', 'headers', 'attachment_count',
                       'attachment_sizes', 'attachment_types', 'attachment_names', 'attachment_hashes', 'thread_topic', 'thread_index', 'refereneces', 'x_sender' ]:

            self.assertTrue(field in log_entry)

    def test_archive_1(self):

        # clear email archive
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("DELETE FROM archive")
            db.commit()

        hostname = socket.gethostname().lower()
        archive_dir = os.path.join(saq.SAQ_HOME, saq.CONFIG['analysis_module_email_archiver']['archive_dir'], hostname)
        if os.path.isdir(archive_dir):
            try:
                shutil.rmtree(archive_dir)
                os.mkdir(archive_dir)
            except Exception as e:
                self.fail("unable to clear archive dir {}: {}".format(archive_dir, e))

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_file_hash_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_archiver', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # there should be a single entry in the archive
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("SELECT archive_id FROM archive")
            row = c.fetchone()
            self.assertIsNotNone(row)
            archive_id = row[0]

            # check the index and make sure all the expected values are there
            expected_values = [ ('body_from', b'unixfreak0037@gmail.com'),
            ('body_to', b'jwdavison@company.com'),
            ('decoded_subject', b'canary #3'),
            ('env_to', b'jwdavison@company.com'),
            ('message_id', b'<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>'),
            ('subject', b'canary #3'),
            ('url', b'http://tldp.org/LDP/abs/html'),
            ('url', b'https://www.alienvault.com'),
            ('url', b'http://197.210.28.107')]

            for field_name, field_value in expected_values:
                c.execute("SELECT value FROM archive_search WHERE field = %s AND archive_id = %s AND value = %s", 
                         (field_name, archive_id, field_value))
                row = c.fetchone()
                self.assertIsNotNone(row)
                value = row[0]
                self.assertEquals(value, field_value)

    def test_archive_2(self):

        # clear email archive
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("DELETE FROM archive")
            db.commit()

        hostname = socket.gethostname().lower()
        archive_dir = os.path.join(saq.SAQ_HOME, saq.CONFIG['analysis_module_email_archiver']['archive_dir'], hostname)
        if os.path.isdir(archive_dir):
            try:
                shutil.rmtree(archive_dir)
                os.mkdir(archive_dir)
            except Exception as e:
                self.fail("unable to clear archive dir {}: {}".format(archive_dir, e))

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'pdf_attachment.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_file_hash_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_archiver', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.enable_module('analysis_module_pdf_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # there should be a single entry in the archive
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("SELECT archive_id FROM archive")
            row = c.fetchone()
            archive_id = row[0]

            # check the index and make sure all the expected values are there
            expected_values = [ ('env_to', b'jwdavison@company.com'),
            ('body_from', b'unixfreak0037@gmail.com'),
            ('body_to', b'jwdavison@company.com'),
            ('subject', b'canary #1'),
            ('decoded_subject', b'canary #1'),
            ('message_id', b'<CANTOGZuWahvYOEr0NwPELF5ASriGNWjfVsWhMSE_ekiSVw1RbA@mail.gmail.com>'),
            #('url', b'mailto:unixfreak0037@gmail.com'),
            ('content', b'6967810094670a0978da20db86fbfadc'),
            ('url', b'http://www.ams.org') ]

            for field_name, field_value in expected_values:
                c.execute("SELECT value FROM archive_search WHERE field = %s AND archive_id = %s AND value = %s", 
                         (field_name, archive_id, field_value))
                row = c.fetchone()
                self.assertIsNotNone(row)
                value = row[0]
                self.assertEquals(value, field_value)

    def test_email_pivot(self):

        # process the email first -- we'll find it when we pivot

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_file_hash_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_archiver', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        saq.load_configuration()

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='cloudphish')
        root.initialize_storage()

        # make up some details
        root.details = { 
            'alertable': 1,
            'context': {
                'c': '1c38af75-0c42-4ae3-941d-de3975f68602',
                'd': '1',
                'i': 'ashland',
                's': 'email_scanner'
            },
            'sha256_url': '0061537d578e4f65d13e31e190e1079e00dadd808e9fa73f77e3308fdb0e1485',
            'url': 'https://www.alienvault.com', # <-- the important part
        }

        url_observable = root.add_observable(F_URL, 'https://www.alienvault.com')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_url_email_pivot_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url_observable = root.get_observable(url_observable.id)
        from saq.modules.email import URLEmailPivotAnalysis_v2
        analysis = url_observable.get_analysis(URLEmailPivotAnalysis_v2)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.count, 1)
        self.assertIsNotNone(analysis.emails)
        self.assertTrue('email_archive' in analysis.emails)
        archive_id = list(analysis.emails['email_archive'].keys())[0]
        entry = analysis.emails['email_archive'][archive_id]
        self.assertEquals(int(archive_id), entry['archive_id'])
        self.assertEquals('canary #3', entry['subject'])
        self.assertEquals('jwdavison@company.com', entry['recipient'])
        self.assertEquals('<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>', entry['message_id'])
        self.assertEquals('unixfreak0037@gmail.com', entry['sender'])
        self.assertEquals(len(entry['remediation_history']), 0)
        self.assertFalse(entry['remediated'])

    def test_email_pivot_excessive_emails(self):

        # process the email first -- we'll find it when we pivot

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_file_hash_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_email_archiver', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        saq.load_configuration()

        # force this to exceed the limit
        saq.CONFIG['analysis_module_url_email_pivot_analyzer']['result_limit'] = '0'
        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='cloudphish')

        root.initialize_storage()

        # make up some details
        root.details = { 
            'alertable': 1,
            'context': {
                'c': '1c38af75-0c42-4ae3-941d-de3975f68602',
                'd': '1',
                'i': 'ashland',
                's': 'email_scanner'
            },
            'sha256_url': '0061537d578e4f65d13e31e190e1079e00dadd808e9fa73f77e3308fdb0e1485',
            'url': 'https://www.alienvault.com', # <-- the important part
        }

        url_observable = root.add_observable(F_URL, 'https://www.alienvault.com')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_url_email_pivot_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url_observable = root.get_observable(url_observable.id)
        from saq.modules.email import URLEmailPivotAnalysis_v2
        analysis = url_observable.get_analysis(URLEmailPivotAnalysis_v2)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.count, 1)
        # this should not have the details since it exceeded the limit
        self.assertIsNone(analysis.emails)

    def test_message_id(self):

        # make sure we extract the correct message-id
        # this test email has an attachment that contains a message-id
        # we need to make sure we do not extract that one as the message-id observable

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'extra_message_id.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertIsNotNone(email_analysis)
        message_id = email_analysis.get_observables_by_type(F_MESSAGE_ID)
        self.assertTrue(isinstance(message_id, list) and len(message_id) > 0)
        message_id = message_id[0]
        
        self.assertEquals(message_id.value, "<MW2PR16MB224997B938FB40AA00214DACA8590@MW2PR16MB2249.namprd16.prod.outlook.com>")

    def test_basic_email_parsing(self):

        # parse a basic email message

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertIsNotNone(email_analysis)

        self.assertIsNone(email_analysis.parsing_error)
        self.assertIsNotNone(email_analysis.email)
        self.assertIsNone(email_analysis.env_mail_from)
        self.assertTrue(isinstance(email_analysis.env_rcpt_to, list))
        self.assertEquals(len(email_analysis.env_rcpt_to), 1)
        self.assertEquals(email_analysis.env_rcpt_to[0], 'jwdavison@company.com')
        self.assertEquals(email_analysis.mail_from, 'John Davison <unixfreak0037@gmail.com>')
        self.assertTrue(isinstance(email_analysis.mail_to, list))
        self.assertEquals(len(email_analysis.mail_to), 1)
        self.assertEquals(email_analysis.mail_to[0], 'jwdavison@company.com')
        self.assertIsNone(email_analysis.reply_to)
        self.assertEquals(email_analysis.subject, 'canary #3')
        self.assertEquals(email_analysis.decoded_subject, email_analysis.subject)
        self.assertEquals(email_analysis.message_id, '<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>')
        self.assertIsNone(email_analysis.originating_ip, None)
        self.assertTrue(isinstance(email_analysis.received, list))
        self.assertEquals(len(email_analysis.received), 6)
        self.assertTrue(isinstance(email_analysis.headers, list))
        self.assertTrue(isinstance(email_analysis.log_entry, dict))
        self.assertIsNone(email_analysis.x_mailer)
        self.assertIsNotNone(email_analysis.body)
        self.assertIsInstance(email_analysis.attachments, list)
        self.assertEquals(len(email_analysis.attachments), 0)
        
    def test_o365_journal_email_parsing(self):

        # parse an office365 journaled message

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'o365_journaled.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)

        self.assertIsNotNone(email_analysis)
        self.assertIsNone(email_analysis.parsing_error)
        self.assertIsNotNone(email_analysis.email)
        self.assertIsNone(email_analysis.env_mail_from)
        self.assertTrue(isinstance(email_analysis.env_rcpt_to, list))
        self.assertEquals(len(email_analysis.env_rcpt_to), 1)
        self.assertEquals(email_analysis.env_rcpt_to[0], 'lulu.zingzing@company.com')
        self.assertEquals(email_analysis.mail_from, 'Bobbie Fruitypie <ap@someothercompany.com>')
        self.assertTrue(isinstance(email_analysis.mail_to, list))
        self.assertEquals(len(email_analysis.mail_to), 1)
        self.assertEquals(email_analysis.mail_to[0], '<lulu.zingzing@company.com>')
        self.assertIsNone(email_analysis.reply_to)
        self.assertEquals(email_analysis.subject, 'INVOICE PDL-06-38776')
        self.assertEquals(email_analysis.decoded_subject, email_analysis.subject)
        self.assertEquals(email_analysis.message_id, '<13268020124593518925.93733CB7019D1C46@company.com>')
        self.assertIsNone(email_analysis.originating_ip, None)
        self.assertTrue(isinstance(email_analysis.received, list))
        self.assertEquals(len(email_analysis.received), 7)
        self.assertTrue(isinstance(email_analysis.headers, list))
        self.assertTrue(isinstance(email_analysis.log_entry, dict))
        self.assertIsNone(email_analysis.x_mailer)
        self.assertIsNotNone(email_analysis.body)
        self.assertIsInstance(email_analysis.attachments, list)
        self.assertEquals(len(email_analysis.attachments), 0)

    # tests the whitelisting capabilities
    def test_whitelisting_000_mail_from(self):

        import saq
        whitelist_path = os.path.join(saq.TEMP_DIR, 'brotex.whitelist')
        saq.CONFIG['analysis_module_email_analyzer']['whitelist_path'] = whitelist_path

        if os.path.exists(whitelist_path):
            os.remove(whitelist_path)

        with open(whitelist_path, 'w') as fp:
            fp.write('smtp_from:ap@someothercompany.com')

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'o365_journaled.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertFalse(email_analysis)

    # tests the whitelisting capabilities
    def test_whitelisting_001_mail_to(self):

        import saq
        whitelist_path = os.path.join('var', 'tmp', 'brotex.whitelist')
        saq.CONFIG['analysis_module_email_analyzer']['whitelist_path'] = whitelist_path

        if os.path.exists(whitelist_path):
            os.remove(whitelist_path)

        with open(whitelist_path, 'w') as fp:
            fp.write('smtp_to:lulu.zingzing@company.com')

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'o365_journaled.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertFalse(email_analysis)

    # XXX move this to the site-specific test
    @unittest.skip
    def test_live_browser_no_render(self):

        # we usually render HTML attachments to emails
        # but not if it has a tag of "no_render" assigned by a yara rule

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'phish_me.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_email_analyzer', 'test_groups')
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        self.assertTrue(file_observable.has_tag('no_render'))
        from saq.modules.url import LiveBrowserAnalysis
        self.assertFalse(file_observable.get_analysis(LiveBrowserAnalysis))
