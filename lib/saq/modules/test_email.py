# vim: sw=4:ts=4:et

import logging
import os, os.path
import shutil
import socket
import uuid
import unittest

import saq, saq.test
from saq.constants import *
from saq.database import get_db_connection
from saq.engine.test_engine import AnalysisEngine, TerminatingMarker
from saq.test import *

class EmailModuleTestCase(ACEModuleTestCase):
    def test_email_000_splunk_logging(self):

        # clear splunk logging directory
        splunk_log_dir = os.path.join(saq.CONFIG['splunk_logging']['splunk_log_dir'], 'smtp')
        if os.path.isdir(splunk_log_dir):
            shutil.rmtree(splunk_log_dir)
            os.mkdir(splunk_log_dir)

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        engine.enable_module('analysis_module_email_logger')
        engine.enable_module('analysis_module_url_extraction')
        self.start_engine(engine)

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        # we should expect three files in this directory now
        splunk_files = os.listdir(splunk_log_dir)
        self.assertEquals(len(splunk_files), 3)
        
        smtp_file = None
        url_file = None

        for _file in splunk_files:
            if _file.startswith('smtp-'):
                smtp_file = os.path.join(splunk_log_dir, _file)
            elif _file.startswith('url-'):
                url_file = os.path.join(splunk_log_dir, _file)

        self.assertIsNotNone(smtp_file)
        self.assertIsNotNone(url_file)

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

    @protect_production
    def test_email_001_archive(self):

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

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_email_analyzer')
        engine.enable_module('analysis_module_email_archiver')
        engine.enable_module('analysis_module_url_extraction')
        self.start_engine(engine)

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        # there should be a single entry in the archive
        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("SELECT archive_id FROM archive")
            row = c.fetchone()
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

    @protect_production
    def test_email_002_archive(self):

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

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_email_analyzer')
        engine.enable_module('analysis_module_email_archiver')
        engine.enable_module('analysis_module_url_extraction')
        engine.enable_module('analysis_module_pdf_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'pdf_attachment.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
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

    def test_email_003_email_pivot(self):

        # process the email first -- we'll find it when we pivot

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_email_analyzer')
        engine.enable_module('analysis_module_email_archiver')
        engine.enable_module('analysis_module_url_extraction')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        saq.load_configuration()

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_url_email_pivot_analyzer')
        self.start_engine(engine)

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

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
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

    def test_email_004_email_pivot_excessive_emails(self):

        # process the email first -- we'll find it when we pivot

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_file_hash_analyzer')
        engine.enable_module('analysis_module_email_analyzer')
        engine.enable_module('analysis_module_email_archiver')
        engine.enable_module('analysis_module_url_extraction')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        file_observable.add_directive(DIRECTIVE_ARCHIVE)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        saq.load_configuration()
        # force this to exceed the limit
        saq.CONFIG['analysis_module_url_email_pivot_analyzer']['result_limit'] = '0'

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_url_email_pivot_analyzer')
        self.start_engine(engine)

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

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        root.load()
        url_observable = root.get_observable(url_observable.id)
        from saq.modules.email import URLEmailPivotAnalysis_v2
        analysis = url_observable.get_analysis(URLEmailPivotAnalysis_v2)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.count, 1)
        # this should not have the details since it exceeded the limit
        self.assertIsNone(analysis.emails)

    def test_email_005_message_id(self):

        # make sure we extract the correct message-id
        # this test email has an attachment that contains a message-id
        # we need to make sure we do not extract that one as the message-id observable

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'extra_message_id.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
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

    def test_email_006_basic_email_parsing(self):

        # parse a basic email message
        
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
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
        
    def test_email_007_o365_journal_email_parsing(self):

        # parse an office365 journaled message
        
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'o365_journaled.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
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
    def test_email_008_whitelisting_000_mail_from(self):

        import saq
        whitelist_path = os.path.join('var', 'tmp', 'brotex.whitelist')
        saq.CONFIG['analysis_module_email_analyzer']['whitelist_path'] = whitelist_path

        if os.path.exists(whitelist_path):
            os.remove(whitelist_path)

        with open(whitelist_path, 'w') as fp:
            fp.write('smtp_from:ap@someothercompany.com')

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'o365_journaled.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()
        
        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertFalse(email_analysis)

    # tests the whitelisting capabilities
    def test_email_008_whitelisting_001_mail_to(self):

        import saq
        whitelist_path = os.path.join('var', 'tmp', 'brotex.whitelist')
        saq.CONFIG['analysis_module_email_analyzer']['whitelist_path'] = whitelist_path

        if os.path.exists(whitelist_path):
            os.remove(whitelist_path)

        with open(whitelist_path, 'w') as fp:
            fp.write('smtp_to:lulu.zingzing@company.com')

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'o365_journaled.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()
        
        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertFalse(email_analysis)

    # XXX move this to the site-specific test
    @unittest.skip
    def test_email_009_live_browser_no_render(self):

        # we usually render HTML attachments to emails
        # but not if it has a tag of "no_render" assigned by a yara rule
        
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        engine.enable_module('analysis_module_yara_scanner_v3_4')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()), alert_type='mailbox')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'phish_me.email.rfc822'), 
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()
        
        root.load()
        from saq.modules.email import EmailAnalysis
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        self.assertTrue(file_observable.has_tag('no_render'))
        from saq.modules.url import LiveBrowserAnalysis
        self.assertFalse(file_observable.get_analysis(LiveBrowserAnalysis))
