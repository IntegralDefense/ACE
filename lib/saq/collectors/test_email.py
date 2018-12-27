# vim: sw=4:ts=4:et:cc=120

import logging
import os, os.path
import re
import shutil

from subprocess import Popen, PIPE

import saq
from saq.collectors.email import EmailCollector
from saq.collectors.test import CollectorBaseTestCase
from saq.database import use_db
from saq.test import *

class EmailCollectorBaseTestCase(CollectorBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # use a different directory for incoming emails
        self.email_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['email']['email_dir'])

        # clear it out
        if os.path.isdir(self.email_dir):
            shutil.rmtree(self.email_dir)
        os.makedirs(self.email_dir)

        # get the path to the amc_mda
        self.amc_mda_path = os.path.join(saq.SAQ_HOME, 'bin', 'amc_mda')

    def submit_email(self, email_path):
        p = Popen(['python3', self.amc_mda_path, '--data-dir', self.email_dir], stdin=PIPE)
        with open(email_path, 'rb') as fp:
            shutil.copyfileobj(fp, p.stdin)
        p.stdin.close()
        p.wait()
    

class EmailCollectorTestCase(EmailCollectorBaseTestCase):
    def test_startup(self):
        collector = EmailCollector()
        collector.load_groups()
        collector.start()

        wait_for_log_count('no work available', 1, 5)
        collector.stop()
        collector.wait()

    def test_single_email(self):
        self.submit_email(os.path.join(saq.SAQ_HOME, 'test_data', 'emails', 'pdf_attachment.email.rfc822'))

        collector = EmailCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found email', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', 1, 5)

        collector.stop()
        collector.wait()

        # the email dir should be empty
        self.assertEquals(len(os.listdir(self.email_dir)), 0)

    def test_multiple_emails(self):
        test_email_dir = os.path.join(saq.SAQ_HOME, 'test_data', 'emails')
        email_count = 0
        for email_file in os.listdir(test_email_dir):
            email_count += 1
            self.submit_email(os.path.join(test_email_dir, email_file))

        collector = EmailCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found email', email_count, 5)
        wait_for_log_count('copied file from', email_count, 5)
        wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', email_count, 5)

        collector.stop()
        collector.wait()

    def test_blacklist(self):
        blacklist_yara_rule_path = os.path.join(saq.TEMP_DIR, 'blacklist.yar')
        with open(blacklist_yara_rule_path, 'w') as fp:
            fp.write("""
rule blacklist : blacklist {
    strings:
        $a = "Message-ID: <80f00181-6bb3-45ee-a16d-b2b25df6cf1e@journal.report.generator>"
    condition:
        any of them
}""")

        self.submit_email(os.path.join(saq.SAQ_HOME, 'test_data', 'emails', 'pdf_attachment.email.rfc822'))

        collector = EmailCollector(blacklist_yara_rule_path=blacklist_yara_rule_path)
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('matched blacklist rule', 1, 5)

        collector.stop()
        collector.wait()

        # the file that we matched should be deleted
        entry = search_log('matched blacklist rule')
        self.assertEquals(len(entry), 1)
        entry = entry[0]
        regex = re.compile(r'^(.+) matched blacklist rule .+')
        m = regex.match(entry.getMessage())
        self.assertIsNotNone(m)
        file_path = m.group(1)
        self.assertFalse(os.path.exists(file_path))

    @use_db
    def test_assignment(self, db, c):
        assignment_yara_rule_path = os.path.join(saq.TEMP_DIR, 'assignment.yar')
        with open(assignment_yara_rule_path, 'w') as fp:
            fp.write("""
rule assignment: unittest {
    strings:
        $a = "Delivered-To: company@mail.phish.solutions"
    condition:
        any of them
}""")
        self.submit_email(os.path.join(saq.SAQ_HOME, 'test_data', 'emails', 'pdf_attachment.email.rfc822'))

        # we add another node group for testing purposes
        saq.CONFIG['collection_group_qa'] = {}
        saq.CONFIG['collection_group_qa']['coverage'] = '100'
        saq.CONFIG['collection_group_qa']['full_delivery'] = 'no'
        saq.CONFIG['collection_group_qa']['database'] = 'ace_qa'

        collector = EmailCollector(assignment_yara_rule_path=assignment_yara_rule_path)
        collector.load_groups()
        collector.initialize()
        collector.execute()

        # look for all the expected log entries
        wait_for_log_count('found email', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', 1, 5)
        
        # see that it got assigned
        wait_for_log_count('assigning email', 1, 5)

        # after this is executed we should have an assignment to unittest but not qa
        c.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                     WHERE work_distribution_groups.name = %s""", ('unittest',))
        self.assertEquals(c.fetchone()[0], 1)

        c.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                     WHERE work_distribution_groups.name = %s""", ('qa',))
        self.assertEquals(c.fetchone()[0], 0)

class EmailCollectorEngineTestCase(EmailCollectorBaseTestCase, ACEEngineTestCase):
    def test_complete_processing(self):
        self.submit_email(os.path.join(saq.SAQ_HOME, 'test_data', 'emails', 'pdf_attachment.email.rfc822'))

        self.start_api_server()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type')
        engine.enable_module('analysis_module_email_analyzer')
        engine.start()

        collector = EmailCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found email', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        # email analysis module should generate this log entry
        wait_for_log_count('parsing email file', 1, 5)
        wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', 1, 5)
        wait_for_log_count('completed analysis RootAnalysis', 1, 20)

        engine.controlled_stop()
        engine.wait()

        collector.stop()
        collector.wait()

    def test_multiple_emails_complete_processing(self):
        test_email_dir = os.path.join(saq.SAQ_HOME, 'test_data', 'emails')
        email_count = 0
        for email_file in os.listdir(test_email_dir):
            email_count += 1
            self.submit_email(os.path.join(test_email_dir, email_file))

        self.start_api_server()

        engine = TestEngine()
        engine.start()

        collector = EmailCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found email', email_count, 5)
        wait_for_log_count('copied file from', email_count, 5)
        wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', email_count, 5)
        wait_for_log_count('completed analysis RootAnalysis', email_count, 20)

        engine.controlled_stop()
        engine.wait()

        collector.stop()
        collector.wait()
