# vim: sw=4:ts=4:et:cc=120

import logging
import os, os.path
import re
import shutil
import tempfile

from subprocess import Popen

import saq
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.collectors.test_bro import BroBaseTestCase
from saq.collectors.smtp import BroSMTPStreamCollector
from saq.test import *
from saq.util import storage_dir_from_uuid

class BroSMTPBaseTestCase(BroBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.bro_smtp_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['bro']['smtp_dir'])

        if os.path.exists(self.bro_smtp_dir):
            shutil.rmtree(self.bro_smtp_dir)

        os.makedirs(self.bro_smtp_dir)

class BroSMTPTestCase(BroSMTPBaseTestCase):
    def test_startup(self):
        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.start()

        wait_for_log_count('no work available', 1, 5)
        collector.stop()
        collector.wait()

    def test_processing(self):
        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'smtp.pcap'))

        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found smtp stream', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        wait_for_log_count('scheduled BRO SMTP Scanner Detection -', 1, 5)

        collector.stop()
        collector.wait()

class BroSMTPEngineTestCase(BroSMTPBaseTestCase, ACEEngineTestCase):
    def test_complete_processing(self):
        from saq.modules.email import BroSMTPStreamAnalysis

        # disable cleanup so we can check the results after
        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'smtp.pcap'))

        self.start_api_server()

        engine = TestEngine()
        engine.enable_module('analysis_module_bro_smtp_analyzer', 'email')
        engine.start()

        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found smtp stream', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        wait_for_log_count('scheduled BRO SMTP Scanner Detection -', 1, 5)
        wait_for_log_count('completed analysis RootAnalysis', 1, 20)

        engine.controlled_stop()
        engine.wait()

        collector.stop()
        collector.wait()

        # get the uuids returned by the api calls
        r = re.compile(r' uuid ([a-f0-9-]+)')
        for result in search_log('submit remote'):
            m = r.search(result.getMessage())
            self.assertIsNotNone(m)
            uuid = m.group(1)

            with self.subTest(uuid=uuid):

                root = RootAnalysis(uuid=uuid, storage_dir=storage_dir_from_uuid(uuid))
                root.load()

                # find the SMTP stream
                file_observable = root.find_observable(lambda x: x.type == F_FILE)
                self.assertTrue(bool(file_observable))
                
                # ensure it has the required directives
                self.assertTrue(file_observable.has_directive(DIRECTIVE_ORIGINAL_SMTP))
                self.assertTrue(file_observable.has_directive(DIRECTIVE_NO_SCAN))

                # ensure the bro smtp analyzer ran on it
                smtp_analysis = file_observable.get_analysis(BroSMTPStreamAnalysis)
                self.assertIsNotNone(smtp_analysis)

                # ensure it extracted a file
                email_observable = smtp_analysis.find_observable(lambda x: x.type == F_FILE)
                self.assertTrue(bool(email_observable))

                # and then ensure that it was treated as an email
                #import pdb; pdb.set_trace()
                self.assertTrue(email_observable.has_directive(DIRECTIVE_NO_SCAN))
                self.assertTrue(email_observable.has_directive(DIRECTIVE_ORIGINAL_EMAIL))
                self.assertTrue(email_observable.has_directive(DIRECTIVE_ARCHIVE))
