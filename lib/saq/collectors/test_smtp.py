# vim: sw=4:ts=4:et:cc=120

import logging
import os, os.path
import shutil
import tempfile

from subprocess import Popen

import saq
from saq.collectors.test_bro import BroBaseTestCase
from saq.collectors.smtp import BroSMTPStreamCollector
from saq.test import *

class BroSMTPBaseTestCase(BroBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # change the bro smtp dir
        saq.CONFIG['bro']['smtp_dir'] = 'var/bro/smtp_unittest'

        self.bro_smtp_dir = saq.CONFIG['bro']['smtp_dir']

        if os.path.exists(self.bro_smtp_dir):
            shutil.rmtree(self.bro_smtp_dir)

        os.mkdir(self.bro_smtp_dir)

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
        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'smtp.pcap'))

        self.start_api_server()

        engine = TestEngine()
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
