# vim: sw=4:ts=4:et:cc=120

import logging
import os, os.path
import shutil
import tempfile

from subprocess import Popen

import saq
from saq.collectors.test_bro import BroBaseTestCase
from saq.collectors.http import BroHTTPStreamCollector
from saq.test import *

class BroHTTPBaseTestCase(BroBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # change the bro http dir
        saq.CONFIG['bro']['http_dir'] = 'var/bro/http_unittest'

        self.bro_http_dir = saq.CONFIG['bro']['http_dir']

        if os.path.exists(self.bro_http_dir):
            shutil.rmtree(self.bro_http_dir)

        os.mkdir(self.bro_http_dir)

class BroHTTPTestCase(BroHTTPBaseTestCase):
    def test_startup(self):
        collector = BroHTTPStreamCollector()
        collector.load_groups()
        collector.start()

        wait_for_log_count('no work available', 1, 5)
        collector.stop()
        collector.wait()

    def test_processing(self):
        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        collector = BroHTTPStreamCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found http stream', 1, 5)
        wait_for_log_count('copied file from', 4, 5)
        wait_for_log_count('scheduled BRO HTTP Scanner Detection -', 1, 5)

        collector.stop()
        collector.wait()

class BroHTTPEngineTestCase(BroHTTPBaseTestCase, ACEEngineTestCase):
    def test_complete_processing(self):
        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        self.start_api_server()

        engine = TestEngine()
        engine.start()

        collector = BroHTTPStreamCollector()
        collector.load_groups()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found http stream', 1, 5)
        wait_for_log_count('copied file from', 4, 5)
        wait_for_log_count('scheduled BRO HTTP Scanner Detection -', 1, 5)
        wait_for_log_count('completed analysis RootAnalysis', 1, 20)

        engine.controlled_stop()
        engine.wait()

        collector.stop()
        collector.wait()
