# vim: sw=4:ts=4:et:cc=120

import logging
import os, os.path
import shutil
import tempfile

from subprocess import Popen

import saq
from saq.collectors.http import BroHTTPStreamCollector
from saq.collectors.test import CollectorBaseTestCase
from saq.test import *

class BroHTTPBaseTestCase(CollectorBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # change the bro http dir
        saq.CONFIG['bro']['http_dir'] = 'var/bro/http_unittest'

        self.bro_http_dir = saq.CONFIG['bro']['http_dir']
        self.bro_work_dir = tempfile.mkdtemp(dir=os.path.join(saq.SAQ_HOME, 'var', 'tmp'))

        if os.path.exists(self.bro_http_dir):
            shutil.rmtree(self.bro_http_dir)
            os.mkdir(self.bro_http_dir)

        os.mkdir(os.path.join(self.bro_work_dir, 'ace'))
        with open(os.path.join(self.bro_work_dir, 'ace', 'ace_local.bro'), 'w') as fp:
            Popen(['sed', '-e', 's:bro/http";:bro/http_unittest";:', os.path.join(saq.SAQ_HOME, 'bro', 'ace_local.bro')], stdout=fp).wait()
        shutil.copy(os.path.join(saq.SAQ_HOME, 'bro', 'ace_http.bro'), os.path.join(self.bro_work_dir, 'ace', 'ace_http.bro'))

        self.bro_bin_path = '/opt/bro/bin/bro'

    def tearDown(self, *args, **kwargs):
        super().tearDown(*args, **kwargs)

        if os.path.isdir(self.bro_work_dir):
            shutil.rmtree(self.bro_work_dir)

    def process_pcap(self, pcap_path):
        # have bro process this pcap file of a download of a PDF file
        logging.debug("processing pcap...")
        Popen([self.bro_bin_path, '-C', '-r', pcap_path, os.path.join('ace', 'ace_http.bro')], cwd=self.bro_work_dir).wait()

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
