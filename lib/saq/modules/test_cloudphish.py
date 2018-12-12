# vim: sw=4:ts=4:et

import os, os.path
import shutil
import subprocess
import threading
import logging

from subprocess import Popen, PIPE

import saq, saq.test
from saq.constants import *
from saq.database import get_db_connection
from saq.test import *

import requests

TEST_URL = 'http://localhost:8080/Payment_Advice.pdf'

class TestCase(ACEModuleTestCase):

    def test_cloudphish_server_rotation(self):
        from saq.modules.cloudphish import CloudphishAnalyzer
        saq.CONFIG['analysis_module_cloudphish']['cloudphish.1'] = 'cloudphish1.local:5000'
        saq.CONFIG['analysis_module_cloudphish']['cloudphish.2'] = 'cloudphish2.local:5000'

        m = CloudphishAnalyzer('analysis_module_cloudphish')
        self.assertEquals(m.get_cloudphish_server(), 'cloudphish1.local:5000')
        self.assertEquals(m.get_cloudphish_server(), 'cloudphish2.local:5000')
        self.assertEquals(m.get_cloudphish_server(), 'cloudphish1.local:5000')
    
    def test_submit(self):

        self.start_api_server()

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, TEST_URL)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        cloudphish_engine = TestEngine()
        cloudphish_engine.enable_module('analysis_module_crawlphish')
        cloudphish_engine.clear_analysis_pools()
        cloudphish_engine.add_analysis_pool('cloudphish', 1)
        cloudphish_engine.local_analysis_modes.append('cloudphish')
        cloudphish_engine.start()

        analysis_engine = TestEngine()
        analysis_engine.enable_module('analysis_module_cloudphish')
        analysis_engine.clear_analysis_pools()
        analysis_engine.add_analysis_pool('analysis', 1)
        analysis_engine.local_analysis_modes.append('analysis')
        analysis_engine.start()

        # see the cloudphish analysis go into delayed analysis
        import time
        time.sleep(10000)
    
    def test_cloudphish_000_invalid_scheme(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_cloudphish')
        self.start_engine(engine)

        root = create_root_analysis()
        url = root.add_observable(F_URL, 'mailto:john@smith.com')
        self.assertIsNotNone(url)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        self.assertEquals(log_count('is not a supported scheme for cloudphish'), 1)

    def test_cloudphish_001_invalid_fqdn(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_cloudphish')
        self.start_engine(engine)

        root = create_root_analysis()
        url = root.add_observable(F_URL, 'http://invalid_domain/hello_world')
        self.assertIsNotNone(url)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        engine.wait()

        self.assertEquals(log_count('ignoring invalid FQDN'), 1)

    def test_cloudphish_002_cached_entry(self):
        local_cache_dir = saq.CONFIG['analysis_module_cloudphish']['local_cache_dir']
        shutil.rmtree(local_cache_dir)
        os.makedirs(local_cache_dir)

        self.start_gui_server()
        self.start_cloudphish_server()

        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_cloudphish')
        self.start_engine(engine)

        root = create_root_analysis()
        url = root.add_observable(F_URL, 'http://www.valvoline.com/')
        self.assertIsNotNone(url)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()

        engine.queue_work_item(root.storage_dir)

        # wait for analysis to complete
        wait_for_log_count('executing post analysis on RootAnalysis({})'.format(root.uuid), 1)

        # we should NOT see cache results getting used here
        self.assertEquals(log_count('using local cache results for'), 0)

        # we should have a single cache entry
        p = Popen(['find', local_cache_dir, '-type', 'f'], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        _stdout, _stderr = p.communicate()
        self.assertEquals(len(_stdout.strip().split('\n')), 1)

        from saq.cloudphish import hash_url
        sha2 = hash_url(url.value)
        target_path = os.path.join(local_cache_dir, sha2[:2], sha2)
        self.assertTrue(os.path.exists(target_path))

        # now the second time we analyze we should see the cache get used
        root = create_root_analysis()
        url = root.add_observable(F_URL, 'http://www.valvoline.com/')
        self.assertIsNotNone(url)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()

        engine.queue_work_item(root.storage_dir)

        # wait for analysis to complete
        wait_for_log_count('executing post analysis on RootAnalysis({})'.format(root.uuid), 2)

        # we should see this now
        self.assertEquals(log_count('using local cache results for'), 1)

        engine.queue_work_item(TerminatingMarker())
        engine.wait()
