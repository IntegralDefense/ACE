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
from saq.engine.cloudphish import CloudPhishEngine
from saq.engine.test_engine import AnalysisEngine, TerminatingMarker

import requests

class CloudphishAnaysisModuleTestCase(ACEModuleTestCase):
    def setUp(self):
        ACEModuleTestCase.setUp(self)

        # clear cloudphish cache
        if os.path.isdir(saq.CONFIG['analysis_module_cloudphish']['local_cache_dir']):
            shutil.rmtree(saq.CONFIG['analysis_module_cloudphish']['local_cache_dir'])
            os.makedirs(saq.CONFIG['analysis_module_cloudphish']['local_cache_dir'])

    def tearDown(self):
        ACEModuleTestCase.tearDown(self)
    
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
