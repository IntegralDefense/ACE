# vim: sw=4:ts=4:et

import os, os.path
import shutil
import subprocess
import threading
import logging
import unittest

from subprocess import Popen, PIPE

import saq, saq.test
from api.cloudphish.test import CloudphishTestCase
from saq.analysis import RootAnalysis, Analysis
from saq.cloudphish import *
from saq.constants import *
from saq.database import get_db_connection, use_db
from saq.test import *
from saq.util import *

import requests

TEST_URL = 'http://localhost:8080/Payment_Advice.pdf'

class TestCase(CloudphishTestCase, ACEModuleTestCase):

    def test_cloudphish_server_rotation(self):
        from saq.modules.cloudphish import CloudphishAnalyzer
        saq.CONFIG['analysis_module_cloudphish']['cloudphish.1'] = 'cloudphish1.local:5000'
        saq.CONFIG['analysis_module_cloudphish']['cloudphish.2'] = 'cloudphish2.local:5000'

        m = CloudphishAnalyzer('analysis_module_cloudphish')
        self.assertEquals(m.get_cloudphish_server(), 'cloudphish1.local:5000')
        self.assertEquals(m.get_cloudphish_server(), 'cloudphish2.local:5000')
        self.assertEquals(m.get_cloudphish_server(), 'cloudphish1.local:5000')
    
    def test_submit(self):

        # disable cleaup for analysis mode analysis
        saq.CONFIG['analysis_mode_analysis']['cleanup'] = 'no'
        saq.CONFIG['analysis_mode_cloudphish']['cleanup'] = 'no'

        self.start_api_server()

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, TEST_URL)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={ANALYSIS_MODE_ANALYSIS: 1,
                                            ANALYSIS_MODE_CLOUDPHISH: 1}, 
                            local_analysis_modes=[ANALYSIS_MODE_ANALYSIS,
                                                  ANALYSIS_MODE_CLOUDPHISH])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)

        engine.start()

        # wait for delayed analysis to be added
        wait_for_log_count('added delayed analysis', 1, 5)
        # and then wait for analysis to complete
        wait_for_log_count('completed analysis RootAnalysis', 1, 5)

        # watch for the download request by cloudphish
        wait_for_log_count('requesting url', 1, 5)
        # watch for crawlphish to finish
        wait_for_log_count('analysis CrawlphishAnalysisV2 is completed', 1, 5)

        # the cloudphish request analyzer should see the downloaded file
        wait_for_log_count('found downloaded file', 1, 5)
        # and should update the database
        wait_for_log_count('executing cloudphish update', 1, 5)

        # should see cloudphish module complete
        wait_for_log_count('analysis CloudphishAnalysis is completed', 1, 10)

        # we should a work request for the original request and one for the cloudphish request
        wait_for_log_count('got work item RootAnalysis', 2, 5)
        
        # and we should see at least one request to handle a delayed analysis request
        wait_for_log_count('got work item DelayedAnalysisRequest', 1, 5)

        engine.controlled_stop()
        engine.wait()

        # check the results
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        url = root.get_observable(url.id)
        self.assertIsNotNone(url)

        # this url should only have a single analysis object attached to it (the cloudphish analysis)
        self.assertEquals(len(url.analysis), 1)

        from saq.modules.cloudphish import CloudphishAnalysis
        cloudphish_analysis = url.get_analysis(CloudphishAnalysis)
        self.assertIsNotNone(cloudphish_analysis)
        for key in [ KEY_ANALYSIS_RESULT, KEY_DETAILS, KEY_FILE_NAME, KEY_HTTP_MESSAGE, KEY_HTTP_RESULT, KEY_LOCATION, 
                     KEY_RESULT, KEY_SHA256_CONTENT, KEY_SHA256_URL, KEY_STATUS, KEY_UUID ]:
            with self.subTest(key=key):
                self.assertTrue(key in cloudphish_analysis.query_result)

        q = cloudphish_analysis.query_result
        self.assertEquals(q[KEY_ANALYSIS_RESULT], SCAN_RESULT_CLEAR)

        for key in [ KEY_DETAILS_CONTEXT, KEY_DETAILS_SHA256_URL, KEY_DETAILS_URL ]:
            with self.subTest(key=key):
                self.assertTrue(key in q[KEY_DETAILS])

        # this is what we should have for context
        self.assertEquals(q[KEY_DETAILS][KEY_DETAILS_CONTEXT]['c'], root.uuid)
        self.assertEquals(q[KEY_DETAILS][KEY_DETAILS_CONTEXT]['ignore_filters'], '0')
        self.assertEquals(q[KEY_DETAILS][KEY_DETAILS_CONTEXT]['reprocess'], '0')

        self.assertEquals(q[KEY_DETAILS][KEY_DETAILS_SHA256_URL].upper(), 'B009F8821B162674B819A2365B07A536645A42657E75BB3996C8B6127E993806')
        self.assertEquals(q[KEY_DETAILS][KEY_DETAILS_URL], TEST_URL)
        
        self.assertEquals(q[KEY_FILE_NAME], 'Payment_Advice.pdf')
        self.assertEquals(q[KEY_HTTP_MESSAGE], 'OK')
        self.assertEquals(q[KEY_HTTP_RESULT], 200)
        self.assertEquals(q[KEY_LOCATION], saq.SAQ_NODE)
        self.assertEquals(q[KEY_RESULT], RESULT_OK)
        self.assertEquals(q[KEY_SHA256_CONTENT].upper(), 'FA13C652534F9207BEEC811A50948860F5B3194AEAE686FCDECAC645FAE65D15')
        self.assertEquals(q[KEY_SHA256_URL].upper(), 'B009F8821B162674B819A2365B07A536645A42657E75BB3996C8B6127E993806')
        self.assertEquals(q[KEY_STATUS], STATUS_ANALYZED)
        self.assertIsNotNone(q[KEY_UUID])

        # these properties should match the query_result keys-value pairs
        self.assertEquals(cloudphish_analysis.result, q[KEY_RESULT])
        self.assertEquals(cloudphish_analysis.result_details, q[KEY_DETAILS])
        self.assertEquals(cloudphish_analysis.status, q[KEY_STATUS])
        self.assertEquals(cloudphish_analysis.analysis_result, q[KEY_ANALYSIS_RESULT])
        self.assertEquals(cloudphish_analysis.http_result, q[KEY_HTTP_RESULT])
        self.assertEquals(cloudphish_analysis.http_message, q[KEY_HTTP_MESSAGE])
        self.assertEquals(cloudphish_analysis.sha256_content, q[KEY_SHA256_CONTENT])
        self.assertEquals(cloudphish_analysis.location, q[KEY_LOCATION])
        self.assertEquals(cloudphish_analysis.file_name, q[KEY_FILE_NAME])

    def test_submit_alert(self):

        # disable cleaup for analysis mode analysis
        saq.CONFIG['analysis_mode_analysis']['cleanup'] = 'no'

        self.start_api_server()

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, TEST_URL)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={ANALYSIS_MODE_ANALYSIS: 1,
                                            ANALYSIS_MODE_CLOUDPHISH: 1}, 
                            local_analysis_modes=[ANALYSIS_MODE_ANALYSIS,
                                                  ANALYSIS_MODE_CLOUDPHISH])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_CLOUDPHISH)

        engine.start()

        # should see cloudphish module complete
        wait_for_log_count('analysis CloudphishAnalysis is completed', 1, 10)

        engine.controlled_stop()
        engine.wait()

        # check the results
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()
        url = root.get_observable(url.id)
        self.assertIsNotNone(url)

        # this url should now have 3 analysis objects attached to it (cloudphish, crawlphish and forced detection)
        self.assertEquals(len(url.analysis), 3)

        from saq.modules.cloudphish import CloudphishAnalysis
        cloudphish_analysis = url.get_analysis(CloudphishAnalysis)
        self.assertIsNotNone(cloudphish_analysis)
        self.assertEquals(cloudphish_analysis.analysis_result, SCAN_RESULT_ALERT)

        from saq.modules.url import CrawlphishAnalysisV2
        crawlphish_analysis = url.get_analysis(CrawlphishAnalysisV2)
        self.assertIsNotNone(crawlphish_analysis)

    @use_db
    def test_submit_double_alert(self, db, c):

        # in this scenario we alert both with the original submission
        # and with the cloudphish submission

        self.start_api_server()

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, TEST_URL)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=[ANALYSIS_MODE_ANALYSIS,
                                                  ANALYSIS_MODE_CLOUDPHISH,
                                                  ANALYSIS_MODE_CORRELATION])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_detection', (ANALYSIS_MODE_CLOUDPHISH, ANALYSIS_MODE_ANALYSIS))

        engine.start()

        # should see cloudphish module complete
        wait_for_log_count('analysis CloudphishAnalysis is completed', 1, 10)

        engine.controlled_stop()
        engine.wait()

        # check the results
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()
        url = root.get_observable(url.id)
        self.assertIsNotNone(url)

        # this url should now have 3 analysis objects attached to it (cloudphish, crawlphish and forced detection)
        self.assertEquals(len(url.analysis), 3)

        from saq.modules.cloudphish import CloudphishAnalysis
        cloudphish_analysis = url.get_analysis(CloudphishAnalysis)
        self.assertIsNotNone(cloudphish_analysis)
        self.assertEquals(cloudphish_analysis.analysis_result, SCAN_RESULT_ALERT)

        from saq.modules.url import CrawlphishAnalysisV2
        crawlphish_analysis = url.get_analysis(CrawlphishAnalysisV2)
        self.assertIsNotNone(crawlphish_analysis)

        # there should be two alerts generated in the database
        c.execute("SELECT COUNT(*) FROM alerts")
        self.assertEquals(c.fetchone()[0], 2)

        # the cloudphish alert should have a reference back to the original alert
        self.assertEquals(cloudphish_analysis.context['c'], root.uuid)

    def test_submit_invalid_scheme(self):
        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, 'mailto:john@smith.com')
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={ANALYSIS_MODE_ANALYSIS: 1,
                                            ANALYSIS_MODE_CLOUDPHISH: 1}, 
                            local_analysis_modes=[ANALYSIS_MODE_ANALYSIS,
                                                  ANALYSIS_MODE_CLOUDPHISH])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)

        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('is not a supported scheme for cloudphish'), 1)

    def test_submit_invalid_url(self):
        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        # clearly not a valid url
        # can't even add it
        url = root.add_observable(F_URL, 'http://qua\x00dle/\\\x90\x90\x90')
        self.assertIsNone(url)

    def test_submit_forced_download(self):
        # disable cleaup for analysis mode analysis
        saq.CONFIG['analysis_mode_analysis']['cleanup'] = 'no'

        self.start_api_server()

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, TEST_URL)
        url.add_directive(DIRECTIVE_CRAWL)
        url.add_directive(DIRECTIVE_FORCE_DOWNLOAD)
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={ANALYSIS_MODE_ANALYSIS: 1,
                                            ANALYSIS_MODE_CLOUDPHISH: 1}, 
                            local_analysis_modes=[ANALYSIS_MODE_ANALYSIS,
                                                  ANALYSIS_MODE_CLOUDPHISH])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)

        engine.start()

        # should see cloudphish module complete
        wait_for_log_count('analysis CloudphishAnalysis is completed', 1, 10)

        engine.controlled_stop()
        engine.wait()

        # check the results
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        url = root.get_observable(url.id)
        self.assertIsNotNone(url)

        # should only have 1 analysis attached to the url
        self.assertEquals(len(url.analysis), 1)

        from saq.modules.cloudphish import CloudphishAnalysis
        cloudphish_analysis = url.get_analysis(CloudphishAnalysis)
        self.assertIsNotNone(cloudphish_analysis)
        self.assertEquals(cloudphish_analysis.analysis_result, SCAN_RESULT_CLEAR)

        # however there should be a file attached
        self.assertEquals(len(cloudphish_analysis.observables), 1)
        self.assertEquals(cloudphish_analysis.observables[0].type, F_FILE)
        self.assertEquals(cloudphish_analysis.observables[0].value, 'Payment_Advice.pdf')
        self.assertTrue(os.path.exists(os.path.join(root.storage_dir, cloudphish_analysis.observables[0].value)))

    @use_db
    def test_submit_timeout_with_alert(self, db, c):

        # any cloudphish submission we make can turn into an alert
        # here we test a cloudphish submission that quickly times out
        # followed by cloudphish alerting on the submission

        # set the timeouts really low
        saq.CONFIG['analysis_module_cloudphish']['frequency'] = '1'
        saq.CONFIG['analysis_module_cloudphish']['query_timeout'] = '1'

        # disable cleaup for analysis mode analysis
        saq.CONFIG['analysis_mode_analysis']['cleanup'] = 'no'
        
        self.start_api_server()

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url = root.add_observable(F_URL, TEST_URL)
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={},
                            local_analysis_modes=[ANALYSIS_MODE_ANALYSIS,
                                                  ANALYSIS_MODE_CLOUDPHISH,
                                                  ANALYSIS_MODE_CORRELATION])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_cloudphish_delayed_test', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_CLOUDPHISH)

        engine.start()

        # watch for the original analysis to time out
        wait_for_log_count('has timed out', 1, 10)

        # we should see cloudphish eventually complete and alert though
        engine.controlled_stop()
        engine.wait()

        # check the results
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        url = root.get_observable(url.id)
        self.assertIsNotNone(url)

        # should see an error here
        from saq.modules.cloudphish import CloudphishAnalysis
        cloudphish_analysis = url.get_analysis(CloudphishAnalysis)
        self.assertIsNotNone(cloudphish_analysis)
        self.assertEquals(cloudphish_analysis.result, SCAN_RESULT_ERROR)

        # however we should have an alert generated
        c.execute("SELECT COUNT(*) FROM alerts")
        self.assertEquals(c.fetchone()[0], 1)

    def test_request_limit(self):

        # only allow one request
        saq.CONFIG['analysis_module_cloudphish']['cloudphish_request_limit'] = '1'
        
        # don't clear the analysis
        saq.CONFIG['analysis_mode_analysis']['cleanup'] = 'no'
        

        self.start_api_server()
        
        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        url_1 = root.add_observable(F_URL, TEST_URL)
        url_2 = root.add_observable(F_URL, 'http://invalid_domain.local/some/path')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={},
                            local_analysis_modes=[ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CLOUDPHISH])

        engine.enable_module('analysis_module_cloudphish', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)

        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        url_1 = root.get_observable(url_1.id)
        url_2 = root.get_observable(url_2.id)

        from saq.modules.cloudphish import CloudphishAnalysis
        analysis_1 = url_1.get_analysis(CloudphishAnalysis)
        analysis_2 = url_2.get_analysis(CloudphishAnalysis)

        self.assertTrue((isinstance(analysis_1, Analysis) and analysis_2 is False) or (analysis_1 is False and isinstance(analysis_2, Analysis)))
        self.assertEquals(log_count('reached cloudphish limit'), 1)

    @use_db
    def test_cloudphish_tracking(self, db, c):

        from saq.modules.email import EmailAnalysis

        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'
        self.start_api_server()

        root = create_root_analysis(alert_type='mailbox', analysis_mode=ANALYSIS_MODE_EMAIL)
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'emails', 'splunk_logging.email.rfc822'),
                    os.path.join(root.storage_dir, 'email.rfc822'))
        file_observable = root.add_observable(F_FILE, 'email.rfc822')
        file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
        test_observable = root.add_observable(F_TEST, 'test_detection')
        test_observable.add_directive(DIRECTIVE_TRACKED)
        root.save()
        root.schedule()

        analysis_modes = [ ANALYSIS_MODE_EMAIL, ANALYSIS_MODE_CLOUDPHISH, ANALYSIS_MODE_CORRELATION ]
        analysis_modules = [
            'analysis_module_file_type',
            'analysis_module_email_analyzer',
            'analysis_module_mailbox_email_analyzer',
            'analysis_module_cloudphish',
            'analysis_module_cloudphish_request_analyzer',
            'analysis_module_crawlphish',
            'analysis_module_url_extraction',
            'analysis_module_detection' ]

        engine = TestEngine(local_analysis_modes=analysis_modes)
        for module in analysis_modules:
            engine.enable_module(module, analysis_modes)

        # we only enable the BasicTestAnalyzer for the cloudphish mode so that cloudphish generates an alert
        engine.enable_module('analysis_module_basic_test', ANALYSIS_MODE_CLOUDPHISH)
        
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # get the message_id observable generated by the EmailAnalysis
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()

        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        email_analysis = file_observable.get_analysis(EmailAnalysis)
        self.assertTrue(bool(email_analysis))
        message_id = email_analysis.find_observable(lambda o: o.type == F_MESSAGE_ID)
        self.assertIsNotNone(message_id)

        # we should have a number of cloudphish alerts now
        c.execute("SELECT uuid FROM alerts WHERE tool != 'test_tool' LIMIT 1")
        row = c.fetchone()
        target_uuid = row[0]
        
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(target_uuid))
        root.load()

        # this cloudphish alert should have the message_id observable
        # and it should be tagged as tracked
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_MESSAGE_ID and o.value == message_id.value and o.has_tag('tracked')))
