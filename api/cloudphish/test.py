# vim: sw=4:ts=4:et

import logging
import time
import os, os.path
import threading

from subprocess import Popen, PIPE

import saq
from api.test import APIBasicTestCase
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.cloudphish import *
from saq.database import use_db, get_db_connection
from saq.test import *

import requests
from flask import url_for

# part of our sample set of data
TEST_URL = 'http://localhost:8080/Payment_Advice.pdf'

class CloudphishAPITestCase(APIBasicTestCase, ACEEngineTestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # subprocess for http server
        self.http_server = None

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("DELETE FROM cloudphish_analysis_results")
            db.commit()

        self.start_http_server()

    def start_http_server(self):
        logging.debug("starting http server")
        self.http_server = Popen(['python3', '-m', 'http.server', '8080'], 
                           cwd=os.path.join(saq.SAQ_HOME, 'test_data', 'pdf'), stdout=PIPE, stderr=PIPE)

        def _reader(p):
            for line in p:
                logging.info("[http_server] - {}".format(line.strip()))

        threading.Thread(target=_reader, args=(self.http_server.stdout,), daemon=True).start()
        threading.Thread(target=_reader, args=(self.http_server.stderr,), daemon=True).start()

        time.sleep(0.1)

        # wait for it to start...
        while True:
            try:
                r = requests.get(TEST_URL)
                logging.debug("http server started!: {}".format(r))
                break
            except Exception as e:
                logging.debug("waiting for http server to start... ({})".format(e))
                time.sleep(0.25)

    def stop_http_server(self):
        if self.http_server:
            logging.debug("stopping http server")
            self.http_server.terminate()
            self.http_server.wait()
            self.http_server = None

    def tearDown(self, *args, **kwargs):
        super().tearDown(*args, **kwargs)
        self.stop_http_server()

    def test_http_server(self):
        # make sure our http server is working
        r = requests.get(TEST_URL)
        self.assertEquals(r.status_code, 200)

    @use_db
    def test_submit_valid_url(self, db, c):
        result = self.client.get(url_for('cloudphish.submit', url=TEST_URL, ignore_filters='1'))
        result = result.get_json()
        self.assertIsNotNone(result)

        # first check the result
        for key in [ KEY_RESULT, KEY_DETAILS, KEY_STATUS, KEY_ANALYSIS_RESULT, KEY_HTTP_RESULT,
                     KEY_HTTP_MESSAGE, KEY_SHA256_CONTENT, KEY_LOCATION, KEY_FILE_NAME ]:
            self.assertTrue(key in result)
        
        self.assertEquals(result[KEY_RESULT], RESULT_OK)
        self.assertEquals(result[KEY_STATUS], STATUS_NEW)
        self.assertEquals(result[KEY_ANALYSIS_RESULT], SCAN_RESULT_UNKNOWN)
        
        # everything else should be None
        for key in [ KEY_DETAILS, KEY_HTTP_RESULT, KEY_HTTP_MESSAGE, KEY_SHA256_CONTENT, KEY_LOCATION, KEY_FILE_NAME ]:
            self.assertIsNone(result[key])

        # we should have a single entry in the cloudphish_analysis_results table
        c.execute("""SELECT sha256_url, http_result_code, sha256_content, result, insert_date, uuid, status
                     FROM cloudphish_analysis_results""")
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        sha256_url, http_result_code, sha256_content, result, insert_date, _uuid, status = result[0]
        self.assertIsNotNone(sha256_url)
        self.assertIsNone(http_result_code)
        self.assertIsNone(sha256_content)
        self.assertEquals(result, SCAN_RESULT_UNKNOWN)
        self.assertIsNotNone(insert_date)
        self.assertIsNotNone(_uuid)
        self.assertEquals(status, STATUS_NEW)

        # we should have a matching entry in the workload for this uuid
        c.execute("""SELECT id, uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir
                     FROM workload""")
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        _id, workload_uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir = result[0]
        self.assertIsNotNone(_id)
        self.assertEquals(workload_uuid, _uuid)
        self.assertEquals(node_id, saq.SAQ_NODE_ID)
        self.assertEquals(analysis_mode, ANALYSIS_MODE_CLOUDPHISH)
        self.assertIsNotNone(insert_date)
        self.assertEquals(company_id, saq.COMPANY_ID)
        self.assertIsNone(exclusive_uuid)
        self.assertIsNotNone(storage_dir)

        # and then make sure we can load the analysis
        root = RootAnalysis(storage_dir=storage_dir)
        root.load()
        self.assertTrue(isinstance(root.details, dict))
        for key in [ KEY_DETAILS_URL, KEY_DETAILS_SHA256_URL, KEY_DETAILS_CONTEXT ]:
            self.assertTrue(key in root.details)

        # now we start an engine to work on cloudphish analysis
        engine = TestEngine()
        engine.clear_analysis_pools()
        engine.add_analysis_pool('cloudphish', 1)
        engine.local_analysis_modes.append('cloudphish')
        engine.enable_module('analysis_module_crawlphish')
        engine.enable_module('analysis_module_cloudphish_request_analyzer')
        # force this analysis to become an alert
        engine.enable_module('analysis_module_forced_detection')
        engine.enable_module('analysis_module_detection')
        engine.enable_module('analysis_module_alert')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should still have a single entry in the cloudphish_analysis_results table
        # but it should be updated with the analysis results
        db.commit()
        c.execute("""SELECT sha256_url, http_result_code, http_message, sha256_content, result, insert_date, uuid, status
                     FROM cloudphish_analysis_results""")
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        sha256_url, http_result_code, http_message, sha256_content, result, insert_date, _uuid, status = result[0]
        self.assertIsNotNone(sha256_url)
        self.assertEquals(http_result_code, 200)
        self.assertEquals(http_message, 'OK')
        self.assertIsNotNone(sha256_content)
        self.assertEquals(result, SCAN_RESULT_ALERT)
        self.assertIsNotNone(insert_date)
        self.assertIsNotNone(_uuid)
        self.assertEquals(status, STATUS_ANALYZED)

        # we should have seen the analysis mode change
        wait_for_log_count('changed from cloudphish to correlation', 1, 5)

        # should also have an entry to work the new alert
        old_storage_dir = storage_dir
        c.execute("""SELECT id, uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir
                     FROM workload""")
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        _id, workload_uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir = result[0]
        self.assertIsNotNone(_id)
        self.assertEquals(workload_uuid, _uuid)
        self.assertEquals(node_id, saq.SAQ_NODE_ID)
        self.assertEquals(analysis_mode, ANALYSIS_MODE_CORRELATION)
        self.assertIsNotNone(insert_date)
        self.assertEquals(company_id, saq.COMPANY_ID)
        self.assertIsNone(exclusive_uuid)
        self.assertEquals(storage_dir, old_storage_dir)
