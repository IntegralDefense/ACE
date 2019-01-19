# vim: sw=4:ts=4:et

import hashlib
import logging
import os, os.path
import threading
import time
import tarfile

from subprocess import Popen, PIPE
from unittest import TestCase

import saq
from api.test import APIBasicTestCase
from saq.analysis import RootAnalysis
from saq.brocess import query_brocess_by_fqdn
from saq.constants import *
from saq.cloudphish import *
from saq.database import use_db, get_db_connection, initialize_node
from saq.test import *

import requests
from flask import url_for

# part of our sample set of data
TEST_URL = 'http://localhost:8080/Payment_Advice.pdf'

class CloudphishTestCase(TestCase):
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

class CloudphishAPITestCase(CloudphishTestCase, ACEEngineTestCase):

    #def setUp(self, *args, **kwargs):
        #super().setUp(*args, **kwargs)
    
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
        self.assertIsNotNone(result[KEY_DETAILS])
        
        # everything else should be None
        for key in [ KEY_HTTP_RESULT, KEY_HTTP_MESSAGE, KEY_SHA256_CONTENT, KEY_LOCATION, KEY_FILE_NAME ]:
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
        engine = TestEngine(analysis_pools={ANALYSIS_MODE_CLOUDPHISH: 1}, local_analysis_modes=[ANALYSIS_MODE_CLOUDPHISH])
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)
        # force this analysis to become an alert
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_CLOUDPHISH)
        #engine.enable_module('analysis_module_alert', ANALYSIS_MODE_CLOUDPHISH)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should still have a single entry in the cloudphish_analysis_results table
        # but it should be updated with the analysis results
        db.commit()
        c.execute("""SELECT HEX(sha256_url), http_result_code, http_message, HEX(sha256_content), result, insert_date, uuid, status
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

        # and we should have an entry in the cloudphish_content_metadata table
        c.execute("""SELECT node, name FROM cloudphish_content_metadata WHERE sha256_content = UNHEX(%s)""", sha256_content)
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        node, file_name = result[0]
        self.assertEquals(node, saq.SAQ_NODE)
        file_name = file_name.decode('unicode_internal')
        self.assertEquals(file_name, 'Payment_Advice.pdf')

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

        # now we make a second api call to the same url
        result = self.client.get(url_for('cloudphish.submit', url=TEST_URL, ignore_filters='1'))
        result = result.get_json()
        self.assertIsNotNone(result)

        # first check the result
        for key in [ KEY_RESULT, KEY_DETAILS, KEY_STATUS, KEY_ANALYSIS_RESULT, KEY_HTTP_RESULT,
                     KEY_HTTP_MESSAGE, KEY_SHA256_CONTENT, KEY_LOCATION, KEY_FILE_NAME ]:
            self.assertTrue(key in result)
        
        self.assertEquals(result[KEY_RESULT], RESULT_OK)
        self.assertEquals(result[KEY_STATUS], STATUS_ANALYZED)
        self.assertEquals(result[KEY_ANALYSIS_RESULT], SCAN_RESULT_ALERT)
        
        # everything else should be None
        self.assertEquals(result[KEY_HTTP_RESULT], 200)
        self.assertEquals(result[KEY_HTTP_MESSAGE], 'OK')
        self.assertEquals(result[KEY_SHA256_CONTENT], sha256_content)
        self.assertEquals(result[KEY_LOCATION], saq.SAQ_NODE)
        self.assertEquals(result[KEY_FILE_NAME], 'Payment_Advice.pdf')

        # now attempt to download the binary by sha256
        result = self.client.get(url_for('cloudphish.download', s=sha256_url))
        # make sure we got the actual file
        m = hashlib.sha256()
        m.update(result.data)
        sha256_result = m.hexdigest()
        self.assertEquals(sha256_result.lower(), sha256_content.lower())
        # and make sure we got the file name
        filename_ok = False
        for header in result.headers:
            header_name, header_value = header
            if header_name == 'Content-Disposition':
                self.assertTrue('Payment_Advice.pdf' in header_value)
                filename_ok = True

        self.assertTrue(filename_ok)

        # now attempt to download the alert itself
        result = self.client.get(url_for('engine.download', uuid=_uuid))
        # we should get back a tar file
        tar_path = os.path.join(saq.TEMP_DIR, 'download.tar')
        output_dir = os.path.join(saq.TEMP_DIR, 'download')

        try:
            with open(tar_path, 'wb') as fp:
                for chunk in result.response:
                    fp.write(chunk)

            with tarfile.open(name=tar_path, mode='r|') as tar:
                tar.extractall(path=output_dir)

            downloaded_root = RootAnalysis(storage_dir=output_dir)
            downloaded_root.load()

            self.assertTrue(isinstance(root.details, dict))
            for key in [ KEY_DETAILS_URL, KEY_DETAILS_SHA256_URL, KEY_DETAILS_CONTEXT ]:
                self.assertTrue(key in root.details)

        finally:
            try:
                os.remove(tar_path)
            except:
                pass

            try:
                shutil.rmtree(output_dir)
            except:
                pass

        # and then finally make sure we can clear the alert
        result = self.client.get(url_for('cloudphish.clear_alert', url=TEST_URL))
        self.assertEquals(result.status_code, 200)
        
        db.commit()
        c.execute("SELECT result FROM cloudphish_analysis_results WHERE sha256_url = UNHEX(%s)", (sha256_url,))
        row = c.fetchone()
        self.assertEquals(row[0], SCAN_RESULT_CLEAR)

        # we should have a brocess entry for this http request
        self.assertEquals(query_brocess_by_fqdn('localhost'), 1)

    @use_db
    def test_submit_invalid_url(self, db, c):
        # try submitting something that is clearly not a URL
        result = self.client.get(url_for('cloudphish.submit', url=b'\xFF\x80\x34\x01\x45', ignore_filters='1'))
        self.assertEquals(result.status_code, 500)

    def test_submit_ignore_filters(self):
        # we add a url for something that should be blacklisted but we ignore the filters
        with open(self.blacklist_path, 'w') as fp:
            fp.write('localhost\n')

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
        self.assertIsNotNone(result[KEY_DETAILS])
        
        # everything else should be None
        for key in [ KEY_HTTP_RESULT, KEY_HTTP_MESSAGE, KEY_SHA256_CONTENT, KEY_LOCATION, KEY_FILE_NAME ]:
            self.assertIsNone(result[key])

    def test_download_redirect(self):
        # create a request to download the pdf
        result = self.client.get(url_for('cloudphish.submit', url=TEST_URL, ignore_filters='1'))

        # have the engine process it
        engine = TestEngine(analysis_pools={ANALYSIS_MODE_CLOUDPHISH: 1}, local_analysis_modes=[ANALYSIS_MODE_CLOUDPHISH])
        engine.enable_module('analysis_module_crawlphish', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_cloudphish_request_analyzer', ANALYSIS_MODE_CLOUDPHISH)

        # force this analysis to become an alert
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_CLOUDPHISH)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_CLOUDPHISH)
        #engine.enable_module('analysis_module_alert', ANALYSIS_MODE_CLOUDPHISH)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # get the sha256_content
        submission_result = self.client.get(url_for('cloudphish.submit', url=TEST_URL, ignore_filters='1'))
        submission_result = submission_result.get_json()
        self.assertIsNotNone(submission_result[KEY_SHA256_URL])

        # change what node we are
        saq.SAQ_NODE = 'second_host'
        initialize_node()
        self.initialize_test_client()

        # we should get a redirect back to the other node
        result = self.client.get(url_for('cloudphish.download', s=submission_result[KEY_SHA256_URL]))
        self.assertEquals(result.status_code, 302)
