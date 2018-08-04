# vim: sw=4:ts=4:et

import os, os.path
import logging
import json
import hashlib
import tarfile
import io
import tempfile
import shutil

from urllib.parse import urlencode

import saq, saq.test
from saq.cloudphish import *
from saq.database import get_db_connection, Alert
from saq.engine.cloudphish import CloudPhishEngine
from saq.test import *

class CloudphishEngineTestCase(ACEEngineTestCase):
    def setUp(self):
        ACEEngineTestCase.setUp(self)

        self.reset_cloudphish()

        # set up custom white/black listing for testing
        saq.CONFIG['analysis_module_crawlphish']['whitelist_path'] = 'var/unittest/etc/crawlphish.whitelist'
        saq.CONFIG['analysis_module_crawlphish']['regex_path'] = 'var/unittest/etc/crawlphish.path_regex'
        saq.CONFIG['analysis_module_crawlphish']['blacklist_path'] = 'var/unittest/etc/crawlphish.blacklist'

        if not os.path.isdir('var/unittest/etc'):
            os.makedirs('var/unittest/etc')

        with open('var/unittest/etc/crawlphish.whitelist', 'w') as fp:
            fp.write('valvoline.com\n')
            fp.write('www.alienvault.com\n')

        with open('var/unittest/etc/crawlphish.path_regex', 'w') as fp:
            fp.write(r'\.(pdf|zip|scr|js|cmd|bat|ps1|doc|docx|xls|xlsx|ppt|pptx|exe|vbs|vbe|jse|wsh|cpl|rar|ace|hta)$')

        with open('var/unittest/etc/crawlphish.blacklist', 'w') as fp:
            fp.write('google.com')

        initialize_url_filter()

        enable_module('engine_cloudphish', 'analysis_module_crawlphish')

        # test client
        from app import create_app
        app = create_app()
        app.jinja_env.add_extension('jinja2.ext.do')
        app.testing = True
        self.client = app.test_client()

class CloudPhishEngineTestCase(CloudphishEngineTestCase):
    def generate_cloudphish_alert(self, url):
        result = self.client.post('/cloudphish/submit', data={
            'url': url,
            'r': 0,
            'a': 0})

        # start the cloudphish engine
        engine = self.create_engine(CloudPhishEngine)
        self.start_engine(engine)

        # wait for the request to complete
        def condition():
            result = self.client.post('/cloudphish/submit', data={
                'url': url,
                'r': 0,
                'a': 0})
            json_data = json.loads(result.get_data().decode())
            return json_data['status'] == STATUS_ANALYZED

        wait_for(condition)

        result = self.client.post('/cloudphish/submit', data={
            'url': url,
            'r': 0,
            'a': 0})
        json_data = json.loads(result.get_data().decode())
        self.assertEquals(json_data['analysis_result'], SCAN_RESULT_ALERT)
        return json_data
        
    def test_cloudphish_engine_000_startup(self):
        engine = CloudPhishEngine()
        self.start_engine(engine)
        engine.stop()
        self.wait_engine(engine)

    def test_cloudphish_engine_001_basic_processing(self):

        url = 'http://valvoline.com/'

        # submit a single URL for processing
        result = analyze_url(url, False, False)
        self.assertEquals(result.result, RESULT_OK)
        self.assertIsNone(result.details)
        self.assertEquals(result.status, STATUS_NEW)
        self.assertEquals(result.analysis_result, SCAN_RESULT_UNKNOWN)
        self.assertIsNone(result.http_result)
        self.assertIsNone(result.http_message)
        self.assertIsNone(result.sha256_content)
        self.assertIsNone(result.location)
        self.assertIsNone(result.file_name)

        engine = CloudPhishEngine()
        self.start_engine(engine)

        def condition():
            result = get_cached_analysis(url)
            return result.status == STATUS_ANALYZED
        
        wait_for(condition)

        result = analyze_url(url, False, False)
        self.assertEquals(result.result, RESULT_OK)
        self.assertIsNone(result.details)
        self.assertEquals(result.status, STATUS_ANALYZED)
        self.assertEquals(result.analysis_result, SCAN_RESULT_CLEAR)
        self.assertEquals(result.http_result, 200)
        self.assertIsNotNone(result.http_message, 'OK')
        self.assertIsNotNone(result.sha256_content)
        self.assertEquals(result.location, saq.SAQ_NODE)
        self.assertIsNotNone(result.file_name)

        engine.stop()
        self.wait_engine(engine)

    @clear_log
    def test_cloudphish_engine_002_whiteblacklisting(self):
        
        url = 'http://valvoline.com/'
        result = analyze_url(url, False, False)

        engine = CloudPhishEngine()
        self.start_engine(engine)

        def condition():
            result = get_cached_analysis(url)
            return result.status == STATUS_ANALYZED
        
        wait_for(condition)

        # we should expect to see this message twice
        # once when cloudphish compares and second when crawlphish compares
        self.assertEquals(log_count('valvoline.com matches whitelisted fqdn valvoline.com'), 2)

        url = 'http://ashland.com/'
        result = analyze_url(url, False, False)

        def condition():
            result = get_cached_analysis(url)
            return result.status == STATUS_ANALYZED
        
        wait_for(condition)

        # we should NOT see this
        self.assertEquals(log_count('ashland.com matches whitelisted fqdn '), 0)

        url = 'http://google.com/'
        result = analyze_url(url, False, False)
        self.assertEquals(result.status, STATUS_ANALYZED)
        self.assertEquals(result.analysis_result, SCAN_RESULT_PASS)
        self.assertEquals(log_count('google.com matches blacklisted fqdn google.com'), 1)

        result = get_cached_analysis(url)
        self.assertIsNone(result)

        engine.stop()
        self.wait_engine(engine)

    def test_cloudphish_engine_003_http_server_startup(self):
        result = self.client.get('/cloudphish/debug')
        self.assertEquals(result.status_code, 200)

    def test_cloudphish_engine_004_http_submit(self):
        url = 'http://valvoline.com/'
        result = self.client.post('/cloudphish/submit', data={
            'url': url,
            'r': 0,
            'a': 0})

        self.assertEquals(result.status_code, 200)
        #logging.info("MARKER: {}".format(result.get_data().decode()))
        # this doesn't seem to be working
        #self.assertEquals(result.mimetype, 'application/json')
        json_data = json.loads(result.get_data().decode())
        self.assertIsInstance(json_data, dict)
        
        self.assertEquals(json_data['result'], RESULT_OK)
        self.assertIsNone(json_data['details'])
        self.assertEquals(json_data['status'], STATUS_NEW)
        self.assertEquals(json_data['analysis_result'], SCAN_RESULT_UNKNOWN)
        self.assertIsNone(json_data['http_result'])
        self.assertIsNone(json_data['http_message'])
        self.assertIsNone(json_data['sha256_content'])
        self.assertIsNone(json_data['location'])
        self.assertIsNone(json_data['file_name'])

        # start the cloudphish engine
        engine = CloudPhishEngine()
        self.start_engine(engine)

        # wait for the request to complete
        def condition():
            result = self.client.post('/cloudphish/submit', data={
                'url': url,
                'r': 0,
                'a': 0})
            json_data = json.loads(result.get_data().decode())
            return json_data['status'] == STATUS_ANALYZED

        wait_for(condition)

        result = self.client.post('/cloudphish/submit', data={
            'url': url,
            'r': 0,
            'a': 0})

        self.assertEquals(result.status_code, 200)
        #logging.info("MARKER: {}".format(result.get_data().decode()))
        # this doesn't seem to be working
        #self.assertEquals(result.mimetype, 'application/json')
        json_data = json.loads(result.get_data().decode())
        self.assertIsInstance(json_data, dict)
        
        self.assertEquals(json_data['result'], RESULT_OK)
        self.assertIsNone(json_data['details'])
        self.assertEquals(json_data['status'], STATUS_ANALYZED)
        self.assertEquals(json_data['analysis_result'], SCAN_RESULT_CLEAR)
        self.assertEquals(json_data['http_result'], 200)
        self.assertIsNotNone(json_data['http_message'])
        self.assertIsNotNone(json_data['sha256_content'])
        self.assertEquals(json_data['location'], saq.SAQ_NODE)
        self.assertIsNotNone(json_data['file_name'])

        engine.stop()

    def test_cloudphish_engine_005_http_download_content(self):
        url = 'http://valvoline.com/'
        result = self.client.post('/cloudphish/submit', data={
            'url': url,
            'r': 0,
            'a': 0})

        # start the cloudphish engine
        engine = CloudPhishEngine()
        self.start_engine(engine)

        # wait for the request to complete
        def condition():
            result = self.client.post('/cloudphish/submit', data={
                'url': url,
                'r': 0,
                'a': 0})
            json_data = json.loads(result.get_data().decode())
            return json_data['status'] == STATUS_ANALYZED

        wait_for(condition)

        # download the content
        result = self.client.post('/cloudphish/submit', data={
            'url': url,
            'r': 0,
            'a': 0})
        json_data = json.loads(result.get_data().decode())
        
        result = self.client.get('/cloudphish/download?s={}'.format(json_data['sha256_content']))
        self.assertEquals(result.status_code, 200)
        
        # the hash of the content should match the sha256_content
        h = hashlib.sha256()
        h.update(result.get_data())
        self.assertEquals(json_data['sha256_content'].lower(), h.hexdigest().lower())

        engine.stop()
        self.wait_engine(engine)
        
    @force_alerts
    def test_cloudphish_engine_006_http_download_alert(self):

        url = 'http://valvoline.com/'
        json_data = self.generate_cloudphish_alert(url)

        # download the alert data
        result = self.client.get('/cloudphish/download_alert?s={}'.format(json_data['sha256_content']))
        self.assertEquals(result.status_code, 200)

        # verify the downloaded tar file
        fp = io.BytesIO(result.get_data())
        t = tarfile.open(None, 'r:gz', fp)

        # extract it into a temporary directory
        temp_dir = tempfile.mkdtemp(dir=saq.test.test_dir)
        t.extractall(temp_dir)

        # try to load it
        alert = Alert(storage_dir=temp_dir)
        alert.load()

    @force_alerts
    def test_cloudphish_engine_007_http_clear_alert(self):
        url = 'http://valvoline.com/'
        json_data = self.generate_cloudphish_alert(url)

        # there should be one result in the database
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""SELECT COUNT(*) FROM analysis_results WHERE result = 'ALERT'""")
            result = c.fetchone()
            self.assertEquals(result[0], 1)

        result = self.client.get('/cloudphish/clear_alert?{}'.format(urlencode({'url': url})))

        # now there should be zero
        with get_db_connection('cloudphish') as db:
            c = db.cursor()
            c.execute("""SELECT COUNT(*) FROM analysis_results WHERE result = 'ALERT'""")
            result = c.fetchone()
            self.assertEquals(result[0], 0)
