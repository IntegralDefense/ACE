# vim: sw=4:ts=4:et

import datetime
import http.server
import logging
import socketserver
import threading
import unittest

import saq, saq.test
from saq.constants import *
from saq.test import *

LOCAL_PORT = 43124
web_server = None

class TestCase(ACEModuleTestCase):

    @classmethod
    def setUpClass(cls):

        global web_server

        # create a simple web server listening on localhost
        class _customTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        web_server = _customTCPServer(('', LOCAL_PORT), http.server.SimpleHTTPRequestHandler)
        web_server_thread = threading.Thread(target=web_server.serve_forever)
        web_server_thread.daemon = True
        web_server_thread.start()

    @classmethod
    def tearDownClass(cls):
        web_server.shutdown()
        
    def setUp(self):
        ACEModuleTestCase.setUp(self)
        # disable proxy for crawlphish
        self.old_proxies = saq.PROXIES
        saq.PROXIES = {}

    def tearDown(self):
        ACEModuleTestCase.tearDown(self)
        saq.PROXIES = self.old_proxies

    def test_basic_download(self):
        from saq.modules.url import CrawlphishAnalysisV2

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        self.assertEquals(analysis.status_code, 200)
        self.assertEquals(analysis.file_name, 'crawlphish.000')
        self.assertTrue(analysis.downloaded)
        self.assertIsNone(analysis.error_reason)

        # there should be a single F_FILE observable
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]

        self.assertTrue(file_observable.has_directive(DIRECTIVE_EXTRACT_URLS))
        self.assertTrue(file_observable.has_relationship(R_DOWNLOADED_FROM))

    def test_download_404(self):
        """We should not extract URLs from data downloaded from URLs that returned a 404."""
        from saq.modules.url import CrawlphishAnalysisV2

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.001'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        self.assertEquals(analysis.proxy_results['GLOBAL'].status_code, 404)
        if 'tor' in analysis.proxy_results:
            self.assertIsNone(analysis.proxy_results['tor'].status_code)
        self.assertIsNone(analysis.file_name) # no file should have been downloaded
        self.assertFalse(analysis.downloaded)
        self.assertIsNotNone(analysis.error_reason)
        
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 0)

    @unittest.skip
    @force_alerts
    def test_live_browser_basic(self):
        """Basic test of LiveBrowserAnalysis."""

        from saq.modules.url import CrawlphishAnalysisV2
        from saq.modules.url import LiveBrowserAnalysis

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/live_browser.000.html'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.enable_module('analysis_module_live_browser_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]

        analysis = file_observable.get_analysis(LiveBrowserAnalysis)
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]

        self.assertEquals(file_observable.value, 'crawlphish/localhost_0/localhost_000.png')

    @force_alerts
    def test_live_browser_404(self):
        """We should not download screenshots for URLs that returned a 404 error message."""

        from saq.database import Alert
        from saq.modules.url import CrawlphishAnalysisV2
        from saq.modules.url import LiveBrowserAnalysis

        root = create_root_analysis()
        root.initialize_storage()
        # this file does not exist
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/live_browser.dne.html'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_alerting()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.enable_module('analysis_module_live_browser_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        alert = saq.db.query(Alert).first()
        self.assertIsNotNone(alert)
        alert.load()
        url = alert.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 0)

    def test_protected_url_outlook_safelinks(self):
        root = create_root_analysis()
        root.initialize_storage()
        # taken from an actual sample
        url = root.add_observable(F_URL, 'https://na01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fwww.getbusinessready.com.au%2FInvoice-Number-49808%2F&data=02%7C01%7Ccyoung%40northernaviationservices.aero%7C8a388036cbf34f90ec5808d5724be7ed%7Cfc01978435d14339945c4161ac91c300%7C0%7C0%7C636540592704791165&sdata=%2FNQGqAp09WTNgnVnpoWIPcYNVAYsJ11ULuSS7cCsS3Q%3D&reserved=0')
        url.add_directive(DIRECTIVE_CRAWL) # not actually going to crawl, just testing that it gets copied over
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_protected_url_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        from saq.modules.url import ProtectedURLAnalysis, PROTECTION_TYPE_OUTLOOK_SAFELINKS
        analysis = url.get_analysis(ProtectedURLAnalysis)

        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.protection_type, PROTECTION_TYPE_OUTLOOK_SAFELINKS)
        self.assertEquals(analysis.extracted_url, 'http://www.getbusinessready.com.au/Invoice-Number-49808/')
        extracted_url = analysis.get_observables_by_type(F_URL)
        self.assertEquals(len(extracted_url), 1)
        extracted_url = extracted_url[0]
        self.assertTrue(extracted_url.has_directive(DIRECTIVE_CRAWL))

    def test_protected_url_dropbox(self):
        root = create_root_analysis()
        root.initialize_storage()
        # taken from an actual sample
        url_with_dl0 = root.add_observable(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=0')
        url_with_dl1 = root.add_observable(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
        url_without_dl = root.add_observable(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip')

        url_with_dl0.add_directive(DIRECTIVE_CRAWL) # not actually going to crawl, just testing that it gets copied over
        url_with_dl1.add_directive(DIRECTIVE_CRAWL) 
        url_without_dl.add_directive(DIRECTIVE_CRAWL)

        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_protected_url_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url_with_dl0 = root.get_observable(url_with_dl0.id)
        url_with_dl1 = root.get_observable(url_with_dl1.id)
        url_without_dl = root.get_observable(url_without_dl.id)
        from saq.modules.url import ProtectedURLAnalysis, PROTECTION_TYPE_DROPBOX

        analysis = url_with_dl0.get_analysis(ProtectedURLAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.protection_type, PROTECTION_TYPE_DROPBOX)
        self.assertEquals(analysis.extracted_url, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
        extracted_url = analysis.get_observables_by_type(F_URL)
        self.assertEquals(len(extracted_url), 1)
        extracted_url = extracted_url[0]
        self.assertTrue(extracted_url.has_directive(DIRECTIVE_CRAWL))

        analysis = url_with_dl1.get_analysis(ProtectedURLAnalysis)
        self.assertFalse(analysis)

        analysis = url_without_dl.get_analysis(ProtectedURLAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.protection_type, PROTECTION_TYPE_DROPBOX)
        self.assertEquals(analysis.extracted_url, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
        extracted_url = analysis.get_observables_by_type(F_URL)
        self.assertEquals(len(extracted_url), 1)
        extracted_url = extracted_url[0]
        self.assertTrue(extracted_url.has_directive(DIRECTIVE_CRAWL))

    def test_protected_url_google_drive(self):
        root = create_root_analysis()
        root.initialize_storage()
        # taken from an actual sample
        url = root.add_observable(F_URL, 'https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view')
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_protected_url_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        from saq.modules.url import ProtectedURLAnalysis, PROTECTION_TYPE_GOOGLE_DRIVE

        analysis = url.get_analysis(ProtectedURLAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.protection_type, PROTECTION_TYPE_GOOGLE_DRIVE)
        self.assertEquals(analysis.extracted_url, 'https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download')
        extracted_url = analysis.get_observables_by_type(F_URL)
        self.assertEquals(len(extracted_url), 1)
        extracted_url = extracted_url[0]
        self.assertTrue(extracted_url.has_directive(DIRECTIVE_CRAWL))

    def test_protected_url_sharepoint(self):
        root = create_root_analysis()
        root.initialize_storage()
        # taken from an actual sample
        url = root.add_observable(F_URL, 'https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD')
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_protected_url_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        from saq.modules.url import ProtectedURLAnalysis, PROTECTION_TYPE_SHAREPOINT

        analysis = url.get_analysis(ProtectedURLAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.protection_type, PROTECTION_TYPE_SHAREPOINT)
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(analysis.extracted_url)
        self.assertEquals(parsed_url.path, '/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx')
        parsed_qs = parse_qs(parsed_url.query)
        self.assertEquals(parsed_qs['e'][0], 'naeXYD')
        self.assertEquals(parsed_qs['share'][0], 'EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ')
        extracted_url = analysis.get_observables_by_type(F_URL)
        self.assertEquals(len(extracted_url), 1)
        extracted_url = extracted_url[0]
        self.assertTrue(extracted_url.has_directive(DIRECTIVE_CRAWL))
