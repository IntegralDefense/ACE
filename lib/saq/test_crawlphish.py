# vim: sw=4:ts=4:et:cc=120

import os, os.path

import saq
from saq.test import *
from saq.database import get_db_connection
from saq.crawlphish import *

import pysip

class CrawlphishTestCase(ACEBasicTestCase):
    def setUp(self):
        ACEBasicTestCase.setUp(self)

        # XXX get rid of verify=False
        self.sip_client = pysip.Client(saq.CONFIG['sip']['remote_address'], saq.CONFIG['sip']['api_key'], verify=False)
        self.test_indicators = []

        # insert the indicator(s) we'll test against
        for indicator in [ 
            { 'type': 'URI - URL', 'value': 'http://whackadoodle.net/dunno.html', 'status': 'Analyzed' },
            #{ 'type': 'Address - ipv4-addr', 'value': '165.45.66.45', 'status': 'Analyzed' },
            { 'type': 'URI - Path', 'value': '/follow/the/white/rabbit.html', 'status': 'Analyzed' },
            { 'type': 'Windows - FileName', 'value': 'ultimate.txt', 'status': 'Analyzed' }, ]:

            self.test_indicators.append(self.sip_client.post('indicators', indicator))

        self.target_urls = [
            'http://whackadoodle.net/dunno.html',
            #'http://165.45.66.45/whatever.asp',
            'http://www.g00gle.com/follow/the/white/rabbit.html',
            'http://www.c00kie.com/ultimate.txt' ]

    def tearDown(self):
        ACEBasicTestCase.tearDown(self)

        # remove the indicator(s) we inserted
        for indicator in self.test_indicators:
            self.sip_client.delete('indicators/{}'.format(indicator['id']))

    def test_filters(self):

        import saq.intel
        import saq.crits

        # XXX need a way of doing this
        #saq.crits.update_local_cache()
        saq.intel.update_local_cache()

        _filter = CrawlphishURLFilter()
        _filter.load()

        result = _filter.filter('http://127.0.0.1/blah.exe')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_BLACKLISTED)

        result = _filter.filter('http://10.1.1.1/whatever/test.asp')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_BLACKLISTED)

        result = _filter.filter('http://localhost.local/whatever/test.asp')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_BLACKLISTED)

        result = _filter.filter('http://subdomain.localhost.local/whatever/test.asp')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_BLACKLISTED)

        result = _filter.filter('http://super.subdomain.localhost.local/whatever/test.asp')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_BLACKLISTED)

        result = _filter.filter('http://evil.com/phish.pdf')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_WHITELISTED)

        result = _filter.filter('http://evil.com/phish.zip')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_WHITELISTED)

        result = _filter.filter('http://evil.com/phish.vbs')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_WHITELISTED)

        # this would still be blacklisted since blacklisting comes first
        result = _filter.filter('http://127.0.0.1/phish.vbs')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_BLACKLISTED)

        result = _filter.filter('http://anonfile.xyz')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_WHITELISTED)

        result = _filter.filter('http://anonfile.xyz/whatever/')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_WHITELISTED)

        # this matches nothing
        result = _filter.filter('http://anonfile.xyz.xyz/whatever/')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_OK)

        # always crawl direct ipv4
        result = _filter.filter('http://1.2.3.4/hello.world')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_DIRECT_IPV4)
        
        # always crawl stuff that is in the intel db
        for target_url in self.target_urls:
            with self.subTest(target_url=target_url):
                result = _filter.filter(target_url)
                self.assertEquals(result.filtered, False)
                self.assertEquals(result.reason, REASON_CRITS)
        
        result = _filter.filter('http://test1.local')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_COMMON_NETWORK)
        
        result = _filter.filter('http://test2.local')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_OK)
