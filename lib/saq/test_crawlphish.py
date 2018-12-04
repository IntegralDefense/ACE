# vim: sw=4:ts=4:et:cc=120

import os, os.path

import saq
from saq.test import *
from saq.database import get_db_connection
from saq.crawlphish import *

class CrawlphishTestCase(ACEBasicTestCase):
    def test_filters(self):

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
        
        # XXX skipping testing the "crits cache" until matt gets his intel stuff done
        
        result = _filter.filter('http://test1.local')
        self.assertEquals(result.filtered, True)
        self.assertEquals(result.reason, REASON_COMMON_NETWORK)
        
        result = _filter.filter('http://test2.local')
        self.assertEquals(result.filtered, False)
        self.assertEquals(result.reason, REASON_OK)
