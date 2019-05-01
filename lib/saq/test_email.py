# vim: sw=4:ts=4:et

from saq.email import normalize_email_address, decode_rfc2822
from saq.test import *

class TestCase(ACEBasicTestCase):
    def test_normalize_email_address(self):
        self.assertEquals(normalize_email_address('test@user.com'), 'test@user.com')
        self.assertEquals(normalize_email_address('<test@user.com>'), 'test@user.com')
        self.assertEquals(normalize_email_address('<TEST@USER.COM>'), 'test@user.com')
        self.assertEquals(normalize_email_address('"user name" <TEST@USER.COM>'), 'test@user.com')
        self.assertEquals(normalize_email_address('user name <TEST@USER.COM>'), 'test@user.com')

    def test_decode_rfc2822(self):
        self.assertEquals(decode_rfc2822('=?utf-8?B?UmU6IFVyZ2VudA==?='), 'Re: Urgent')
        self.assertEquals(decode_rfc2822('=?UTF-8?B?RklOQUwgREFZIC0gRU1BSUwgRVhDTFVTSVZFIC0gJDMyLjk5IEp1?= =?UTF-8?B?c3QgQmFzaWNz4oSiIDEwLVJlYW0gQ2FzZSBQYXBlcg==?='), 
                          'FINAL DAY - EMAIL EXCLUSIVE - $32.99 Just Basics™ 10-Ream Case Paper')
        self.assertEquals(decode_rfc2822('=?US-ASCII?Q?CSMS#_19-000228_-_ACE_CERTIFICATION_Scheduled_Ma?= =?US-ASCII?Q?intenance,_Wed._May_1,_2019_@_1700_ET_to_2000_ET?='), 
                          'CSMS# 19-000228 - ACE CERTIFICATION Scheduled Maintenance, Wed. May 1, 2019 @ 1700 ET to 2000 ET')
        self.assertEquals(decode_rfc2822('=?Windows-1252?Q?Money_Talk_=96_Profit=99_Performance_Monitor_(Honeywell_?= =?Windows-1252?Q?Webinar)?='), 
                          'Money Talk – Profit™ Performance Monitor (Honeywell Webinar)')
        self.assertEquals(decode_rfc2822('=?ISO-8859-1?Q?Puede_que_algunos_contribuyentes_tengan_?= =?ISO-8859-1?Q?que_enmendar_su_declaraci=F3n_de_impuestos?='), 
                          'Puede que algunos contribuyentes tengan que enmendar su declaración de impuestos')
        self.assertEquals(decode_rfc2822('=?GBK?B?UmU6gYbKssC8tcTNxo9Wst/C1A==?='), 
                          'Re:亞什兰的推廣策略')
