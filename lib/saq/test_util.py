# vim: sw=4:ts=4:et

import saq
from saq.test import *
from saq.util import parse_event_time

class ACEUtilTestCase(ACEBasicTestCase):
    def test_util_000_date_parsing(self):
        default_format = '2018-10-19 14:06:34 +0000'
        old_default_format = '2018-10-19 14:06:34'
        json_format = '2018-10-19T18:08:08.346118-05:00'
        old_json_format = '2018-10-19T18:08:08.346118'
        splunk_format = '2015-02-19T09:50:49.000-05:00'

        result = parse_event_time(default_format)
        self.assertEquals(result.year, 2018)
        self.assertEquals(result.month, 10)
        self.assertEquals(result.day, 19)
        self.assertEquals(result.hour, 14)
        self.assertEquals(result.minute, 6)
        self.assertEquals(result.second, 34)
        self.assertIsNotNone(result.tzinfo)
        self.assertEquals(int(result.tzinfo.utcoffset(None).total_seconds()), 0)

        result = parse_event_time(old_default_format)
        self.assertEquals(result.year, 2018)
        self.assertEquals(result.month, 10)
        self.assertEquals(result.day, 19)
        self.assertEquals(result.hour, 14)
        self.assertEquals(result.minute, 6)
        self.assertEquals(result.second, 34)
        self.assertIsNotNone(result.tzinfo)
        self.assertEquals(saq.LOCAL_TIMEZONE.tzname, result.tzinfo.tzname)
        
        result = parse_event_time(json_format)
        self.assertEquals(result.year, 2018)
        self.assertEquals(result.month, 10)
        self.assertEquals(result.day, 19)
        self.assertEquals(result.hour, 18)
        self.assertEquals(result.minute, 8)
        self.assertEquals(result.second, 8)
        self.assertIsNotNone(result.tzinfo)
        self.assertEquals(int(result.tzinfo.utcoffset(None).total_seconds()), -(5 * 60 * 60))

        result = parse_event_time(old_json_format)
        self.assertEquals(result.year, 2018)
        self.assertEquals(result.month, 10)
        self.assertEquals(result.day, 19)
        self.assertEquals(result.hour, 18)
        self.assertEquals(result.minute, 8)
        self.assertEquals(result.second, 8)
        self.assertIsNotNone(result.tzinfo)
        self.assertEquals(saq.LOCAL_TIMEZONE.tzname, result.tzinfo.tzname)

        result = parse_event_time(splunk_format)
        self.assertEquals(result.year, 2015)
        self.assertEquals(result.month, 2)
        self.assertEquals(result.day, 19)
        self.assertEquals(result.hour, 9)
        self.assertEquals(result.minute, 50)
        self.assertEquals(result.second, 49)
        self.assertIsNotNone(result.tzinfo)
        self.assertEquals(int(result.tzinfo.utcoffset(None).total_seconds()), -(5 * 60 * 60))
