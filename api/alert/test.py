# vim: sw=4:ts=4:et

import datetime
import io
import json
import logging

import saq
from saq.analysis import _JSONEncoder
from saq.constants import *
from saq.test import *
from api.test import APIBasicTestCase

import pytz
from flask import url_for

#KEY_TOOL = 'tool'
#KEY_TOOL_INSTANCE = 'tool_instance'
#KEY_TYPE = 'type'
#KEY_DESCRIPTION = 'description'
#KEY_EVENT_TIME = 'event_time'
#KEY_DETAILS = 'details'
#KEY_OBSERVABLES = 'observables'
#KEY_TAGS = 'tags'
#KEY_COMPANY_NAME = 'company_name'

#KEY_O_TYPE = 'type'
#KEY_O_VALUE = 'value'
#KEY_O_TIME = 'time'
#KEY_O_TAGS = 'tags'
#KEY_O_DIRECTIVES = 'directives'

class APIAlertTestCase(APIBasicTestCase):
    @protect_production
    @reset_alerts
    def test_api_alert_000_submit(self):
        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('alert.submit'), data={
            'alert': json.dumps({
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)

        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        self.assertIsNotNone(result['id'])

        uuid = result['uuid']
        _id = result['id']

        result = self.client.get(url_for('alert.get_alert', alert_id=uuid))
        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']

        self.assertEquals(result['tool'], 'unittest')
        self.assertEquals(result['tool_instance'], 'unittest_instance')
        self.assertEquals(result['type'], 'unittest')
        self.assertEquals(result['description'], 'testing')
        self.assertEquals(result['event_time'], '2017-11-11T07:36:01.000001+0000')
        self.assertEquals(result['tags'][0], 'alert_tag_1')
        self.assertEquals(result['tags'][1], 'alert_tag_2')
        self.assertEquals(len(result['observable_store']), 3)

        for o_uuid in result['observable_store']:
            o = result['observable_store'][o_uuid]
            if o['type'] == F_IPV4:
                self.assertEquals(o['type'], F_IPV4)
                self.assertEquals(o['value'], '1.2.3.4')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
                self.assertEquals(o['tags'][0], 'tag_1')
                self.assertEquals(o['tags'][1], 'tag_2')
                self.assertEquals(o['directives'][0], DIRECTIVE_NO_SCAN)
            elif o['type'] == F_USER:
                self.assertEquals(o['type'], F_USER)
                self.assertEquals(o['value'], 'test_user')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
            elif o['type'] == F_FILE:
                self.assertEquals(o['type'], F_FILE)
                self.assertEquals(o['value'], 'sample.dat')
                self.assertIsNone(o['time'])
