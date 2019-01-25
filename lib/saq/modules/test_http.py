# vim: sw=4:ts=4:et

import datetime
import json
import logging
import os.path
import shutil

import saq

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.test import *
from saq.util import storage_dir_from_uuid, workload_storage_dir

import pytz

class TestCase(ACEModuleTestCase):
    def test_bro_http_analyzer(self):
        saq.CONFIG['analysis_mode_http']['cleanup'] = 'no'

        root = create_root_analysis(alert_type=ANALYSIS_TYPE_BRO_HTTP, analysis_mode=ANALYSIS_MODE_HTTP)
        root.initialize_storage()
        root.details = { }
        for file_name in [ 'CZZiJd1zicZKNMMrV1.0.ready', 
                           'CZZiJd1zicZKNMMrV1.0.reply', 
                           'CZZiJd1zicZKNMMrV1.0.reply.entity', 
                           'CZZiJd1zicZKNMMrV1.0.request' ]:
            source_path = os.path.join('test_data', 'http_streams', file_name)
            dest_path = os.path.join(root.storage_dir, file_name)
            shutil.copy(source_path, dest_path)
            root.add_observable(F_FILE, file_name)
            
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={ANALYSIS_MODE_HTTP: 1}, local_analysis_modes=[ANALYSIS_MODE_HTTP])
        engine.enable_module('analysis_module_bro_http_analyzer', ANALYSIS_MODE_HTTP)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        self.verify(root)

    def verify(self, root):

        from saq.modules.http import HTTP_DETAILS_READY, HTTP_DETAILS_REQUEST, HTTP_DETAILS_REPLY

        self.assertTrue(HTTP_DETAILS_READY in root.details)
        self.assertTrue(HTTP_DETAILS_REQUEST in root.details)
        self.assertTrue(HTTP_DETAILS_REPLY in root.details)
        self.assertTrue(len(root.details[HTTP_DETAILS_READY]) > 0)
        self.assertTrue(len(root.details[HTTP_DETAILS_REQUEST]) > 0)
        self.assertTrue(len(root.details[HTTP_DETAILS_REPLY]) > 0)
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_IPV4 and o.value == '67.195.197.75'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_IPV4 and o.value == '172.16.139.143'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_IPV4_CONVERSATION and o.value == '172.16.139.143_67.195.197.75'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_URL and o.value == 'http://www.pdf995.com/samples/pdf.pdf'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_FQDN and o.value == 'www.pdf995.com'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_FILE and o.value == 'CZZiJd1zicZKNMMrV1.0.ready'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_FILE and o.value == 'CZZiJd1zicZKNMMrV1.0.reply'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_FILE and o.value == 'CZZiJd1zicZKNMMrV1.0.reply.entity'))
        self.assertIsNotNone(root.find_observable(lambda o: o.type == F_FILE and o.value == 'CZZiJd1zicZKNMMrV1.0.request'))
        self.assertEquals(root.description, 'BRO HTTP Scanner Detection - GET /samples/pdf.pdf')
        for file_name in [ 'CZZiJd1zicZKNMMrV1.0.ready',
                           'CZZiJd1zicZKNMMrV1.0.reply',
                           'CZZiJd1zicZKNMMrV1.0.reply.entity',
                           'CZZiJd1zicZKNMMrV1.0.request' ]:
            self.assertTrue(os.path.exists(os.path.join('test_data', 'http_streams', file_name)))

    def test_bro_http_submission(self):
        saq.CONFIG['analysis_mode_http']['cleanup'] = 'no'

        from flask import url_for
        from saq.analysis import _JSONEncoder
        from saq.modules.email import EmailAnalysis

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime.now()).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        ready_fp = open(os.path.join('test_data', 'http_streams', 'CZZiJd1zicZKNMMrV1.0.ready'), 'rb')
        reply_fp = open(os.path.join('test_data', 'http_streams', 'CZZiJd1zicZKNMMrV1.0.reply'), 'rb')
        reply_entity_fp = open(os.path.join('test_data', 'http_streams', 'CZZiJd1zicZKNMMrV1.0.reply.entity'), 'rb')
        request_fp = open(os.path.join('test_data', 'http_streams', 'CZZiJd1zicZKNMMrV1.0.request'), 'rb')

        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': ANALYSIS_MODE_HTTP,
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': ANALYSIS_TYPE_BRO_HTTP,
                'description': 'BRO HTTP Scanner Detection - {}'.format('CZZiJd1zicZKNMMrV1.0'),
                'event_time': t,
                'details': { },
                'observables': [
                    { 'type': F_FILE, 'value': 'CZZiJd1zicZKNMMrV1.0.ready' },
                    { 'type': F_FILE, 'value': 'CZZiJd1zicZKNMMrV1.0.reply' },
                    { 'type': F_FILE, 'value': 'CZZiJd1zicZKNMMrV1.0.reply.entity' },
                    { 'type': F_FILE, 'value': 'CZZiJd1zicZKNMMrV1.0.request' },
                ],
                'tags': [ ],
            }, cls=_JSONEncoder),
            'file': [ (ready_fp, 'CZZiJd1zicZKNMMrV1.0.ready'),
                      (reply_fp, 'CZZiJd1zicZKNMMrV1.0.reply'),
                      (reply_entity_fp, 'CZZiJd1zicZKNMMrV1.0.reply.entity'),
                      (request_fp, 'CZZiJd1zicZKNMMrV1.0.request'), ],
            }, content_type='multipart/form-data')

        ready_fp.close()
        reply_fp.close()
        reply_entity_fp.close()
        request_fp.close()

        result = result.get_json()
        self.assertIsNotNone(result)

        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        uuid = result['uuid']

        # make sure we have a job ready

        engine = TestEngine(analysis_pools={ANALYSIS_MODE_HTTP: 1}, local_analysis_modes=[ANALYSIS_MODE_HTTP])
        engine.enable_module('analysis_module_bro_http_analyzer', ANALYSIS_MODE_HTTP)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=workload_storage_dir(uuid))
        root.load()

        self.verify(root)
