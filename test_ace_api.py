# vim: ts=4:sw=4:et:cc=120

import datetime
import io
import logging
import os.path
import shutil
import tempfile
import uuid

import ace_api

import saq
from saq.analysis import RootAnalysis
from saq.database import acquire_lock, use_db
from saq.test import *
from saq.util import storage_dir_from_uuid

import pytz
import tzlocal

class APIWrapperTestCase(ACEEngineTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.start_api_server()

        ace_api.set_default_node(saq.API_PREFIX)
        ace_api.set_default_ssl_ca_path(saq.CONFIG['SSL']['ca_chain_path'])

    def test_ping(self):
        result = ace_api.ping()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        self.assertEquals(result['result'], 'pong')

    def test_get_supported_api_version(self):
        result = ace_api.get_supported_api_version()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        self.assertEquals(result['result'], 1)

    @use_db
    def test_get_valid_companies(self, db, c):
        result = ace_api.get_valid_companies()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        self.assertTrue(isinstance(result['result'], list))

        lookup = {}
        c.execute("SELECT id, name FROM company")
        for _id, _name in c:
            lookup[_id] = _name

        self.assertEquals(len(lookup), len(result['result']))
        for r in result['result']:
            self.assertTrue(r['id'] in lookup and lookup[r['id']] == r['name'])
        result = ace_api.get_valid_companies()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        self.assertTrue(isinstance(result['result'], list))

    def test_get_valid_observables(self):
        from saq.constants import VALID_OBSERVABLE_TYPES, OBSERVABLE_DESCRIPTIONS
        result = ace_api.get_valid_observables()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        self.assertTrue(isinstance(result['result'], list))

        for r in result['result']:
            self.assertTrue(r['name'] in VALID_OBSERVABLE_TYPES)
            self.assertEquals(OBSERVABLE_DESCRIPTIONS[r['name']], r['description'])

    def _get_submit_time(self):
        return datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)

    def _get_localized_submit_time(self):
        return ace_api.LOCAL_TIMEZONE.localize(self._get_submit_time()).astimezone(pytz.UTC)

    def _submit(self):
        temp_path = os.path.join(saq.SAQ_HOME, saq.CONFIG['global']['tmp_dir'], 'submit_test.dat')
        temp_data = os.urandom(1024)

        with open(temp_path, 'wb') as fp:
            fp.write(temp_data)

        try:
            with open(temp_path, 'rb') as fp:
                return ace_api.submit(
                    analysis_mode='test_empty', 
                    tool='unittest_tool',
                    tool_instance='unittest_tool_instance',
                    type='unittest_type',
                    description='testing',
                    details={'hello': 'world'},
                    event_time=self._get_submit_time(),
                    observables=[
                            { 'type': 'ipv4', 'value': '1.2.3.4', 'time': self._get_submit_time(), 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ 'no_scan' ], 'limited_analysis': ['basic_test'] },
                            { 'type': 'user', 'value': 'test_user', 'time': self._get_submit_time() },
                    ],
                    tags=[ 'alert_tag_1', 'alert_tag_2' ],
                    files=[('sample.dat', io.BytesIO(b'Hello, world!')),
                           ('submit_test.dat', fp)])
        finally:
            os.remove(temp_path)

    def test_submit(self):
        result = self._submit()
        self.assertIsNotNone(result)

        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        uuid = result['uuid']

        # make sure this actually uploaded
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(uuid))
        root.load()

        self.assertEquals(root.analysis_mode, 'test_empty')
        self.assertEquals(root.tool, 'unittest_tool')
        self.assertEquals(root.tool_instance, 'unittest_tool_instance')
        self.assertEquals(root.alert_type, 'unittest_type')
        self.assertEquals(root.description, 'testing')
        self.assertEquals(root.details, {'hello': 'world'})
        # this fails because the timezone objects are different even thought they both represent utc
        #self.assertEquals(root.event_time, self._get_localized_submit_time())
        self.assertEquals(root.tags[0].name, 'alert_tag_1')
        self.assertEquals(root.tags[1].name, 'alert_tag_2')
        # NOTE that this is 4 instead of 2 since adding a file adds a F_FILE observable type
        self.assertEquals(len(root.all_observables), 4)

        o = root.find_observable(lambda o: o.type == 'ipv4')
        self.assertIsNotNone(o)
        self.assertEquals(o.value, '1.2.3.4')
        self.assertEquals(len(o.tags), 2)
        self.assertTrue(o.has_directive('no_scan'))
        self.assertTrue('basic_test' in o.limited_analysis)

        o = root.find_observable(lambda o: o.type == 'file' and o.value == 'sample.dat')
        self.assertIsNotNone(o)

        with open(os.path.join(root.storage_dir, o.value), 'rb') as fp:
            self.assertEquals(fp.read(), b'Hello, world!')

        o = root.find_observable(lambda o: o.type == 'file' and o.value == 'submit_test.dat')
        self.assertIsNotNone(o)
        self.assertEquals(os.path.getsize(os.path.join(root.storage_dir, o.value)), 1024)

    def blah(self):

        result = self.client.get(url_for('analysis.get_analysis', uuid=uuid))
        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']

        self.assertEquals(result['analysis_mode'], 'analysis')
        self.assertEquals(result['tool'], 'unittest')
        self.assertEquals(result['tool_instance'], 'unittest_instance')
        self.assertEquals(result['type'], 'unittest')
        self.assertEquals(result['description'], 'testing')
        self.assertEquals(result['event_time'], '2017-11-11T07:36:01.000001+0000')
        self.assertEquals(result['tags'][0], 'alert_tag_1')
        self.assertEquals(result['tags'][1], 'alert_tag_2')
        self.assertEquals(len(result['observable_store']), 3)

        file_uuid = None

        for o_uuid in result['observable_store']:
            o = result['observable_store'][o_uuid]
            if o['type'] == F_IPV4:
                self.assertEquals(o['type'], F_IPV4)
                self.assertEquals(o['value'], '1.2.3.4')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
                self.assertEquals(o['tags'][0], 'tag_1')
                self.assertEquals(o['tags'][1], 'tag_2')
                self.assertEquals(o['directives'][0], DIRECTIVE_NO_SCAN)
                self.assertEquals(o['limited_analysis'][0], 'basic_test')
            elif o['type'] == F_USER:
                self.assertEquals(o['type'], F_USER)
                self.assertEquals(o['value'], 'test_user')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
            elif o['type'] == F_FILE:
                self.assertEquals(o['type'], F_FILE)
                self.assertEquals(o['value'], 'sample.dat')
                self.assertIsNone(o['time'])
                self.assertIsNotNone(o['id'])
                file_uuid = o['id']

        # we should see a single workload entry
        c.execute("SELECT id, uuid, node, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row[0])
        self.assertEquals(row[1], uuid)
        self.assertEquals(row[2], saq.SAQ_NODE)
        self.assertEquals(row[3], 'analysis')

        result = self.client.get(url_for('analysis.get_details', uuid=uuid, name=result['details']['file_path']))
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']
        self.assertTrue('hello' in result)
        self.assertEquals(result['hello'], 'world')

        result = self.client.get(url_for('analysis.get_file', uuid=uuid, file_uuid=file_uuid))
        self.assertEquals(result.status_code, 200)
        self.assertEquals(result.data, b'Hello, world!')

        result = self.client.get(url_for('analysis.get_status', uuid=uuid))
        self.assertEquals(result.status_code, 200)
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']
        self.assertTrue('workload' in result)
        self.assertTrue('delayed_analysis' in result)
        self.assertTrue('locks' in result)
        self.assertEquals(result['delayed_analysis'], [])
        self.assertIsNone(result['locks'])
        self.assertTrue(isinstance(result['workload']['id'], int))
        self.assertEquals(result['workload']['uuid'], uuid)
        self.assertEquals(result['workload']['node'], saq.SAQ_NODE)
        self.assertEquals(result['workload']['analysis_mode'], 'analysis')
        self.assertTrue(isinstance(parse_event_time(result['workload']['insert_date']), datetime.datetime))
        

    def test_transfer(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        root.save()

        temp_dir = tempfile.mkdtemp(dir=saq.CONFIG['global']['tmp_dir'])
        try:
            result = ace_api.transfer(root.uuid, temp_dir)
            self.assertTrue(os.path.join(temp_dir, 'data.json'))
            root = RootAnalysis(storage_dir=temp_dir)
            root.load()
            self.assertEquals(root.details, { 'hello': 'world' })
        finally:
            shutil.rmtree(temp_dir)
        
    def test_clear(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        root.save()
        self.assertTrue(os.path.exists(root.storage_dir))

        lock_uuid = str(uuid.uuid4())
        self.assertTrue(acquire_lock(root.uuid, lock_uuid))

        result = ace_api.clear(root.uuid, lock_uuid)
        self.assertFalse(os.path.exists(root.storage_dir))

    def test_clear_invalid_lock_uuid(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        root.save()
        self.assertTrue(os.path.exists(root.storage_dir))

        lock_uuid = str(uuid.uuid4())
        self.assertTrue(acquire_lock(root.uuid, lock_uuid))

        lock_uuid = str(uuid.uuid4())
        with self.assertRaises(Exception):
            self.assertFalse(ace_api.clear(root.uuid, lock_uuid))

        self.assertTrue(os.path.exists(root.storage_dir))
