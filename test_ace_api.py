# vim: ts=4:sw=4:et:cc=120

import os.path
import shutil
import tempfile
import uuid

import ace_api

import saq
from saq.analysis import RootAnalysis
from saq.database import acquire_lock
from saq.test import *

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
