# vim: sw=4:ts=4:et

import logging
import os
import shutil
import tarfile
import uuid

import saq
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.database import acquire_lock, release_lock, use_db
from api.test import *
from saq.test import *

from flask import url_for

class APIEngineTestCase(APIBasicTestCase):
    def test_transfer(self):

        # first create something to transfer
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        with open(os.path.join(root.storage_dir, 'test.dat'), 'w') as fp:
            fp.write('test')
        file_observable = root.add_observable(F_FILE, 'test.dat')
        root.save()

        # ask for a transfer
        result = self.client.get(url_for('engine.transfer', uuid=root.uuid))

        # we should get back a tar file
        tar_path = os.path.join(saq.SAQ_HOME, saq.CONFIG['global']['tmp_dir'], 'transfer.tar')
        output_dir = os.path.join(saq.CONFIG['global']['tmp_dir'], 'transfer')

        try:
            with open(tar_path, 'wb') as fp:
                for chunk in result.response:
                    fp.write(chunk)

            with tarfile.open(name=tar_path, mode='r|') as tar:
                tar.extractall(path=output_dir)

            root = RootAnalysis(storage_dir=output_dir)
            root.load()

            self.assertTrue('hello' in root.details)
            self.assertEquals('world', root.details['hello'])

            file_observable = root.get_observable(file_observable.id)
            self.assertTrue(os.path.exists(os.path.join(root.storage_dir, file_observable.value)))
            with open(os.path.join(root.storage_dir, file_observable.value), 'r') as fp:
                self.assertEquals(fp.read(), 'test')

        finally:
            try:
                os.remove(tar_path)
            except:
                pass

            try:
                shutil.rmtree(output_dir)
            except:
                pass

    def test_clear(self):

        # first create something to clear
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.details = { 'hello': 'world' }
        with open(os.path.join(root.storage_dir, 'test.dat'), 'w') as fp:
            fp.write('test')
        file_observable = root.add_observable(F_FILE, 'test.dat')
        root.save()

        lock_uuid = str(uuid.uuid4())

        # get a lock on it
        self.assertTrue(acquire_lock(root.uuid, lock_uuid))

        # clear it
        result = self.client.get(url_for('engine.clear', uuid=root.uuid, lock_uuid=lock_uuid))
        self.assertEquals(result.status_code, 200)

        # make sure it cleared
        self.assertFalse(os.path.exists(root.storage_dir))
