# vim: sw=4:ts=4:et
import logging
import uuid

import saq
import saq.database
import saq.test

from saq.analysis import RootAnalysis
from saq.database import use_db
from saq.constants import *
from saq.test import *

from saq.engine.test_engine import TestEngine

class AlertModuleTestCase(ACEModuleTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.disable_all_modules()
        self.reset_workload()
        self.reset_correlation()

    @use_db
    def test_engine_detection(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_7')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_detection')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        # the analysis mode should have changed
        self.assertEquals(root.analysis_mode, saq.CONFIG['analysis_module_detection']['target_mode'])

        # make sure we detected the change in modes
        self.assertTrue(log_count('analysis mode for RootAnalysis({}) changed from test_empty to correlation'.format(root.uuid)) > 0)
        self.assertEquals(log_count('completed analysis RootAnalysis({})'.format(root.uuid)), 2)

    @use_db
    def test_engine_no_detection(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_detection')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        # the analysis mode should be the same
        self.assertEquals(root.analysis_mode, 'test_empty')

        # make sure we detected the change in modes
        self.assertEquals(log_count('analysis mode for RootAnalysis({}) changed from test_empty to correlation'.format(root.uuid)), 0)
        self.assertEquals(log_count('completed analysis RootAnalysis({})'.format(root.uuid)), 1)

    @use_db
    def test_engine_alert(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_7')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_detection')
        engine.enable_module('analysis_module_alert')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have a single entry in the alerts database table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)

    @use_db
    def test_engine_no_alert(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_detection')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should NOT have an entry in the alerts table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        self.assertIsNone(c.fetchone())

    @use_db
    def test_engine_existing_alert(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_7')
        root.save()
        root.schedule()

        # go ahead and insert the alert
        alert = saq.database.Alert()
        alert.storage_dir = root.storage_dir
        alert.load()
        alert.sync()
    
        # now analyze the alert that's already in the database
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_detection')
        engine.enable_module('analysis_module_alert')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have a single entry in the alerts database table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)

        # and we should have a warning about the alert already existing
        #self.assertEquals(log_count('uuid {} already exists in alerts table'.format(root.uuid)), 1)

    @use_db
    def test_engine_whitelisted(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_8')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_detection')
        engine.enable_module('analysis_module_alert')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have NO entries in the alerts database table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        row = c.fetchone()
        self.assertIsNone(row)

        # and we should have a warning about the alert already existing
        #self.assertEquals(log_count('uuid {} already exists in alerts table'.format(root.uuid)), 1)
