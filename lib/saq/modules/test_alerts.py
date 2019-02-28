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
from saq.util import *

class TestCase(ACEModuleTestCase):
    @use_db
    def test_detection(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_7')
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=['test_groups', ANALYSIS_MODE_CORRELATION])
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # analysis will have moved over to data dir now
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()

        # make sure we detected the change in modes
        self.assertTrue(log_count('analysis mode for RootAnalysis({}) changed from test_groups to correlation'.format(root.uuid)) > 0)
        self.assertEquals(log_count('completed analysis RootAnalysis({})'.format(root.uuid)), 2)

    @use_db
    def test_no_detection(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        # the analysis mode should be the same
        self.assertEquals(root.analysis_mode, 'test_groups')

        # make sure we detected the change in modes
        self.assertEquals(log_count('analysis mode for RootAnalysis({}) changed from test_empty to correlation'.format(root.uuid)), 0)
        self.assertEquals(log_count('completed analysis RootAnalysis({})'.format(root.uuid)), 1)

    @use_db
    def test_alert(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_7')
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=['test_groups', ANALYSIS_MODE_CORRELATION])
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have a single entry in the alerts database table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)

    @use_db
    def test_no_alert(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should NOT have an entry in the alerts table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        self.assertIsNone(c.fetchone())

    @use_db
    def test_existing_alert(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
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
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test')
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
    def test_whitelisted(self, db, c):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_8')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have NO entries in the alerts database table
        c.execute("SELECT id FROM alerts WHERE uuid = %s", (root.uuid,))
        row = c.fetchone()
        self.assertIsNone(row)

        # and we should have a warning about the alert already existing
        #self.assertEquals(log_count('uuid {} already exists in alerts table'.format(root.uuid)), 1)

    def test_alert_dispositioned(self):

        from saq.database import Alert, User, Workload, set_dispositions

        # test the following scenario
        # 1) alert is generated
        # 2) ace begins to analyze the alert in correlation mode
        # 3) user sets the disposition of the alert WHILE ace is analyzing it
        # 4) ace detects the disposition and stops analyzing the alert
        # 5) ace picks up the alert in ANALYSIS_MODE_DISPOSITIONED mode

        saq.CONFIG['engine']['alert_disposition_check_frequency'] = '1'
        
        # create an analysis that turns into an alert
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_detection')
        observable_pause = root.add_observable(F_TEST, 'pause_3')
        root.save()
        root.schedule()
    
        engine = TestEngine(pool_size_limit=1, local_analysis_modes=['test_single', ANALYSIS_MODE_CORRELATION])
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test', ['test_single', ANALYSIS_MODE_CORRELATION])
        engine.enable_module('analysis_module_low_priority', ANALYSIS_MODE_CORRELATION)
        engine.enable_module('analysis_module_pause', ANALYSIS_MODE_CORRELATION)
        engine.start()

        # wait until we're processing the alert
        wait_for_log_count("processing This is only a test. mode correlation", 1, 10)

        # set the disposition of this alert
        set_dispositions([root.uuid],
                         DISPOSITION_FALSE_POSITIVE, 
                         saq.db.query(User).first().id)

        # look for analysis_module_alert_disposition_analyzer to cancel the analysis
        wait_for_log_count("detected disposition of alert", 1)

        # now wait for it to stop
        engine.controlled_stop()
        engine.wait()

        saq.db.close()
        alert = saq.db.query(Alert).filter(Alert.uuid == root.uuid).one()
        self.assertIsNotNone(alert)
        alert.load()

        observable_pause = alert.get_observable(observable_pause.id)
        self.assertIsNotNone(observable_pause)
        # since LowPriorityAnalysis executes *after* analysis_module_pause, it
        # should NOT have executed on this observable
        low_pri_analysis = observable_pause.get_analysis('LowPriorityAnalysis')
        self.assertIsNone(low_pri_analysis)

        # the mode should have changed to dispositioned 
        self.assertTrue(alert.analysis_mode, ANALYSIS_MODE_DISPOSITIONED)
        # and we should have a workload entry for this as well
        saq.db.close()
        self.assertIsNotNone(saq.db.query(Workload).filter(
                             Workload.uuid == alert.uuid, 
                             Workload.analysis_mode == ANALYSIS_MODE_DISPOSITIONED).first())

        # now with the analysis in correlation mode, if we start up the analysis again it should *NOT* analyze
        alert = saq.db.query(Alert).filter(Alert.uuid == root.uuid).one()
        self.assertIsNotNone(alert)
        alert.load()
        alert.schedule()

        engine = TestEngine(pool_size_limit=1, local_analysis_modes=[ANALYSIS_MODE_CORRELATION])
        engine.enable_alerting()
        engine.enable_module('analysis_module_basic_test', ['test_single', ANALYSIS_MODE_CORRELATION])
        engine.enable_module('analysis_module_low_priority', ANALYSIS_MODE_CORRELATION)
        engine.enable_module('analysis_module_pause', ANALYSIS_MODE_CORRELATION)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        wait_for_log_count('skipping analysis of dispositioned alert', 1)

        saq.db.close()
        alert = saq.db.query(Alert).filter(Alert.uuid == root.uuid).one()
        self.assertIsNotNone(alert)
        alert.load()

        observable_pause = alert.get_observable(observable_pause.id)
        self.assertIsNotNone(observable_pause)
        # since LowPriorityAnalysis executes *after* analysis_module_pause, it
        # should NOT have executed on this observable
        low_pri_analysis = observable_pause.get_analysis('LowPriorityAnalysis')
        self.assertIsNone(low_pri_analysis)
