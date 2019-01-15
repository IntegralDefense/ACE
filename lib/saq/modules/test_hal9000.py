# vim: sw=4:ts=4:et
import logging

import saq
import saq.database
import saq.test

from saq.analysis import RootAnalysis
from saq.database import use_db, get_db_connection
from saq.constants import *
from saq.test import *

from .hal9000 import HAL9000Analysis, _compute_hal9000_md5, \
                     KEY_MAL_COUNT, KEY_TOTAL_COUNT, STATE_KEY_ID_TRACKING, STATE_KEY_PREVIOUS_DISPOSITION

class TestCase(ACEModuleTestCase):

    @use_db(name='hal9000')
    def test_hal9000_no_alert(self, db, c):

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_ANALYSIS ])
        engine.set_cleanup(ANALYSIS_MODE_ANALYSIS, False)
        engine.enable_module('analysis_module_hal9000', ANALYSIS_MODE_ANALYSIS)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        # make sure we did NOT alert
        self.assertEquals(root.analysis_mode, ANALYSIS_MODE_ANALYSIS)

        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        analysis = test_observable.get_analysis(HAL9000Analysis)
        self.assertIsNotNone(analysis)

        # total count and mal count should both be 0
        self.assertEquals(analysis.total_count, 0)
        self.assertEquals(analysis.mal_count, 0)
        
        # we should have a single entry in the database for this observable
        hal9000_id = _compute_hal9000_md5(test_observable)
        
        c.execute("SELECT total_count, mal_count FROM observables WHERE id = UNHEX(%s)", (hal9000_id,))
        result = c.fetchone()
        self.assertIsNotNone(result)
        self.assertEquals(result[0], 1)
        self.assertEquals(result[1], 0)

        # verify the correct state is kept
        state = root.state['hal9000']
        
        self.assertTrue(STATE_KEY_ID_TRACKING in state)
        tracking = state[STATE_KEY_ID_TRACKING]
        self.assertTrue(hal9000_id in tracking)
        tracking_info = tracking[hal9000_id]
        self.assertTrue('id' in tracking_info)
        self.assertEquals(tracking_info['id'], test_observable.id)
        self.assertTrue(KEY_TOTAL_COUNT in tracking_info)
        self.assertTrue(KEY_MAL_COUNT in tracking_info)
        
        # since this doesn't become an alert we don't bother tracking the changes
        self.assertIsNone(tracking_info[KEY_TOTAL_COUNT])
        self.assertIsNone(tracking_info[KEY_MAL_COUNT])

    @use_db(name='hal9000')
    def test_hal9000_alert_no_disposition(self, db, c):

        # same as above except we end up alerting

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.set_cleanup(ANALYSIS_MODE_ANALYSIS, False)
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_hal9000', [ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        # make sure we alerted
        self.assertEquals(root.analysis_mode, ANALYSIS_MODE_CORRELATION)

        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        analysis = test_observable.get_analysis(HAL9000Analysis)
        self.assertIsNotNone(analysis)

        # total count and mal count should both be 0
        self.assertEquals(analysis.total_count, 0)
        self.assertEquals(analysis.mal_count, 0)
        
        # we should have a single entry in the database for this observable
        hal9000_id = _compute_hal9000_md5(test_observable)
        
        # since we have NOT set a disposition yet we should have nothing in the database about it
        c.execute("SELECT total_count, mal_count FROM observables WHERE id = UNHEX(%s)", (hal9000_id,))
        result = c.fetchone()
        self.assertIsNone(result)

        # verify the correct state is kept
        state = root.state['hal9000']
        
        self.assertTrue(STATE_KEY_ID_TRACKING in state)
        tracking = state[STATE_KEY_ID_TRACKING]
        self.assertTrue(hal9000_id in tracking)
        tracking_info = tracking[hal9000_id]
        self.assertTrue('id' in tracking_info)
        self.assertEquals(tracking_info['id'], test_observable.id)
        self.assertTrue(KEY_TOTAL_COUNT in tracking_info)
        self.assertTrue(KEY_MAL_COUNT in tracking_info)
        
        # we have not made any changes yet either
        self.assertIsNone(tracking_info[KEY_TOTAL_COUNT])
        self.assertIsNone(tracking_info[KEY_MAL_COUNT])

    @use_db(name='hal9000')
    def test_hal9000_alert_mal_disposition(self, db, c):

        # same as above except we end up alerting and disposition as malicious

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_ANALYSIS)
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.set_cleanup(ANALYSIS_MODE_ANALYSIS, False)
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_hal9000', [ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # XXX - fix this when you implement the gui api
        # right now the set_disposition function in the API is what both sets the disposition
        # and re-inserts the alert back into the workload

        # set the disposition for the alert
        with get_db_connection() as ace_db:
            ace_c = ace_db.cursor()
            ace_c.execute("""
                UPDATE alerts SET 
                    disposition = %s, 
                    disposition_user_id = %s, 
                    disposition_time = NOW(),
                    owner_id = %s, 
                    owner_time = NOW()
                WHERE 
                    uuid = %s
                    AND ( disposition IS NULL OR disposition != %s )""",
                ( DISPOSITION_DELIVERY, UNITTEST_USER_ID, UNITTEST_USER_ID, root.uuid, DISPOSITION_DELIVERY  ))

            ace_c.execute("""
                INSERT INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir ) 
                SELECT 
                    alerts.uuid, 
                    nodes.id,
                    %s, 
                    NOW(),
                    alerts.company_id, 
                    NULL, 
                    alerts.storage_dir 
                FROM 
                    alerts JOIN nodes ON alerts.location = nodes.name
                WHERE 
                    uuid = %s""", ( ANALYSIS_MODE_CORRELATION, root.uuid ))
            ace_db.commit()

        # run the engine again so that is processes the alert in correlation mode with the disposition set
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_hal9000', [ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        # make sure we alerted
        self.assertEquals(root.analysis_mode, ANALYSIS_MODE_CORRELATION)

        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        analysis = test_observable.get_analysis(HAL9000Analysis)
        self.assertIsNotNone(analysis)

        # these should still both be 0
        self.assertEquals(analysis.total_count, 0)
        self.assertEquals(analysis.mal_count, 0)
        
        # we should have a single entry in the database for this observable
        hal9000_id = _compute_hal9000_md5(test_observable)
        
        # with the disposition set we should have the corresponding values
        c.execute("SELECT total_count, mal_count FROM observables WHERE id = UNHEX(%s)", (hal9000_id,))
        result = c.fetchone()
        db.commit()
        self.assertIsNotNone(result)
        self.assertEquals(result[0], 1)
        self.assertEquals(result[1], 1)

        # verify the correct state is kept
        state = root.state['hal9000']
        
        self.assertTrue(STATE_KEY_ID_TRACKING in state)
        tracking = state[STATE_KEY_ID_TRACKING]
        self.assertTrue(hal9000_id in tracking)
        tracking_info = tracking[hal9000_id]
        self.assertTrue('id' in tracking_info)
        self.assertEquals(tracking_info['id'], test_observable.id)
        self.assertTrue(KEY_TOTAL_COUNT in tracking_info)
        self.assertTrue(KEY_MAL_COUNT in tracking_info)
        
        # we should be tracking the change we made in here
        self.assertIsNotNone(tracking_info[KEY_TOTAL_COUNT])
        self.assertIsNotNone(tracking_info[KEY_MAL_COUNT])

        # now we change it to FP
        with get_db_connection() as ace_db:
            ace_c = ace_db.cursor()
            ace_c.execute("""
                UPDATE alerts SET 
                    disposition = %s, 
                    disposition_user_id = %s, 
                    disposition_time = NOW(),
                    owner_id = %s, 
                    owner_time = NOW()
                WHERE 
                    uuid = %s
                    AND ( disposition IS NULL OR disposition != %s )""",
                ( DISPOSITION_FALSE_POSITIVE, UNITTEST_USER_ID, UNITTEST_USER_ID, root.uuid, DISPOSITION_FALSE_POSITIVE  ))

            ace_c.execute("""
                INSERT INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir ) 
                SELECT 
                    alerts.uuid, 
                    nodes.id,
                    %s, 
                    NOW(),
                    alerts.company_id, 
                    NULL, 
                    alerts.storage_dir 
                FROM 
                    alerts JOIN nodes ON alerts.location = nodes.name
                WHERE 
                    uuid = %s""", ( ANALYSIS_MODE_CORRELATION, root.uuid ))
            ace_db.commit()

        # run the engine again so that is processes the alert in the new correlation mode with the disposition changed
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_hal9000', [ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        analysis = test_observable.get_analysis(HAL9000Analysis)
        self.assertIsNotNone(analysis)

        # these should still both be 0
        self.assertEquals(analysis.total_count, 0)
        self.assertEquals(analysis.mal_count, 0)
        
        # we should have a single entry in the database for this observable
        hal9000_id = _compute_hal9000_md5(test_observable)
        
        # with the disposition set we should have the corresponding values
        c.execute("SELECT total_count, mal_count FROM observables WHERE id = UNHEX(%s)", (hal9000_id,))
        result = c.fetchone()
        db.commit()
        self.assertIsNotNone(result)
        self.assertEquals(result[0], 1)
        self.assertEquals(result[1], 0) # <-- should be 0 now that it's set to FP

        # verify the correct state is kept
        state = root.state['hal9000']
        
        self.assertTrue(STATE_KEY_ID_TRACKING in state)
        tracking = state[STATE_KEY_ID_TRACKING]
        self.assertTrue(hal9000_id in tracking)
        tracking_info = tracking[hal9000_id]
        self.assertTrue('id' in tracking_info)
        self.assertEquals(tracking_info['id'], test_observable.id)
        self.assertTrue(KEY_TOTAL_COUNT in tracking_info)
        self.assertTrue(KEY_MAL_COUNT in tracking_info)
        
        # we should be tracking the change we made in here
        self.assertIsNotNone(tracking_info[KEY_TOTAL_COUNT])
        self.assertIsNone(tracking_info[KEY_MAL_COUNT])

        # finally we change it to ignore, which should entirely remove the counters (set them to 0 anyways)
        with get_db_connection() as ace_db:
            ace_c = ace_db.cursor()
            ace_c.execute("""
                UPDATE alerts SET 
                    disposition = %s, 
                    disposition_user_id = %s, 
                    disposition_time = NOW(),
                    owner_id = %s, 
                    owner_time = NOW()
                WHERE 
                    uuid = %s
                    AND ( disposition IS NULL OR disposition != %s )""",
                ( DISPOSITION_IGNORE, UNITTEST_USER_ID, UNITTEST_USER_ID, root.uuid, DISPOSITION_IGNORE  ))

            ace_c.execute("""
                INSERT INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir ) 
                SELECT 
                    alerts.uuid, 
                    nodes.id,
                    %s, 
                    NOW(),
                    alerts.company_id, 
                    NULL, 
                    alerts.storage_dir 
                FROM 
                    alerts JOIN nodes ON alerts.location = nodes.name
                WHERE 
                    uuid = %s""", ( ANALYSIS_MODE_CORRELATION, root.uuid ))
            ace_db.commit()

        # run the engine again so that is processes the alert in the new correlation mode with the disposition changed
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_forced_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_detection', ANALYSIS_MODE_ANALYSIS)
        engine.enable_module('analysis_module_hal9000', [ ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        analysis = test_observable.get_analysis(HAL9000Analysis)
        self.assertIsNotNone(analysis)

        # these should still both be 0
        self.assertEquals(analysis.total_count, 0)
        self.assertEquals(analysis.mal_count, 0)
        
        # we should have a single entry in the database for this observable
        hal9000_id = _compute_hal9000_md5(test_observable)
        
        # with the disposition set we should have the corresponding values
        c.execute("SELECT total_count, mal_count FROM observables WHERE id = UNHEX(%s)", (hal9000_id,))
        result = c.fetchone()
        db.commit()
        self.assertIsNotNone(result)
        self.assertEquals(result[0], 0) # <-- now both should be set to 0
        self.assertEquals(result[1], 0) 

        # verify the correct state is kept
        state = root.state['hal9000']
        
        self.assertTrue(STATE_KEY_ID_TRACKING in state)
        tracking = state[STATE_KEY_ID_TRACKING]
        self.assertTrue(hal9000_id in tracking)
        tracking_info = tracking[hal9000_id]
        self.assertTrue('id' in tracking_info)
        self.assertEquals(tracking_info['id'], test_observable.id)
        self.assertTrue(KEY_TOTAL_COUNT in tracking_info)
        self.assertTrue(KEY_MAL_COUNT in tracking_info)
        
        # we should be tracking the change we made in here
        self.assertIsNone(tracking_info[KEY_TOTAL_COUNT])
        self.assertIsNone(tracking_info[KEY_MAL_COUNT])
