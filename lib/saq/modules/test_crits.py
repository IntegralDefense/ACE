# vim: sw=4:ts=4:et
import logging

import saq
import saq.database
import saq.test

from saq.analysis import RootAnalysis
from saq.database import use_db, get_db_connection, ALERT
from saq.constants import *
from saq.test import *

class TestCase(ACEModuleTestCase):
    def test_faqueue_alert(self):
        
        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_CORRELATION, alert_type=ANALYSIS_TYPE_FAQUEUE)
        root.initialize_storage()
        root.details = { 'indicator': { 'crits_id': '5c3c9e42ad951d6254d20f98' } }
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_faqueue_alert_analyzer', ANALYSIS_MODE_CORRELATION)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        ALERT(root)

        # change the disposition to FALSE POSITIVE which will change the indicator into INFORMATIONAL
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

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_faqueue_alert_analyzer', ANALYSIS_MODE_CORRELATION)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('updating crits_id 5c3c9e42ad951d6254d20f98 to status Informational'), 1)

        # change the disposition to anything except FALSE POSITIVE and the indicator becomes ANALYZED
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
                ( DISPOSITION_WEAPONIZATION, UNITTEST_USER_ID, UNITTEST_USER_ID, root.uuid, DISPOSITION_WEAPONIZATION  ))

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

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_faqueue_alert_analyzer', ANALYSIS_MODE_CORRELATION)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('updating crits_id 5c3c9e42ad951d6254d20f98 to status Analyzed'), 1)
