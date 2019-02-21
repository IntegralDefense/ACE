# vim: sw=4:ts=4:et
import logging

import saq
import saq.database
import saq.test

from saq.analysis import RootAnalysis
from saq.database import use_db, get_db_connection, ALERT, set_dispositions
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
        set_dispositions([root.uuid], DISPOSITION_FALSE_POSITIVE, UNITTEST_USER_ID)

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED ])
        engine.enable_module('analysis_module_faqueue_alert_analyzer', [ ANALYSIS_MODE_CORRELATION,
                                                                         ANALYSIS_MODE_DISPOSITIONED ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('updating crits_id 5c3c9e42ad951d6254d20f98 to status Informational'), 1)

        # change the disposition to anything except FALSE POSITIVE and the indicator becomes ANALYZED
        set_dispositions([root.uuid], DISPOSITION_WEAPONIZATION, UNITTEST_USER_ID)

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED ])
        engine.enable_module('analysis_module_faqueue_alert_analyzer', [ANALYSIS_MODE_CORRELATION,
                                                                        ANALYSIS_MODE_DISPOSITIONED])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('updating crits_id 5c3c9e42ad951d6254d20f98 to status Analyzed'), 1)
