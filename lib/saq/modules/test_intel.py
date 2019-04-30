# vim: sw=4:ts=4:et:cc=120

import saq
from saq.analysis import RootAnalysis
from saq.database import ALERT, set_dispositions
from saq.constants import *
from saq.test import *

import pysip

class TestCase(ACEModuleTestCase):
    def setUp(self):
        ACEModuleTestCase.setUp(self)

        if not saq.CONFIG['sip'].getboolean('enabled'):
            return

        # XXX get rid of verify=False
        self.sip_client = pysip.Client(saq.CONFIG['sip']['remote_address'], saq.CONFIG['sip']['api_key'], verify=False)

        # insert the indicator we'll test against
        self.test_indicator = self.sip_client.post('indicators', { 'type': 'Email - Address', 
                                                                   'value': 'badguy@evil.com' })
        self.test_indicator_id = self.test_indicator['id']
        self.assertTrue(isinstance(self.test_indicator_id, int))

    def tearDown(self):
        ACEModuleTestCase.tearDown(self)
        
        if not saq.CONFIG['sip'].getboolean('enabled'):
            return

        # remove the indicator we inserted
        self.sip_client.delete('indicators/{}'.format(self.test_indicator_id))

    def test_intel_analysis(self):
        if not saq.CONFIG['sip'].getboolean('enabled'):
            return

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_CORRELATION)
        root.initialize_storage()
        i = root.add_observable(F_INDICATOR, 'sip:{}'.format(self.test_indicator_id))
        self.assertIsNotNone(i)
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_intel_analyzer', ANALYSIS_MODE_CORRELATION)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        i = root.get_observable(i.id)
        self.assertIsNotNone(i)
        
        from saq.modules.intel import IntelAnalysis
        analysis = i.get_analysis(IntelAnalysis)
        self.assertIsNotNone(analysis)
        
        # what we get here should be the same as what we got when we inserted it
        self.assertEquals(analysis.details, self.test_indicator)
        
    def test_faqueue_alert(self):
        if not saq.CONFIG['sip'].getboolean('enabled'):
            return

        root = create_root_analysis(analysis_mode=ANALYSIS_MODE_CORRELATION, alert_type=ANALYSIS_TYPE_FAQUEUE)
        root.initialize_storage()
        root.details = { 'indicator': { 'sip_id': '1' } }
        root.save()
        root.schedule()
    
        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION ])
        engine.enable_module('analysis_module_faqueue_sip_alert_analyzer', ANALYSIS_MODE_CORRELATION)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        ALERT(root)
        set_dispositions([root.uuid], DISPOSITION_FALSE_POSITIVE, UNITTEST_USER_ID)

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED ])
        engine.enable_module('analysis_module_faqueue_sip_alert_analyzer', [ ANALYSIS_MODE_CORRELATION,
                                                                         ANALYSIS_MODE_DISPOSITIONED ])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('updating sip_id 1 to status Informational'), 1)

        # change the disposition to anything except FALSE POSITIVE and the indicator becomes ANALYZED
        set_dispositions([root.uuid], DISPOSITION_WEAPONIZATION, UNITTEST_USER_ID)

        engine = TestEngine(local_analysis_modes=[ ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED ])
        engine.enable_module('analysis_module_faqueue_sip_alert_analyzer', [ANALYSIS_MODE_CORRELATION,
                                                                        ANALYSIS_MODE_DISPOSITIONED])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('updating sip_id 1 to status Analyzed'), 1)
