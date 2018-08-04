# vim: sw=4:ts=4:et

import os, os.path
import logging
import uuid
import pickle

import saq, saq.test
from saq.constants import *
from saq.database import Alert, get_db_connection
from saq.engine import DelayedAnalysisRequest
from saq.engine.ace import ACE, AnalysisRequest
from saq.engine.test_engine import AnalysisEngine, TerminatingMarker
from saq.network_client import submit_alerts
from saq.test import *

class CustomACEEngine(ACE, AnalysisEngine):
    def collect(self):
        ACE.collect(self)
        AnalysisEngine.collect(self)

    def process(self, work_item):
        if isinstance(work_item, AnalysisRequest):
            ACE.process(self, work_item)
        else:
            AnalysisEngine.process(self, work_item)

    def enable_module(self, module_name):
        """Adds a module to be enabled."""
        saq.CONFIG[module_name]['enabled'] = 'yes'
        saq.CONFIG['engine_ace'][module_name] = 'yes'

class ACECoreEngineTestCase(ACEEngineTestCase):
    def setUp(self, *args, **kwargs):
        ACEEngineTestCase.setUp(self, *args, **kwargs)

        config = saq.CONFIG['engine_ace']
        self.ssl_cert_path = config['ssl_cert_path']
        self.ssl_key_path = config['ssl_key_path']
        self.ssl_ca_path = config['ssl_ca_path']
        self.ssl_hostname = config['ssl_hostname']
        self.server_host = 'localhost'
        self.server_port = config.getint('server_port')

        # clear out the database for testing
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""DELETE FROM alerts""")
            c.execute("""DELETE FROM workload""")
            db.commit()
        
    def test_ace_engine_000_startup(self):
        """ACE engine startup and shutdown."""
        engine = ACE()
        self.start_engine(engine)
        engine.stop()
        self.wait_engine(engine)

    def test_ace_engine_001_basic_analysis(self):
        """Submit a single alert with no observables for analysis."""
        engine = ACE()
        self.start_engine(engine)

        root = create_root_analysis()
        root.initialize_storage()
        root.save()

        submit_alerts(self.server_host, self.server_port, self.ssl_cert_path, self.ssl_hostname,
                      self.ssl_key_path, self.ssl_ca_path, root.storage_dir)

        import time
        time.sleep(5)

        engine.stop()
        self.wait_engine(engine)

    @cleanup_delayed_analysis
    def test_ace_engine_002_persistent_engine(self):

        engine = CustomACEEngine()
        if os.path.exists(engine.delayed_analysis_path):
            os.remove(engine.delayed_analysis_path)

        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, '0:05|0:10').id
        root.save()

        alert = Alert()
        alert.storage_dir = root.storage_dir
        alert.load()
        alert.sync()
        alert.request_correlation()

        def callback():
            return os.path.exists(os.path.join(root.storage_dir, '.delayed'))
        self.assertTrue(self.wait_for_condition(callback))
        self.kill_engine(engine)
        
        self.assertTrue(os.path.exists(engine.delayed_analysis_path))
        with open(engine.delayed_analysis_path, 'rb') as fp:
            delayed_analysis = pickle.load(fp)

        if len(delayed_analysis) > 1:
            for item in delayed_analysis:
                print(item[1])
            self.fail("more than one delayed analysis request is available")

        next_time, dar = delayed_analysis[0] # dar == delayed_analysis_request
        from saq.engine import DelayedAnalysisRequest
        self.assertIsInstance(dar, DelayedAnalysisRequest)
        self.assertEquals(dar.storage_dir, root.storage_dir)
        self.assertEquals(dar.target_type, type(alert))
        self.assertEquals(dar.observable_uuid, o_uuid)
        self.assertEquals(dar.analysis_module, 'analysis_module_test_delayed_analysis')
        self.assertEquals(dar.uuid, root.uuid)
        self.assertFalse(dar.lock_proxy.is_locked())

        from saq.modules.test import DelayedAnalysisTestAnalysis

        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        analysis = root.get_observable(o_uuid).get_analysis(DelayedAnalysisTestAnalysis)

        self.assertTrue(analysis.initial_request)
        self.assertFalse(analysis.delayed_request)
        self.assertEquals(analysis.request_count, 1)
        self.assertFalse(analysis.completed)

        engine = CustomACEEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        analysis = root.get_observable(o_uuid).get_analysis(DelayedAnalysisTestAnalysis)

        self.assertTrue(analysis.initial_request)
        self.assertTrue(analysis.delayed_request)
        self.assertEquals(analysis.request_count, 2)
        self.assertTrue(analysis.completed)

        self.assertFalse(os.path.exists(engine.delayed_analysis_path))

    @cleanup_delayed_analysis
    def test_ace_engine_003_persistent_engine_multiple(self):
        """Multiple delayed analysis requests are saved at shutdown and reloaded at startup."""

        engine = CustomACEEngine()
        if os.path.exists(engine.delayed_analysis_path):
            os.remove(engine.delayed_analysis_path)

        tracking = {}  # key = storage_dir, value = observable uuid

        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)
        for _ in range(3):
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.initialize_storage()
            tracking[root.storage_dir] = root.add_observable(F_TEST, '0:10|0:15').id
            root.save()
            
            alert = Alert()
            alert.storage_dir = root.storage_dir
            alert.load()
            alert.sync()
            alert.request_correlation()

            def callback():
                return os.path.exists(os.path.join(root.storage_dir, '.delayed'))
            self.assertTrue(self.wait_for_condition(callback))

        self.kill_engine(engine)
        
        self.assertTrue(os.path.exists(engine.delayed_analysis_path))
        with open(engine.delayed_analysis_path, 'rb') as fp:
            delayed_analysis = pickle.load(fp)

        self.assertEquals(len(delayed_analysis), 3)

        from saq.modules.test import DelayedAnalysisTestAnalysis

        for storage_dir in tracking.keys():
            root = create_root_analysis(storage_dir=storage_dir)
            root.load()

            analysis = root.get_observable(tracking[storage_dir]).get_analysis(DelayedAnalysisTestAnalysis)

            self.assertTrue(analysis.initial_request)
            self.assertFalse(analysis.delayed_request)
            self.assertEquals(analysis.request_count, 1)
            self.assertFalse(analysis.completed)

        engine = CustomACEEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        for storage_dir in tracking.keys():
            root = create_root_analysis(storage_dir=storage_dir)
            root.load()
            analysis = root.get_observable(tracking[storage_dir]).get_analysis(DelayedAnalysisTestAnalysis)

            self.assertTrue(analysis.initial_request)
            self.assertTrue(analysis.delayed_request)
            self.assertEquals(analysis.request_count, 2)
            self.assertTrue(analysis.completed)

        self.assertFalse(os.path.exists(engine.delayed_analysis_path))
