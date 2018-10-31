# vim: sw=4:ts=4:et

import logging
import os, os.path
import pickle
import re
import shutil
import signal
import tarfile
import tempfile
import threading
import unittest
import uuid

from multiprocessing import Queue, cpu_count, Event
from queue import Empty

import saq, saq.test
from saq.anp import *
from saq.analysis import RootAnalysis, _get_io_read_count, _get_io_write_count, Observable
from saq.constants import *
from saq.database import get_db_connection
from saq.engine import Engine, DelayedAnalysisRequest, SSLNetworkServer, MySQLCollectionEngine, ANPNodeEngine, add_workload
from saq.lock import LocalLockableObject
from saq.network_client import submit_alerts
from saq.observables import create_observable
from saq.test import *
from saq.util import storage_dir_from_uuid

class TestEngine(Engine):
    def __init__(self, *args, **kwargs):
        super().__init__(name='unittest', *args, **kwargs)

    def enable_module(self, module_name):
        """Adds a module to be enabled."""
        saq.CONFIG[module_name]['enabled'] = 'yes'
        saq.CONFIG['analysis_mode_test_empty'][module_name] = 'yes'

    def set_analysis_pool_size(self, count):
        saq.CONFIG['engine']['analysis_pool_size_any'] = str(count)

class EngineTestCase(ACEEngineTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("DELETE FROM workload")
            c.execute("DELETE FROM locks")
            c.execute("DELETE FROM delayed_analysis")
            db.commit()

        # we only want to enable specific modules
        for section in saq.CONFIG.keys():
            if section.startswith('analysis_module_'):
                saq.CONFIG[section]['enabled'] = 'no'

    def tearDown(self, *args, **kwargs):
        super().tearDown()
        # reload the configuration
        saq.load_configuration()

    def test_engine_000_controlled_stop(self):

        engine = Engine()

        try:
            engine.start()
            engine.controlled_stop()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_engine_immediate_stop(self):

        engine = Engine()

        try:
            engine.start()
            engine.stop()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_engine_signal_terminate(self):

        engine = Engine()

        try:
            engine.start()
            
            def _send_sigterm(pid):
                wait_for_log_count('waiting for engine process', 1)
                logging.info("sending SIGTERM to {}".format(pid))
                os.kill(pid, signal.SIGTERM)

            t = threading.Thread(target=_send_sigterm, args=(os.getpid(),))
            t.start()

            engine.wait()

        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_engine_single_process(self):
        """Test starting and stopping in single-process mode."""

        engine = Engine()
        started_event = threading.Event()
        
        def _terminate():
            started_event.wait()
            engine.stop()

        t = threading.Thread(target=_terminate)
        t.start()

        try:
            engine.single_threaded_start(started_event=started_event)
        except KeyboardInterrupt:
            pass

        t.join()

    def test_engine_default_pools(self):
        """Test starting with no analysis pools defined."""
        engine = Engine()
        engine.start()
        engine.stop()
        engine.wait()

        regex = re.compile(r'no analysis pools defined -- defaulting to (\d+) workers assigned to any pool')
        results = search_log_regex(regex)
        self.assertEquals(len(results), 1)
        m = regex.search(results[0].getMessage())
        self.assertIsNotNone(m)
        self.assertEquals(int(m.group(1)), cpu_count())

    def test_engine_analysis_modes(self):
        """Tests analysis mode module loading."""

        engine = TestEngine()
        engine.initialize()
        engine.initialize_modules()

        # analysis mode test_empty should have 0 modules
        self.assertEquals(len(engine.analysis_mode_mapping['test_empty']), 0)

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.enable_module('analysis_module_test_engine_locking')
        engine.enable_module('analysis_module_test_final_analysis')
        engine.enable_module('analysis_module_test_post_analysis')
        engine.initialize()
        engine.initialize_modules()
    
        # analysis mode test_single should have 1 module
        self.assertEquals(len(engine.analysis_mode_mapping['test_single']), 1)
        self.assertEquals(engine.analysis_mode_mapping['test_single'][0].config_section, 'analysis_module_basic_test')

        # analysis mode test_groups should have 5 modules
        self.assertEquals(len(engine.analysis_mode_mapping['test_groups']), 5)

        # analysis mode test_disabled should have 4 modules (minus basic_test)
        self.assertEquals(len(engine.analysis_mode_mapping['test_disabled']), 4)
        self.assertTrue('analysis_module_basic_test' not in [m.config_section for m in engine.analysis_mode_mapping['test_disabled']])

    def test_engine_single_process_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_empty'
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.single_threaded_start(analysis_mode_priority='test_single')

        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

    def test_engine_multi_process_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_empty'
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.set_analysis_pool_size(1)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

    def test_engine_missing_analysis_mode(self):

        # we're not setting the analysis mode here
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.set_analysis_pool_size(1)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # the analysis mode should default to test_empty
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

    def test_engine_invalid_analysis_mode(self):

        # we're setting the analysis mode to an invalid value
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='invalid')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.set_analysis_pool_size(1)
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # the analysis mode should default to test_empty but we should also get a warning
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)
        self.assertTrue(log_count('specifies invalid analysis mode') > 0)

    def test_engine_multi_process_multi_analysis(self):

        uuids = []

        for _ in range(3):
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.storage_dir = storage_dir_from_uuid(root.uuid)
            root.initialize_storage()
            observable = root.add_observable(F_TEST, 'test_1')
            root.analysis_mode = 'test_empty'
            root.save()
            root.schedule()
            uuids.append((root.uuid, observable.id))

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        for root_uuid, observable_uuid in uuids:
            root = RootAnalysis(uuid=root_uuid)
            root.storage_dir = storage_dir_from_uuid(root_uuid)
            root.load()
            observable = root.get_observable(observable_uuid)
            self.assertIsNotNone(observable)
            from saq.modules.test import BasicTestAnalysis
            analysis = observable.get_analysis(BasicTestAnalysis)
            self.assertIsNotNone(analysis)

    def test_engine_locks(self):
        from saq.database import acquire_lock, release_lock
        first_lock_uuid = str(uuid.uuid4())
        second_lock_uuid = str(uuid.uuid4())
        target_lock = str(uuid.uuid4())
        self.assertTrue(acquire_lock(target_lock, first_lock_uuid))
        self.assertFalse(acquire_lock(target_lock, second_lock_uuid))
        self.assertTrue(acquire_lock(target_lock, first_lock_uuid))
        release_lock(target_lock, first_lock_uuid)
        self.assertTrue(acquire_lock(target_lock, second_lock_uuid))
        self.assertFalse(acquire_lock(target_lock, first_lock_uuid))
        release_lock(target_lock, second_lock_uuid)

    def test_engine_lock_timeout(self):
        from saq.database import acquire_lock, release_lock
        OLD_TIMEOUT = saq.LOCK_TIMEOUT_SECONDS
        saq.LOCK_TIMEOUT_SECONDS = 0
        first_lock_uuid = str(uuid.uuid4())
        second_lock_uuid = str(uuid.uuid4())
        target_lock = str(uuid.uuid4())
        self.assertTrue(acquire_lock(target_lock, first_lock_uuid))
        self.assertTrue(acquire_lock(target_lock, second_lock_uuid))
        saq.LOCK_TIMEOUT_SECONDS = OLD_TIMEOUT

    def test_engine_no_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_2')
        root.analysis_mode = 'test_empty'
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(uuid=root.uuid, storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)

        from saq.modules.test import BasicTestAnalysis
        
        self.assertTrue(isinstance(observable.get_analysis(BasicTestAnalysis), bool))
        self.assertFalse(observable.get_analysis(BasicTestAnalysis))

    def test_engine_no_analysis_no_return(self):
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        root.schedule()

        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(uuid=root.uuid, storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)

        from saq.modules.test import BasicTestAnalysis
        
        # so what happens here is even though you return nothing from execute_analysis
        # execute_final_analysis defaults to returning False
        self.assertFalse(observable.get_analysis(BasicTestAnalysis))

    def test_engine_delayed_analysis_single(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, '0:01|0:05')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        from saq.modules.test import DelayedAnalysisTestAnalysis

        root = create_root_analysis(uuid=root.uuid, storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()
        analysis = root.get_observable(observable.id).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis.initial_request)
        self.assertTrue(analysis.delayed_request)
        self.assertEquals(analysis.request_count, 2)
        self.assertTrue(analysis.completed)

    def test_engine_delayed_analysis_multiple(self):

        uuids = []
        
        for i in range(3):
            root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
            root.storage_dir = storage_dir_from_uuid(root.uuid)
            root.initialize_storage()
            observable = root.add_observable(F_TEST, '0:01|0:05')
            root.save()
            root.schedule()
            uuids.append((root.uuid, observable.id))

        engine = TestEngine()
        engine.set_analysis_pool_size(2)
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        from saq.modules.test import DelayedAnalysisTestAnalysis

        for root_uuid, observable_uuid in uuids:
            root = create_root_analysis(uuid=root_uuid, storage_dir=storage_dir_from_uuid(root_uuid))
            root.load()
            analysis = root.get_observable(observable_uuid).get_analysis(DelayedAnalysisTestAnalysis)
            self.assertTrue(analysis.initial_request)
            self.assertTrue(analysis.delayed_request)
            self.assertEquals(analysis.request_count, 2)
            self.assertTrue(analysis.completed)
        
    def test_engine_delayed_analysis_timing(self):
        root_1 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root_1.initialize_storage()
        o_1 = root_1.add_observable(F_TEST, '0:02|0:10')
        root_1.save()
        root_1.schedule()

        root_2 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root_2.initialize_storage()
        o_2 = root_2.add_observable(F_TEST, '0:01|0:10')
        root_2.save()
        root_2.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        from saq.modules.test import DelayedAnalysisTestAnalysis

        # the second one should finish before the first one
        root_1 = RootAnalysis(uuid=root_1.uuid, storage_dir=storage_dir_from_uuid(root_1.uuid))
        root_1.load()
        analysis_1 = root_1.get_observable(o_1.id).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis_1.initial_request)
        self.assertTrue(analysis_1.delayed_request)
        self.assertEquals(analysis_1.request_count, 2)
        self.assertTrue(analysis_1.completed)

        root_2 = RootAnalysis(uuid=root_2.uuid, storage_dir=storage_dir_from_uuid(root_2.uuid))
        root_2.load()
        analysis_2 = root_2.get_observable(o_2.id).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis_2.initial_request)
        self.assertTrue(analysis_2.delayed_request)
        self.assertEquals(analysis_2.request_count, 2)
        self.assertTrue(analysis_2.completed)
        
        self.assertLess(analysis_2.complete_time, analysis_1.complete_time)

    def test_engine_unix_signals(self):
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.start()

        # tell ACE to reload the configuration and then reload all the workers
        os.kill(engine.engine_process.pid, signal.SIGHUP)

        self.assertTrue(wait_for_log_entry(lambda event: 'reloading engine configuration' in event.getMessage(), timeout=5))
        wait_for_log_count('starting workers', 2)
        engine.controlled_stop()
        # we rely on the logs to tell us that something happened that we expect
        self.assertEquals(log_count('reloading engine configuration'), 1)
        engine.wait()

    @track_io
    def test_engine_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # at this point it should have loaded the root analysis
        # and then saved it again along with the details for the BasicTestAnalysis
        self.assertEquals(_get_io_write_count(), 3) 
        self.assertEquals(_get_io_read_count(), 1)

        from saq.modules.test import BasicTestAnalysis

        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        self.assertEquals(_get_io_write_count(), 3)
        self.assertEquals(_get_io_read_count(), 2)
        analysis = root.get_observable(observable.id).get_analysis(BasicTestAnalysis)
        self.assertEquals(_get_io_read_count(), 2) # should not have loaded details yet...
        self.assertTrue(analysis.test_result)
        self.assertEquals(_get_io_read_count(), 3) 

    @track_io
    def test_engine_delayed_analysis_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, '00:01|00:05')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # expect 5 writes at this point
        # (1) initial root analysis save
        # (2) initial module save
        # (3) root analysis completed save
        # (4) updated module save
        # (5) root analysis completed save
        self.assertEquals(_get_io_write_count(), 5) 
        # and then 4 reads (one LOAD for each, iterated twice)
        self.assertEquals(_get_io_read_count(), 3)

        from saq.modules.test import DelayedAnalysisTestAnalysis

        root = create_root_analysis(uuid=root.uuid)
        self.assertTrue(root.load())
        self.assertEquals(_get_io_write_count(), 5)
        self.assertEquals(_get_io_read_count(), 4)
        analysis = root.get_observable(observable.id).get_analysis(DelayedAnalysisTestAnalysis)
        
        self.assertIsNotNone(analysis)
        self.assertEquals(_get_io_read_count(), 4) # should not have loaded details yet...
        self.assertTrue(analysis.delayed_request)
        self.assertEquals(_get_io_read_count(), 5) 

    def test_engine_autorefresh(self):
        saq.CONFIG['engine']['auto_refresh_frequency'] = '3'
        engine = TestEngine()
        engine.start()
        wait_for_log_count('triggered reload of worker modules', 1)
        engine.controlled_stop()
        engine.wait()

    def test_engine_final_analysis(self):
        """Test final analysis execution."""

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test')
        root.save() 
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_final_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have a single observable now
        root = create_root_analysis(uuid=root.uuid)
        root.load()
        self.assertEquals(len(root.all_observables), 1)
        self.assertTrue(root.has_observable(F_TEST, 'test'))
        from saq.modules.test import FinalAnalysisTestAnalysis
        analysis = root.get_observable(observable.id).get_analysis(FinalAnalysisTestAnalysis)
        self.assertIsNotNone(analysis)
        # we should have seen this twice since the modification of adding an analysis will triggert
        # final analysis again
        self.assertEquals(log_count('entering final analysis for '), 2)

    @track_io
    def test_engine_final_analysis_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_final_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(_get_io_write_count(), 3) 
        self.assertEquals(_get_io_read_count(), 1)
        self.assertEquals(log_count('entering final analysis for '), 2)

    @track_io
    def test_engine_final_analysis_io_count_2(self):
        """Same thing as before but we test with multiple observables."""
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable_1 = root.add_observable(F_TEST, 'test_01')
        observable_2 = root.add_observable(F_TEST, 'test_02')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_final_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(_get_io_write_count(), 4) 
        self.assertEquals(_get_io_read_count(), 1)
        self.assertEquals(log_count('entering final analysis for '), 3)

    # ensure that post analysis is executed even if delayed analysis times out
    def test_engine_delayed_analysis_timeout(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        test_observable = root.add_observable(F_TEST, '0:01|0:01')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_test_delayed_analysis_timeout')
        engine.enable_module('analysis_module_test_post_analysis')
        engine.set_analysis_pool_size(1)
        engine.start()

        # wait for delayed analysis to time out
        wait_for_log_count('has timed out', 1)

        engine.controlled_stop()
        engine.wait()

        # post analysis should have executed
        self.assertEquals(log_count('execute_post_analysis called'), 1)

    def test_engine_wait_for_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(uuid=root.uuid, storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))

        self.assertEquals(log_count("depends on"), 1)

    @clear_error_reports
    def test_engine_wait_for_disabled_analysis(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        #engine.enable_module('analysis_module_test_wait_b')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_B))

        #self.assertEquals(log_count("requested to wait for disabled (or missing) module"), 1)

    def test_engine_wait_for_analysis_circ_dep(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_B))

        self.assertEquals(log_count("CIRCULAR DEPENDENCY ERROR"), 1)

    def test_engine_wait_for_analysis_missing_analysis(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertFalse(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))

        # we would only see this log if A waited on B
        #self.assertEquals(log_count("did not generate analysis to resolve dep"), 1)

    def test_engine_wait_for_analysis_circ_dep_chained(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.enable_module('analysis_module_test_wait_c')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_B))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_C))

        self.assertEquals(log_count("CIRCULAR DEPENDENCY ERROR"), 1)

    def test_engine_wait_for_analysis_chained(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_5')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.enable_module('analysis_module_test_wait_c')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_C))

        self.assertEquals(log_count("CIRCULAR DEPENDENCY ERROR"), 0)

    def test_engine_wait_for_analysis_delayed(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_6')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))

    def test_engine_wait_for_analysis_rejected(self):

        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C, \
                                     WaitAnalyzerModule_B

        
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_engine_032a')
        test_observable.exclude_analysis(WaitAnalyzerModule_B)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.enable_module('analysis_module_test_wait_c')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertFalse(test_observable.get_analysis(WaitAnalysis_B))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_C))

    def test_engine_post_analysis_after_false_return(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_post_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)

        from saq.modules.test import PostAnalysisTestResult
        self.assertFalse(test_observable.get_analysis(PostAnalysisTestResult))
        self.assertEquals(log_count('execute_post_analysis called'), 1)

    def test_engine_maximum_cumulative_analysis_warning_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_cumulative_analysis_warning_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        self.assertEquals(log_count('ACE has been analyzing'), 1)

    def test_engine_maximum_cumulative_analysis_fail_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_cumulative_analysis_fail_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('ACE took too long to analyze'), 1)

    def test_engine_maximum_analysis_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_analysis_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # will fire again in final analysis
        self.assertEquals(log_count('excessive time - analysis module'), 2)

    def test_engine_is_module_enabled(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_dependency_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)
        
        from saq.modules.test import DependencyTestAnalysis, KEY_SUCCESS, KEY_FAIL
        analysis = test_observable.get_analysis(DependencyTestAnalysis)
        for key in analysis.details[KEY_SUCCESS].keys():
            self.assertTrue(analysis.details[KEY_SUCCESS][key])
        for key in analysis.details[KEY_FAIL].keys():
            self.assertFalse(analysis.details[KEY_FAIL][key])

    def test_engine_analysis_mode_priority(self):
        saq.CONFIG['engine']['analysis_pool_size_test_empty'] = '1'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        test_1_uuid = root.uuid

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        root.schedule()
        test_2_uuid = root.uuid

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should see test_2_uuid get selected BEFORE test_1_uuid gets selected
        results = [_.getMessage() for _ in search_log('got work item')]
        self.assertEquals(len(results), 2)
        self.assertEquals(results.index('got work item RootAnalysis({})'.format(test_2_uuid)), 0)

    def test_engine_analysis_mode_no_priority(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        test_1_uuid = root.uuid

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        root.schedule()
        test_2_uuid = root.uuid

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # since we don't have any kind of priority set they should get selected in order they were inserted (FIFO)
        # so we should see test_1_uuid get selected BEFORE test_2_uuid gets selected
        results = [_.getMessage() for _ in search_log('got work item')]
        self.assertEquals(len(results), 2)
        self.assertEquals(results.index('got work item RootAnalysis({})'.format(test_1_uuid)), 0)

    def test_engine_merge(self):

        # first analysis
        root_1 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root_1.initialize_storage()
        test_observable_1 = root_1.add_observable(F_TEST, 'test_1')
        existing_user_observable = root_1.add_observable(F_USER, 'admin')
        root_1.save()
        root_1.schedule()

        # second analysis we want to merge into the first
        root_2 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root_2.initialize_storage()
        test_observable_2 = root_2.add_observable(F_TEST, 'merge_test_1')
        root_2.save()
        root_2.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_merge_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        from saq.modules.test import BasicTestAnalysis, MergeTestAnalysis

        root_1.load()
        test_observable_1 = root_1.get_observable(test_observable_1.id)
        self.assertIsNotNone(test_observable_1)
        basic_analysis = test_observable_1.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(basic_analysis)
        
        root_2.load()
        root_1.merge(basic_analysis, root_2)
        root_1.save()

        # now the basic analysis should have the test_observable_2
        test_observable_2 = root_1.get_observable(test_observable_2.id)
        self.assertIsNotNone(test_observable_2)
        # and it should have the merge analysis
        merge_analysis = test_observable_2.get_analysis(MergeTestAnalysis)
        self.assertIsNotNone(merge_analysis)
        # and that should have a new observable of it's own
        output_observable = merge_analysis.get_observables_by_type(F_TEST)
        self.assertEquals(len(output_observable), 1)
        output_observable = output_observable[0]
        self.assertEquals(output_observable.value, 'test_output')
        self.assertTrue(output_observable.has_tag('test'))

        # there should also be a file observable
        file_observable = merge_analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observable), 1)
        file_observable = file_observable[0]
        with open(os.path.join(root_1.storage_dir, file_observable.value), 'r') as fp:
            self.assertEquals(fp.read(), 'test')

        # that should have a relationship to a URL observable
        self.assertEquals(len(file_observable.relationships), 1)
        self.assertEquals(file_observable.relationships[0].r_type, R_DOWNLOADED_FROM)
        url_observable = file_observable.relationships[0].target
        self.assertTrue(isinstance(url_observable, Observable))
        self.assertTrue(url_observable.value, F_URL)

        # we also merged an existing observable
        # so we should see this observable twice
        existing_observable = root_1.get_observable(existing_user_observable.id)
        self.assertIsNotNone(existing_observable)
        instance_copy = merge_analysis.get_observables_by_type(F_USER)
        self.assertEquals(len(instance_copy), 1)
        self.assertEquals(instance_copy[0].id, existing_observable.id)

    @reset_config
    def test_engine_error_reporting(self):
        # trigger the failure this way
        saq.CONFIG['global']['maximum_cumulative_analysis_fail_time'] = '0'

        # remember what was already in the error reporting directory
        def _enum_error_reporting():
            return set(os.listdir(os.path.join(saq.SAQ_HOME, 'error_reports')))

        existing_reports = _enum_error_reporting()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # look at what is in the error reporting directory now
        # exclude what we found before to find the new stuff
        new_reports = _enum_error_reporting() - existing_reports

        # we should have a single error report and a single storage directory in the error reporting directory
        self.assertEquals(len(new_reports), 2)

        # one should be a file and the other a directory
        file_path = None
        dir_path = None
        for _file in new_reports:
            path = os.path.join(os.path.join(saq.SAQ_HOME, 'error_reports', _file))
            if os.path.isfile(path):
                file_path = path
            if os.path.isdir(path):
                dir_path = path

        self.assertIsNotNone(file_path)
        self.assertIsNotNone(dir_path)

        # check that everything we expect to exist in the dir exists
        self.assertTrue(os.path.exists(os.path.join(dir_path, 'data.json')))
        self.assertTrue(os.path.exists(os.path.join(dir_path, 'saq.log')))
        self.assertTrue(os.path.isdir(os.path.join(dir_path, 'stats')))
        self.assertTrue(os.path.isdir(os.path.join(dir_path, '.ace')))

        # go ahead and remove these since we check for them after running tests to review actual error reports
        shutil.rmtree(dir_path)
        os.remove(file_path)

    def test_engine_stats(self):
        # clear engine statistics
        if os.path.exists(os.path.join(saq.MODULE_STATS_DIR, 'unittest')):
            shutil.rmtree(os.path.join(saq.MODULE_STATS_DIR, 'unittest'))

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # there should be one subdir in the engine's stats dir
        self.assertEquals(len(os.listdir(os.path.join(saq.MODULE_STATS_DIR, 'unittest'))), 1)
        subdir = os.listdir(os.path.join(saq.MODULE_STATS_DIR, 'unittest'))
        subdir = subdir[0]

        # this should have a single stats file in it
        stats_files = os.listdir(os.path.join(os.path.join(saq.MODULE_STATS_DIR, 'unittest', subdir)))
        self.assertEquals(len(stats_files), 1)

        # and it should not be empty
        self.assertGreater(os.path.getsize(os.path.join(os.path.join(saq.MODULE_STATS_DIR, 'unittest', 
                                                                     subdir, stats_files[0]))), 0)

    def test_engine_exclusion(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_6')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)
        # we should have two that were both excluded in different ways
        self.assertEquals(len(analysis.observables), 2)
        for new_observable in analysis.observables:
            new_observable = analysis.observables[0]
            new_analysis = new_observable.get_analysis(BasicTestAnalysis)
            self.assertFalse(new_analysis)
