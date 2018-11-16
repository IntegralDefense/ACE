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
from saq.analysis import RootAnalysis, _get_io_read_count, _get_io_write_count, Observable
from saq.constants import *
from saq.database import get_db_connection, use_db, acquire_lock, clear_expired_locks
from saq.engine import Engine, DelayedAnalysisRequest, add_workload
from saq.network_client import submit_alerts
from saq.observables import create_observable
from saq.test import *
from saq.util import storage_dir_from_uuid

class EngineTestCase(ACEEngineTestCase):

    def test_engine_controlled_stop(self):

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

        try:
            engine.single_threaded_start()
        except KeyboardInterrupt:
            pass

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
        #engine.controlled_stop() # redundant
        engine.single_threaded_start(mode='test_single')

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
        root.analysis_mode = None
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
        self.assertIsNone(root.analysis_mode)
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
        self.assertTrue(log_count('invalid analysis mode') > 0)

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
        o_1 = root_1.add_observable(F_TEST, '0:04|0:10')
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

        wait_for_log_count('reloading engine configuration', 1, 5)
        wait_for_log_count('got command to restart workers', 1, 5)
        wait_for_log_count('started worker loop', 2)
        engine.controlled_stop()
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
        self.clear_error_reports()

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
        engine.set_analysis_pool_size(1)
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

    def test_limited_analysis(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        observable.limit_analysis('basic_test')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.enable_module('analysis_module_test_engine_locking')
        engine.enable_module('analysis_module_test_final_analysis')
        engine.enable_module('analysis_module_test_post_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)

        # there should only be one analysis performed
        self.assertEquals(len(observable.all_analysis), 1)
        
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

        self.assertTrue(len(search_log('analysis for test(test_1) limited to 1 modules (basic_test)')) > 0)

    def test_limited_analysis_invalid(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        observable.limit_analysis('basic_tast') # mispelled test
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.enable_module('analysis_module_test_engine_locking')
        engine.enable_module('analysis_module_test_final_analysis')
        engine.enable_module('analysis_module_test_post_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)

        # there should be no analysis
        self.assertEquals(len(observable.all_analysis), 0)
        
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNone(analysis)

        self.assertTrue(len(search_log('specified unknown limited analysis')) > 0)

    def test_cleanup(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_cleanup')
        root.initialize_storage()
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertFalse(os.path.isdir(root.storage_dir))

    def test_no_cleanup(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertTrue(os.path.isdir(root.storage_dir))

    def test_cleanup_with_delayed_analysis(self):
        # we are set to cleanup, however, we don't because we have delayed analysis
        saq.CONFIG['analysis_mode_test_empty']['cleanup'] = 'yes'
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, '00:01|00:05')
        root.save()
        root.schedule()
    
        engine = TestEngine()
        engine.set_analysis_pool_size(1)
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertFalse(os.path.isdir(root.storage_dir))
        self.assertEquals(log_count('not cleaning up RootAnalysis({}) (found outstanding work)'.format(root.uuid)), 1)

    def test_local_analysis_mode_single(self):

        saq.CONFIG['engine']['local_analysis_modes'] = 'test_empty'

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

    def test_local_analysis_mode_missing_default(self):

        # we specify test_single as the supported local analysis mode, but the default is test_empty
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_single'

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

        # both test_empty and test_single should be in this list
        self.assertEquals(len(engine.local_analysis_modes), 2)
        self.assertTrue('test_single' in engine.local_analysis_modes)
        self.assertTrue('test_empty' in engine.local_analysis_modes)

    def test_local_analysis_mode_missing_pool(self):

        # we specify test_single as the default and the local mode
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_single'
        saq.CONFIG['engine']['default_analysis_mode'] = 'test_single'

        # we also specify an analysis pool for test_empty
        saq.CONFIG['engine']['analysis_pool_size_test_empty'] = '1'

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

        # XXX - do we really need the engine process?
        # the engine.local_analysis_modes doesn't get modified until it's running on a new process
        wait_for_log_count('engine.analysis_pool_size_test_empty specified but test_empty not in engine.local_analysis_modes', 1, 5)
        #self.assertEquals(len(engine.local_analysis_modes), 2)
        #self.assertTrue('test_single' in engine.local_analysis_modes)
        #self.assertTrue('test_empty' in engine.local_analysis_modes)

    def test_local_analysis_mode_not_local(self):

        # we say we only support test_empty analysis modes
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_empty'

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        # but we target test_single for this analysis
        root.analysis_mode = 'test_single'
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()

        # we should see this message over and over again
        wait_for_log_count('queue sizes workload 1 delayed 0', 5, 10)
        engine.stop()
        engine.wait()

    def test_local_analysis_mode_remote_pickup(self):

        # we say we only support test_empty analysis modes
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_empty'
        saq.CONFIG['engine']['analysis_pool_size_test_empty'] = '1'

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        # but we target test_single for this analysis
        root.analysis_mode = 'test_single'
        root.save()
        root.schedule()

        # remember the old storage dir
        old_storage_dir = root.storage_dir

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()

        # we should see this message over and over again
        wait_for_log_count('queue sizes workload 1 delayed 0', 5)
        engine.stop()
        engine.wait()

        # make sure our stuff is still there
        self.assertTrue(os.path.exists(old_storage_dir))

        # start an api server for this node
        self.start_api_server()
        self.reset_config()

        # now start another engine on a different "node"
        saq.CONFIG['global']['node'] = 'second_host'
        saq.SAQ_NODE = 'second_host'
        saq.CONFIG['analysis_mode_test_single']['cleanup'] = 'no'

        # and this node handles the test_single mode
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_single'
        saq.CONFIG['engine']['analysis_pool_size_test_single'] = '1'

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.start()

        # since this is remote we can't use the technique where we call controlled_stop and
        # wait for the queues to empty because only the local queue is checked (which is currently empty)

        # look for the log to move the work target
        wait_for_log_count('transferring work target {} from '.format(root.uuid), 1, 5)
        wait_for_log_count('completed analysis RootAnalysis({})'.format(root.uuid), 1, 5)
        engine.controlled_stop()
        engine.wait()

        # now the old storage directory should be gone
        self.assertFalse(os.path.exists(old_storage_dir))

        # but there should be a new one in the new "node"
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

    @use_db
    def test_local_analysis_mode_remote_pickup_invalid_company_id(self, db, c):

        # TestCase - we've got nothing to do locally but there is work
        # on a remote server, but that work is assigned to a different company
        # we do NOT grab that work

        # first we add a new company
        c.execute("INSERT INTO company ( name ) VALUES ( 'unittest' )")
        db.commit()

        # get the new company_id
        c.execute("SELECT id FROM company WHERE name = 'unittest'")
        row = c.fetchone()
        self.assertIsNotNone(row)
        other_company_id = row[0]

        # we say we only support test_empty analysis modes
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_empty'
        saq.CONFIG['engine']['analysis_pool_size_test_empty'] = '1'

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        # but we target test_single for this analysis
        root.analysis_mode = 'test_single'
        root.company_id = other_company_id
        root.save()
        root.schedule()

        # remember the old storage dir
        old_storage_dir = root.storage_dir

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()

        # we should see this message over and over again
        wait_for_log_count('queue sizes workload 1 delayed 0', 5)
        engine.stop()
        engine.wait()

        # make sure our stuff is still there
        self.assertTrue(os.path.exists(old_storage_dir))

        # start an api server for this node
        self.start_api_server()
        self.reset_config()

        # now start another engine on a different "node"
        saq.CONFIG['global']['node'] = 'second_host'
        saq.SAQ_NODE = 'second_host'
        saq.CONFIG['analysis_mode_test_single']['cleanup'] = 'no'

        # and this node handles the test_single mode
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_single'
        saq.CONFIG['engine']['analysis_pool_size_test_single'] = '1'

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.start()

        # we should see the same thing happen since the remote work is assigned to the other company
        wait_for_log_count('queue sizes workload 1 delayed 0', 5)
        engine.stop()
        engine.wait()

        # make sure our stuff is still there
        self.assertTrue(os.path.exists(old_storage_dir))

    @use_db
    def test_status_update(self, db, c):
        
        # start an empty engine and wait for the node update
        engine = TestEngine()
        engine.start()

        wait_for_log_count('updated node', 1, 5)
        
        # do we have an entry in the nodes database table?
        c.execute("SELECT node, location, company_id, last_update FROM nodes WHERE node = %s", (saq.SAQ_NODE,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEquals(row[0], saq.SAQ_NODE)
        self.assertEquals(row[1], saq.API_PREFIX)
        self.assertEquals(row[2], saq.COMPANY_ID)

        engine.stop()
        engine.wait()

    @use_db
    def test_primary_node(self, db, c):
        # test having a node become the primary node
        engine = TestEngine()
        engine.start()
        
        wait_for_log_count('this node {} has become the primary node'.format(saq.SAQ_NODE), 1, 5)

        c.execute("SELECT node FROM nodes WHERE node = %s AND is_primary = 1", (saq.SAQ_NODE,))
        self.assertIsNotNone(c.fetchone())

        engine.stop()
        engine.wait()

    @use_db
    def test_primary_node_contest(self, db, c):
        # test having a node become the primary node
        # and then another node NOT becoming a primary node because there already is one
        engine = TestEngine()
        engine.start()
        
        wait_for_log_count('this node {} has become the primary node'.format(saq.SAQ_NODE), 1, 5)

        c.execute("SELECT node FROM nodes WHERE node = %s AND is_primary = 1", (saq.SAQ_NODE,))
        self.assertIsNotNone(c.fetchone())

        engine.stop()
        engine.wait()

        saq.SAQ_NODE = 'another_node'
        engine = TestEngine()
        engine.start()

        wait_for_log_count('node {} is not primary'.format(saq.SAQ_NODE), 1, 5)
        engine.stop()
        engine.wait()

    @use_db
    def test_primary_node_contest_winning(self, db, c):
        # test having a node become the primary node
        # after another node times out
        engine = TestEngine()
        engine.start()
        
        wait_for_log_count('this node {} has become the primary node'.format(saq.SAQ_NODE), 1, 5)

        c.execute("SELECT node FROM nodes WHERE node = %s AND is_primary = 1", (saq.SAQ_NODE,))
        self.assertIsNotNone(c.fetchone())

        engine.stop()
        engine.wait()

        # update the node to make it look like it last updated a while ago
        c.execute("UPDATE nodes SET last_update = ADDTIME(last_update, '-1:00:00') WHERE node = %s", (saq.SAQ_NODE,))
        db.commit()

        saq.SAQ_NODE = 'another_node'
        engine = TestEngine()
        engine.start()

        wait_for_log_count('this node {} has become the primary node'.format(saq.SAQ_NODE), 1, 5)
        engine.stop()
        engine.wait()

    @use_db
    def test_primary_node_clear_locks(self, db, c):
        target = str(uuid.uuid4())
        lock_uuid = str(uuid.uuid4())
        self.assertTrue(acquire_lock(target, lock_uuid))
        saq.LOCK_TIMEOUT_SECONDS = 0
        # test having a node become the primary node
        # and then clearing out an expired lock
        engine = TestEngine()
        engine.start()
        
        wait_for_log_count('this node {} has become the primary node'.format(saq.SAQ_NODE), 1, 5)
        wait_for_log_count('removed 1 expired locks', 1, 5)

        engine.stop()
        engine.wait()

        # make sure the lock is gone
        c.execute("SELECT uuid FROM locks WHERE uuid = %s", (target,))
        self.assertIsNone(c.fetchone())

    def test_threaded_analysis_module(self):
        
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_empty'
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_threaded_test')
        engine.set_analysis_pool_size(1)
        engine.controlled_stop()
        engine.start()
        # we should see this execute at least once
        wait_for_log_count('threaded execution called', 1, 5)
        engine.wait()

    def test_threaded_analysis_module_broken(self):
        
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_empty'
        root.save()
        root.schedule()

        # have this fail after 1 second of waiting
        saq.EXECUTION_THREAD_LONG_TIMEOUT = 1

        engine = TestEngine()
        engine.enable_module('analysis_module_threaded_test_broken')
        engine.set_analysis_pool_size(1)
        engine.start()
        wait_for_log_count('is not stopping', 1, 6)
        wait_for_log_count('failing to stop - process dying', 1, 10)
        engine.stop()
        engine.wait()

    def test_engine_worker_recovery(self):
        
        # make sure the engine detects dead workers and replaces them
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_worker_death')
        root.analysis_mode = 'test_empty'
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.set_analysis_pool_size(1)
        engine.start()
        # we should see it die
        wait_for_log_count('detected death of', 1, 5)
        # and then we should have seen two workers start
        wait_for_log_count('started worker loop', 2, 5)
        engine.stop()
        engine.wait()
