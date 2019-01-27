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
from saq.database import get_db_connection, use_db, acquire_lock, clear_expired_locks, initialize_node
from saq.engine import Engine, DelayedAnalysisRequest, add_workload
from saq.network_client import submit_alerts
from saq.observables import create_observable
from saq.test import *
from saq.util import *

class TestCase(ACEEngineTestCase):

    def test_controlled_stop(self):

        engine = Engine()

        try:
            engine.start()
            engine.controlled_stop()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_immediate_stop(self):

        engine = Engine()

        try:
            engine.start()
            engine.stop()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_signal_TERM(self):

        engine = Engine()

        try:
            engine.start()
            
            def _send_signal():
                wait_for_log_count('waiting for engine process', 1)
                os.kill(engine.engine_process.pid, signal.SIGTERM)

            t = threading.Thread(target=_send_signal)
            t.start()

            engine.wait()

        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_signal_INT(self):

        engine = Engine()

        try:
            engine.start()
            
            def _send_signal():
                wait_for_log_count('waiting for engine process', 1)
                os.kill(engine.engine_process.pid, signal.SIGINT)

            t = threading.Thread(target=_send_signal)
            t.start()

            engine.wait()

        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def test_single_process(self):

        # test starting and stopping in single-process mode
        engine = Engine(single_threaded_mode=True)

        try:
            engine.start()
        except KeyboardInterrupt:
            pass

    def test_engine_default_pools(self):

        # test starting with no analysis pools defined
        engine = Engine()
        engine.start()
        engine.stop()
        engine.wait()

        # we should see this log message
        regex = re.compile(r'no analysis pools defined -- defaulting to (\d+) workers assigned to any pool')
        results = search_log_regex(regex)
        self.assertEquals(len(results), 1)
        m = regex.search(results[0].getMessage())
        self.assertIsNotNone(m)
        self.assertEquals(int(m.group(1)), cpu_count())

    @use_db
    def test_acquire_node_id(self, db, c):

        engine = Engine()
        engine.start()
        engine.stop()
        engine.wait()

        # when an Engine starts up it should acquire a node_id for saq.SAQ_NODE
        self.assertIsNotNone(saq.SAQ_NODE_ID)
        c.execute("""SELECT name, location, company_id, is_primary, any_mode, is_local 
                     FROM nodes WHERE id = %s""", (saq.SAQ_NODE_ID,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        _name, _location, _company_id, _is_primary, _any_mode, _is_local = row
        self.assertEquals(_name, saq.SAQ_NODE)
        self.assertEquals(_location, saq.API_PREFIX)
        self.assertEquals(_company_id, saq.COMPANY_ID)
        #self.assertIsInstance(_any_mode, int)
        #self.assertEquals(_any_mode, 0)
        self.assertIsInstance(_is_local, int)
        self.assertEquals(_is_local, 0)

    @use_db
    def test_acquire_local_node_id(self, db, c):

        engine = Engine()
        engine.set_local()
        engine.start()
        engine.stop()
        engine.wait()

        # when a local engine starts up it should acquire a local node with a uuid as the name
        self.assertIsNotNone(saq.SAQ_NODE_ID)
        c.execute("""SELECT name, location, company_id, is_primary, any_mode, is_local 
                     FROM nodes WHERE id = %s""", (saq.SAQ_NODE_ID,))
        row = c.fetchone()
        from saq.util import validate_uuid
        self.assertIsNotNone(row)
        _name, _location, _company_id, _is_primary, _any_mode, _is_local = row
        self.assertTrue(validate_uuid(_name))
        self.assertEquals(_company_id, saq.COMPANY_ID)
        #self.assertIsInstance(_any_mode, int)
        #self.assertEquals(_any_mode, 0)
        self.assertIsInstance(_is_local, int)
        self.assertEquals(_is_local, 1)

    def test_analysis_modes(self):

        engine = TestEngine()
        engine.initialize()
        engine.initialize_modules()

        # analysis mode test_empty should have 0 modules
        self.assertEquals(len(engine.analysis_mode_mapping['test_empty']), 0)

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test', 'test_empty')
        engine.enable_module('analysis_module_test_delayed_analysis', 'test_empty')
        engine.enable_module('analysis_module_test_engine_locking', 'test_empty')
        engine.enable_module('analysis_module_test_final_analysis', 'test_empty')
        engine.enable_module('analysis_module_test_post_analysis', 'test_empty')
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

    def test_single_process_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_single'
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

    def test_multi_process_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_single'
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

    def test_missing_analysis_mode(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.analysis_mode = None # <-- no analysis mode here
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.default_analysis_mode = 'test_single' # <-- default to test_single
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # the analysis mode should default to test_single
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        self.assertIsNone(root.analysis_mode)
        observable = root.get_observable(observable.id)
        self.assertIsNotNone(observable)
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

    def test_invalid_analysis_mode(self):

        # an invalid analysis mode happens when you submit an analysis to an engine
        # that supports any analysis mode but doesn't have any configuration settings
        # for the one that was submitted
        # in that case we use the default_analysis_mode

        # we're setting the analysis mode to an invalid value
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='foobar')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=[])
        engine.default_analysis_mode = 'test_single'
        engine.enable_module('analysis_module_basic_test')
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

    def test_multi_process_multi_analysis(self):

        uuids = []

        for _ in range(3):
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.storage_dir = storage_dir_from_uuid(root.uuid)
            root.initialize_storage()
            observable = root.add_observable(F_TEST, 'test_1')
            root.analysis_mode = 'test_single'
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

    def test_no_enabled_modules(self):

        # by default the analysis modules specified for the unit tests are disabled (globally)
        # so just starting up an engine should load no modules at all
        # even though there are modules enabled for the "test_groups" analysis mode
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('loading module '), 0)

    def test_globally_enabled_modules(self):

        # if we globally enable ALL modules then we should see the correct modules get loaded
        for section in saq.CONFIG.keys():
            if not section.startswith('analysis_module_'):
                continue

            saq.CONFIG[section]['enabled'] = 'yes'

        # the config file specifies test_empty,test_single,test_groups,test_disabled,test_cleanup as the 
        # locally supported analysis modes
        # so we should see only the modules assigned to these modes get loaded here
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # there should be 13 analysis modules loaded
        self.assertEquals(log_count('loading module '), 17)

    def test_locally_enabled_modules(self):
        
        # if we enable modules locally then ONLY those should get loaded
        # first we change the config to globally enable all modules
        for section in saq.CONFIG.keys():
            if not section.startswith('analysis_module_'):
                continue

            saq.CONFIG[section]['enabled'] = 'yes'

        engine = TestEngine(analysis_pools={'test_groups': 1})
        # this is the only module that should get loaded
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # even though 5 are specified and globally enabled, only 1 is loaded
        self.assertEquals(log_count('loading module '), 1)
        self.assertEquals(log_count('loading module analysis_module_basic_test'), 1)

    def test_no_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        # this test should return False instead of an Analysis
        observable = root.add_observable(F_TEST, 'test_2')
        root.analysis_mode = 'test_single'
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
        
        # so this should come back as False
        self.assertTrue(isinstance(observable.get_analysis(BasicTestAnalysis), bool))
        self.assertFalse(observable.get_analysis(BasicTestAnalysis))

    def test_no_analysis_no_return(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_3')
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
        
        # so what happens here is even though you return nothing from execute_analysis
        # execute_final_analysis defaults to returning False
        self.assertFalse(observable.get_analysis(BasicTestAnalysis))

        # you should also get a warning log
        wait_for_log_count('is not returning a boolean value', 1, 5)

    def test_delayed_analysis_single(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, '0:01|0:05')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        from saq.modules.test import DelayedAnalysisTestAnalysis

        root = create_root_analysis(uuid=root.uuid, storage_dir=storage_dir_from_uuid(root.uuid))
        root.load()
        analysis = root.get_observable(observable.id).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertIsNotNone(analysis)
        self.assertTrue(analysis.initial_request)
        self.assertTrue(analysis.delayed_request)
        self.assertEquals(analysis.request_count, 2)
        self.assertTrue(analysis.completed)

    def test_delayed_analysis_multiple(self):

        uuids = []
        
        for i in range(3):
            root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
            root.storage_dir = storage_dir_from_uuid(root.uuid)
            root.initialize_storage()
            observable = root.add_observable(F_TEST, '0:01|0:05')
            root.save()
            root.schedule()
            uuids.append((root.uuid, observable.id))

        engine = TestEngine()
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
        
    def test_delayed_analysis_timing(self):
        root_1 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root_1.initialize_storage()
        o_1 = root_1.add_observable(F_TEST, '0:04|0:10')
        root_1.save()
        root_1.schedule()

        root_2 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
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
        root_1 = RootAnalysis(uuid=root_1.uuid, storage_dir=root_1.storage_dir)
        root_1.load()
        analysis_1 = root_1.get_observable(o_1.id).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis_1.initial_request)
        self.assertTrue(analysis_1.delayed_request)
        self.assertEquals(analysis_1.request_count, 2)
        self.assertTrue(analysis_1.completed)

        root_2 = RootAnalysis(uuid=root_2.uuid, storage_dir=root_2.storage_dir)
        root_2.load()
        analysis_2 = root_2.get_observable(o_2.id).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis_2.initial_request)
        self.assertTrue(analysis_2.delayed_request)
        self.assertEquals(analysis_2.request_count, 2)
        self.assertTrue(analysis_2.completed)
        
        self.assertLess(analysis_2.complete_time, analysis_1.complete_time)

    def test_unix_signals(self):
        engine = TestEngine()
        engine.start()

        # tell ACE to reload the configuration and then reload all the workers
        os.kill(engine.engine_process.pid, signal.SIGHUP)

        wait_for_log_count('reloading engine configuration', 1, 5)
        wait_for_log_count('got command to restart workers', 1, 5)
        wait_for_log_count('started worker loop', 2)
        engine.controlled_stop()
        engine.wait()

    @track_io
    def test_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine(pool_size_limit=1)
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
    def test_delayed_analysis_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, '00:01|00:05')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine(pool_size_limit=1)
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

    def test_autorefresh(self):
        saq.CONFIG['engine']['auto_refresh_frequency'] = '3'
        engine = TestEngine(pool_size_limit=1)
        engine.start()
        wait_for_log_count('triggered reload of worker modules', 1)
        wait_for_log_count('detected death of process', 1)
        engine.controlled_stop()
        engine.wait()

    def test_final_analysis(self):
        """Test final analysis execution."""

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test')
        root.save() 
        root.schedule()

        engine = TestEngine(pool_size_limit=1)
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
    def test_final_analysis_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_test_final_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(_get_io_write_count(), 3) 
        self.assertEquals(_get_io_read_count(), 1)
        self.assertEquals(log_count('entering final analysis for '), 2)

    @track_io
    def test_final_analysis_io_count_2(self):
        """Same thing as before but we test with multiple observables."""
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable_1 = root.add_observable(F_TEST, 'test_01')
        observable_2 = root.add_observable(F_TEST, 'test_02')
        root.save() 
        root.schedule()

        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)

        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_test_final_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(_get_io_write_count(), 4) 
        self.assertEquals(_get_io_read_count(), 1)
        self.assertEquals(log_count('entering final analysis for '), 3)

    # ensure that post analysis is executed even if delayed analysis times out
    def test_delayed_analysis_timeout(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        test_observable = root.add_observable(F_TEST, '0:01|0:01')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_test_delayed_analysis_timeout', 'test_groups')
        engine.enable_module('analysis_module_test_post_analysis', 'test_groups')
        engine.start()

        # wait for delayed analysis to time out
        wait_for_log_count('has timed out', 1)

        engine.controlled_stop()
        engine.wait()

        # post analysis should have executed
        self.assertEquals(log_count('execute_post_analysis called'), 1)

    def test_wait_for_analysis(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
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

    def test_wait_for_disabled_analysis(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
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

    def test_wait_for_analysis_circ_dep(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
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

    def test_wait_for_analysis_missing_analysis(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
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

    def test_wait_for_analysis_circ_dep_chained(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
        engine.enable_module('analysis_module_test_wait_c', 'test_groups')
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

    def test_wait_for_analysis_chained(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_5')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
        engine.enable_module('analysis_module_test_wait_c', 'test_groups')
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

    def test_wait_for_analysis_delayed(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_6')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
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

    def test_wait_for_analysis_rejected(self):

        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C, \
                                     WaitAnalyzerModule_B

        
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_engine_032a')
        test_observable.exclude_analysis(WaitAnalyzerModule_B)
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_wait_a', 'test_groups')
        engine.enable_module('analysis_module_test_wait_b', 'test_groups')
        engine.enable_module('analysis_module_test_wait_c', 'test_groups')
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

    def test_post_analysis_after_false_return(self):
        # the execute_post_analysis function should be called regardless of what happened during analysis
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_post_analysis', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        test_observable = root.get_observable(test_observable.id)

        from saq.modules.test import PostAnalysisTestResult
        self.assertFalse(test_observable.get_analysis(PostAnalysisTestResult))
        self.assertEquals(log_count('execute_post_analysis called'), 1)

    def test_maximum_cumulative_analysis_warning_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_cumulative_analysis_warning_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        self.assertEquals(log_count('ACE has been analyzing'), 1)

    def test_maximum_cumulative_analysis_warning_time_analysis_mode(self):
        # same thing as before except we set the timeout for just the analysis mode
        # setting this to zero should cause it to happen right away
        saq.CONFIG['analysis_mode_test_groups']['maximum_cumulative_analysis_warning_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        self.assertEquals(log_count('ACE has been analyzing'), 1)

    def test_maximum_cumulative_analysis_fail_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_cumulative_analysis_fail_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('ACE took too long to analyze'), 1)

    def test_maximum_cumulative_analysis_fail_time_analysis_mode(self):
        # same thing as before except we set the timeout for just the analysis mode
        # setting this to zero should cause it to happen right away
        saq.CONFIG['analysis_mode_test_groups']['maximum_cumulative_analysis_fail_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('ACE took too long to analyze'), 1)

    def test_maximum_analysis_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_analysis_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # will fire again in final analysis
        self.assertEquals(log_count('excessive time - analysis module'), 2)

    def test_maximum_analysis_time_analysis_mode(self):
        # same thing as before except we set the timeout for just the analysis mode
        # setting this to zero should cause it to happen right away
        saq.CONFIG['analysis_mode_test_groups']['maximum_analysis_time'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()
        root.schedule()
        
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # will fire again in final analysis
        self.assertEquals(log_count('excessive time - analysis module'), 2)

    def test_is_module_enabled(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_dependency_test', 'test_groups')
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

    def test_analysis_mode_priority(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        test_1_uuid = root.uuid

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        root.schedule()
        test_2_uuid = root.uuid

        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should see test_2_uuid get selected BEFORE test_1_uuid gets selected
        results = [_.getMessage() for _ in search_log('got work item')]
        self.assertEquals(len(results), 2)
        self.assertEquals(results.index('got work item RootAnalysis({})'.format(test_2_uuid)), 0)

    def test_analysis_mode_no_priority(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()
        test_1_uuid = root.uuid

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        root.schedule()
        test_2_uuid = root.uuid

        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # since we don't have any kind of priority set they should get selected in order they were inserted (FIFO)
        # so we should see test_1_uuid get selected BEFORE test_2_uuid gets selected
        results = [_.getMessage() for _ in search_log('got work item')]
        self.assertEquals(len(results), 2)
        self.assertEquals(results.index('got work item RootAnalysis({})'.format(test_1_uuid)), 0)

    def test_merge(self):

        # first analysis
        root_1 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root_1.initialize_storage()
        test_observable_1 = root_1.add_observable(F_TEST, 'test_1')
        existing_user_observable = root_1.add_observable(F_USER, 'admin')
        root_1.save()
        root_1.schedule()

        # second analysis we want to merge into the first
        root_2 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
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

    def test_error_reporting(self):
        # trigger the failure this way
        saq.CONFIG['global']['maximum_cumulative_analysis_fail_time'] = '0'

        # remember what was already in the error reporting directory
        def _enum_error_reporting():
            return set(os.listdir(os.path.join(saq.DATA_DIR, 'error_reports')))

        existing_reports = _enum_error_reporting()

        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.copy_analysis_on_error = True
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
            path = os.path.join(os.path.join(saq.DATA_DIR, 'error_reports', _file))
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

    def test_stats(self):
        # clear engine statistics
        if os.path.exists(os.path.join(saq.MODULE_STATS_DIR, 'ace')):
            shutil.rmtree(os.path.join(saq.MODULE_STATS_DIR, 'ace'))

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
        self.assertEquals(len(os.listdir(os.path.join(saq.MODULE_STATS_DIR, 'ace'))), 1)
        subdir = os.listdir(os.path.join(saq.MODULE_STATS_DIR, 'ace'))
        subdir = subdir[0]

        # this should have a single stats file in it
        stats_files = os.listdir(os.path.join(os.path.join(saq.MODULE_STATS_DIR, 'ace', subdir)))
        self.assertEquals(len(stats_files), 1)

        # and it should not be empty
        self.assertGreater(os.path.getsize(os.path.join(os.path.join(saq.MODULE_STATS_DIR, 'ace', 
                                                                     subdir, stats_files[0]))), 0)

    def test_exclusion(self):

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

    def test_cleanup_alt_workdir(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_cleanup')
        root.storage_dir = workload_storage_dir(root.uuid)
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
        saq.CONFIG['analysis_mode_test_groups']['cleanup'] = 'yes'
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
        root.initialize_storage()
        observable = root.add_observable(F_TEST, '00:01|00:05')
        root.save()
        root.schedule()
    
        engine = TestEngine(analysis_pools={'test_groups': 1})
        engine.enable_module('analysis_module_test_delayed_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertFalse(os.path.isdir(root.storage_dir))
        self.assertEquals(log_count('not cleaning up RootAnalysis({}) (found outstanding work)'.format(root.uuid)), 1)

    def test_local_analysis_mode_single(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=['test_groups'], pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')
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

        # when we specify a default analysis mode that is not in the locally supported modes of the engine
        # it should automatically get added to the list of locally supported modes

        # we specify test_single as the supported local analysis mode, but the default is test_empty
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.analysis_mode = 'test_single'
        root.save()
        root.schedule()

        engine = TestEngine(local_analysis_modes=['test_empty'], 
                            default_analysis_mode='test_single', 
                            pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')
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

        # test_empty is specified as the only supported mode
        # but we specify a pool for test_single
        # this is a configuration error
        engine = TestEngine(local_analysis_modes=['test_empty'], 
                            default_analysis_mode='test_empty',
                            analysis_pools={'test_single': 1})

        wait_for_log_count('attempted to add analysis pool for mode test_single which is not supported by this engine', 1, 5)

    def test_local_analysis_mode_not_local(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        # but we target test_single for this analysis
        root.analysis_mode = 'test_single'
        root.save()
        root.schedule()

        # we say we only support test_empty analysis modes
        engine = TestEngine(local_analysis_modes=['test_empty'])
        engine.enable_module('analysis_module_basic_test', 'test_empty')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # this should exit out since the workload entry is for test_single analysis mode
        # but we don't support that with this engine so it shouldn't see it

    def test_local_analysis_mode_remote_pickup(self):

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

        # we say we only support test_empty analysis modes
        engine = TestEngine(local_analysis_modes=['test_empty'],
                            analysis_pools={'test_empty': 1})

        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        # this should exist out since we don't support this analysis mode with this engine instance
        engine.wait()

        # make sure our stuff is still there
        self.assertTrue(os.path.exists(old_storage_dir))

        # start an api server for this node
        self.start_api_server()
        self.reset_config()

        # now start another engine on a different "node"
        saq.CONFIG['global']['node'] = 'second_host'
        saq.set_node('second_host')
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
        wait_for_log_count('downloading work target {} from '.format(root.uuid), 1, 5)
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

        # we say we only support test_empty analysis modes
        engine = TestEngine(local_analysis_modes=['test_empty'], 
                            analysis_pools={'test_empty': 1})
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        # this should exit out since we do not support this analysis mode with this engine
        engine.wait()

        # make sure our stuff is still there
        self.assertTrue(os.path.exists(old_storage_dir))

        # start an api server for this node
        self.start_api_server()
        self.reset_config()

        # now start another engine on a different "node"
        saq.CONFIG['global']['node'] = 'second_host'
        saq.set_node('second_host')
        saq.CONFIG['analysis_mode_test_single']['cleanup'] = 'no'

        # and this node handles the test_single mode
        saq.CONFIG['engine']['local_analysis_modes'] = 'test_single'
        saq.CONFIG['engine']['analysis_pool_size_test_single'] = '1'

        engine = TestEngine(local_analysis_modes=['test_single'],
                            analysis_pools={'test_single': 1})
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        # we should see the same thing happen since the remote work is assigned to the other company
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
        c.execute("SELECT name, location, company_id, last_update FROM nodes WHERE id = %s", (saq.SAQ_NODE_ID,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEquals(row[0], saq.SAQ_NODE)
        self.assertEquals(row[1], saq.API_PREFIX)
        self.assertEquals(row[2], saq.COMPANY_ID)

        engine.stop()
        engine.wait()

    @use_db
    def test_node_modes_update(self, db, c):

        # when an Engine starts up it updates the node_modes database with the list of analysis modes it locally supports
        # configure to support two modes
        engine = TestEngine(local_analysis_modes=['test_empty', 'test_single'])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have two entries in the node_modes database for the current node_id
        c.execute("SELECT analysis_mode FROM node_modes WHERE node_id = %s ORDER BY analysis_mode ASC", (saq.SAQ_NODE_ID,))
        self.assertEquals(c.fetchone(), ('test_empty',))
        self.assertEquals(c.fetchone(), ('test_single',))

        # and the any_mode column should be 0 for this node
        c.execute("SELECT any_mode FROM nodes WHERE id = %s", (saq.SAQ_NODE_ID,))
        self.assertEquals(c.fetchone(), (0,))

    @use_db
    def test_node_modes_update_any(self, db, c):

        # when an Engine starts up it updates the node_modes database with the list of analysis modes it locally supports
        # configure to support two modes
        engine = TestEngine(local_analysis_modes=[])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have NO entries in the node_modes database for the current node_id
        c.execute("SELECT analysis_mode FROM node_modes WHERE node_id = %s ORDER BY analysis_mode ASC", (saq.SAQ_NODE_ID,))
        self.assertIsNone(c.fetchone())

        # and the any_mode column should be 1 for this node
        c.execute("SELECT any_mode FROM nodes WHERE id = %s", (saq.SAQ_NODE_ID,))
        self.assertEquals(c.fetchone(), (1,))

    @use_db
    def test_primary_node(self, db, c):

        # test having a node become the primary node
        saq.CONFIG['engine']['node_status_update_frequency'] = '1'
        engine = TestEngine()
        engine.start()
        
        wait_for_log_count('this node {} has become the primary node'.format(saq.SAQ_NODE), 1, 5)

        c.execute("SELECT name FROM nodes WHERE id = %s AND is_primary = 1", (saq.SAQ_NODE_ID,))
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

        c.execute("SELECT name FROM nodes WHERE id = %s AND is_primary = 1", (saq.SAQ_NODE_ID,))
        self.assertIsNotNone(c.fetchone())

        engine.stop()
        engine.wait()

        saq.set_node('another_node')
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

        c.execute("SELECT name FROM nodes WHERE id = %s AND is_primary = 1", (saq.SAQ_NODE_ID,))
        self.assertIsNotNone(c.fetchone())

        engine.stop()
        engine.wait()

        # update the node to make it look like it last updated a while ago
        c.execute("UPDATE nodes SET last_update = ADDTIME(last_update, '-1:00:00') WHERE id = %s", (saq.SAQ_NODE_ID,))
        db.commit()

        c.execute("SELECT last_update FROM nodes WHERE id = %s", (saq.SAQ_NODE_ID,))

        saq.set_node('another_node')
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

    @use_db
    def test_primary_node_clear_expired_local_nodes(self, db, c):
        # create a local node and have it expire
        engine = TestEngine()
        engine.set_local()
        engine.controlled_stop()
        engine.start()
        engine.stop()

        c.execute("UPDATE nodes SET last_update = ADDTIME(last_update, '-1:00:00') WHERE id = %s", (saq.SAQ_NODE_ID,))
        db.commit()

        saq.set_node('another_node')
        engine = TestEngine()
        engine.start()

        wait_for_log_count('removed 1 expired local nodes', 1, 5)
        engine.stop()
        engine.wait()

    def test_threaded_analysis_module(self):
        
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_threaded_test')
        engine.controlled_stop()
        engine.start()
        # we should see this execute at least once
        wait_for_log_count('threaded execution called', 1, 5)
        engine.wait()

    def test_threaded_analysis_module_broken(self):
        
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        root.schedule()

        # have this fail after 1 second of waiting
        saq.EXECUTION_THREAD_LONG_TIMEOUT = 1

        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_threaded_test_broken')
        engine.start()
        wait_for_log_count('is not stopping', 1, 6)
        wait_for_log_count('failing to stop - process dying', 1, 10)
        engine.stop()
        engine.wait()

    def test_engine_worker_recovery(self):
        
        # make sure the engine detects dead workers and replaces them
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_worker_death')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')
        engine.start()
        # we should see it die
        wait_for_log_count('detected death of', 1, 5)
        # and then we should have seen two workers start
        wait_for_log_count('started worker loop', 2, 5)
        engine.stop()
        engine.wait()

    @use_db
    def test_engine_exclusive_uuid(self, db, c):

        exclusive_uuid = str(uuid.uuid4())
        
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        root.save()
        root.schedule(exclusive_uuid)

        c.execute("SELECT exclusive_uuid FROM workload WHERE uuid = %s", (root.uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEquals(row[0], exclusive_uuid)
        
        # this engine should NOT process the work item
        # since the exclusive_uuid is NOT set
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')
        engine.start()
        # we should see this a bunch of times
        wait_for_log_count('workload.exclusive_uuid IS NULL', 3, 5)
        self.assertEquals(log_count('queue sizes workload 1 delayed 0'), 0)
        engine.stop()
        engine.wait()

        # this engine should process the work item
        engine = TestEngine(pool_size_limit=1)
        engine.exclusive_uuid = exclusive_uuid
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

    @use_db
    def test_clear_outstanding_locks(self, db, c):
        
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        root.add_observable(F_TEST, 'test_never_return')
        root.save()
        root.schedule()

        engine = TestEngine(pool_size_limit=1)
        engine.initialize() # get the node created

        # create an arbitrary lock
        from saq.database import acquire_lock
        self.assertTrue(acquire_lock(str(uuid.uuid4()), str(uuid.uuid4()), f'{saq.SAQ_NODE}-unittest-12345'))
        self.assertTrue(acquire_lock(str(uuid.uuid4()), str(uuid.uuid4()), f'some_other_node.local-unittest-12345'))
        
        # should have two locks now
        c.execute("SELECT COUNT(*) FROM locks")
        self.assertEquals(c.fetchone()[0], 2)
        db.commit()

        # initialize the engine again
        engine = TestEngine(pool_size_limit=1)
        engine.initialize()

        # should see a logging message about locks being deleted
        wait_for_log_count('clearing 1 locks from previous execution', 1, 5)

        # we should have one lock left, belong to the "other node"
        c.execute("SELECT lock_owner FROM locks")
        self.assertEquals(c.fetchone()[0], 'some_other_node.local-unittest-12345')

    def test_action_counters(self):
        
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test_action_counter_1')
        t2 = root.add_observable(F_TEST, 'test_action_counter_2')
        t3 = root.add_observable(F_TEST, 'test_action_counter_3')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we have an action count limit of 2, so 2 of these should have analysis and 1 should not
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()

        t1 = root.get_observable(t1.id)
        t2 = root.get_observable(t2.id)
        t3 = root.get_observable(t3.id)
    
        self.assertIsNotNone(t1)
        self.assertIsNotNone(t2)
        self.assertIsNotNone(t3)

        from saq.modules.test import BasicTestAnalysis
        analysis_count = 0
        for t in [ t1, t2, t3 ]:
            if t.get_analysis(BasicTestAnalysis):
                analysis_count += 1

        self.assertEquals(analysis_count, 2)

    def test_module_priority(self):
        
        root = create_root_analysis()
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_high_priority')
        engine.enable_module('analysis_module_low_priority')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should see the high priority execute before the low priority
        hp_log_entry = search_log('analyzing test(test) with HighPriorityAnalyzer')
        self.assertEquals(len(hp_log_entry), 1)
        hp_log_entry = hp_log_entry[0]

        lp_log_entry = search_log('analyzing test(test) with LowPriorityAnalyzer')
        self.assertEquals(len(lp_log_entry), 1)
        lp_log_entry = lp_log_entry[0]
        
        self.assertLess(hp_log_entry.created, lp_log_entry.created)

        # swap the priorities
        saq.CONFIG['analysis_module_high_priority']['priority'] = '1'
        saq.CONFIG['analysis_module_low_priority']['priority'] = '0'

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_high_priority')
        engine.enable_module('analysis_module_low_priority')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should see the high priority execute before the low priority
        hp_log_entry = search_log('analyzing test(test) with HighPriorityAnalyzer')
        self.assertEquals(len(hp_log_entry), 2)
        hp_log_entry = hp_log_entry[1]

        lp_log_entry = search_log('analyzing test(test) with LowPriorityAnalyzer')
        self.assertEquals(len(lp_log_entry), 2)
        lp_log_entry = lp_log_entry[1]
        
        self.assertLess(lp_log_entry.created, hp_log_entry.created)

        # test a high priority analysis against an analysis without a priority
        saq.CONFIG['analysis_module_high_priority']['priority'] = '0'
        del saq.CONFIG['analysis_module_low_priority']['priority']

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()

        saq.CONFIG['analysis_module_high_priority']['priority'] = '-1'
        saq.CONFIG['analysis_module_low_priority']['priority'] = '1'
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_high_priority')
        engine.enable_module('analysis_module_low_priority')
        engine.enable_module('analysis_module_no_priority')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should see the high priority execute before the low priority
        hp_log_entry = search_log('analyzing test(test) with HighPriorityAnalyzer')
        self.assertEquals(len(hp_log_entry), 3)
        hp_log_entry = hp_log_entry[2]

        lp_log_entry = search_log('analyzing test(test) with LowPriorityAnalyzer')
        self.assertEquals(len(lp_log_entry), 3)
        lp_log_entry = lp_log_entry[2]

        np_log_entry = search_log('analyzing test(test) with NoPriorityAnalyzer')
        self.assertEquals(len(np_log_entry), 1)
        np_log_entry = np_log_entry[0]
        
        self.assertLess(hp_log_entry.created, lp_log_entry.created)
        self.assertLess(lp_log_entry.created, np_log_entry.created)

    def test_post_analysis_multi_mode(self):
        
        root = create_root_analysis(analysis_mode='test_groups')
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1, local_analysis_modes=['test_groups', 'test_single', 'test_empty'])
        engine.enable_module('analysis_module_post_analysis_multi_mode', ['test_groups', 'test_single', 'test_empty'])
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # at the end of analysi sin test_groups mode post_analysis will execute and change the mode to test_single
        # it will happen again and change the mode to test_empty but will return True indicating post analysis has completed
        # so we should see the "execute_post_analysis called" message twice but not three times

        self.assertEquals(log_count('execute_post_analysis called'), 2)
        self.assertEquals(log_count('executing post analysis routines for'), 3)

    def test_post_analysis_delayed_analysis(self):

        root = create_root_analysis()
        root.storage_dir = storage_dir_from_uuid(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test_delayed')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_test_post_analysis')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('execute_post_analysis called'), 1)
        self.assertEquals(log_count('executing post analysis routines for'), 1)
    
    def test_alt_workload_move(self):

        # when an analysis moves into alert (correlation) mode and we are using an alt workload dir
        # then that analysis should move into the saq.DATA_DIR directory
        
        root = create_root_analysis()
        root.storage_dir = workload_storage_dir(root.uuid)
        root.initialize_storage()
        t1 = root.add_observable(F_TEST, 'test')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_forced_detection', 'test_groups')
        engine.enable_module('analysis_module_detection', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

    def test_analysis_reset(self):
        
        root = create_root_analysis()
        root.initialize_storage()
        o1 = root.add_observable(F_TEST, 'test_add_file')
        o2 = root.add_observable(F_TEST, 'test_action_counter')
        root.save()
        root.schedule()
        
        engine = TestEngine(pool_size_limit=1)
        engine.enable_module('analysis_module_basic_test')  
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        o1 = root.get_observable(o1.id)
        self.assertIsNotNone(o1)
        from saq.modules.test import BasicTestAnalysis
        analysis = o1.get_analysis(BasicTestAnalysis)
        self.assertIsNotNone(analysis)

        # this analysis should have two file observables
        file_observables = analysis.find_observables(lambda o: o.type == F_FILE)
        self.assertEquals(len(file_observables), 2)

        # make sure the files are actually there
        for _file in file_observables:
            self.assertTrue(os.path.exists(abs_path(_file.value)))

        # we should also have a non-empty state
        self.assertTrue(bool(root.state))

        # and we should have some action counters
        self.assertTrue(bool(root.action_counters))

        # reset the analysis
        root.reset()

        # the original observable should still be there
        o1 = root.get_observable(o1.id)
        self.assertIsNotNone(o1)
        analysis = o1.get_analysis(BasicTestAnalysis)
        # but it should NOT have analysis
        self.assertIsNone(analysis)

        # and that should be the only observable
        self.assertEquals(len(root.all_observables), 2)

        # and those two files should not exist anymore
        for _file in file_observables:
            self.assertFalse(os.path.exists(abs_path(_file.value)))

        #root.schedule()

        #engine = TestEngine(pool_size_limit=1)
        #engine.enable_module('analysis_module_basic_test')  
        #engine.controlled_stop()
        #engine.start()
        #engine.wait()
        
        #root = RootAnalysis(storage_dir=root.storage_dir)
        #observable = root.get_observable(observable.id)
        #self.assertIsNotNone(observable)
        #from saq.modules.test import BasicTestAnalysis
        #analysis = observable.get_analysis(BasicTestAnalysis)
        ##self.assertIsNotNone(analysis)
