# vim: sw=4:ts=4:et

import logging
import os, os.path
import pickle
import shutil
import signal
import tarfile
import tempfile
import unittest
import uuid

from multiprocessing import Queue, cpu_count, Event
from queue import Empty

import saq, saq.test
from saq.anp import *
from saq.analysis import RootAnalysis, _get_io_read_count, _get_io_write_count, Observable
from saq.constants import *
from saq.database import get_db_connection
from saq.engine import Engine, DelayedAnalysisRequest, SSLNetworkServer, MySQLCollectionEngine, ANPNodeEngine
from saq.lock import LocalLockableObject
from saq.network_client import submit_alerts
from saq.observables import create_observable
from saq.test import *

class TrackableWorkItem(object):
    def __init__(self):
        self.tracker_path = os.path.join(saq.SAQ_HOME, saq.test.test_dir, str(uuid.uuid4()))

    def mark_processed(self):
        with open(self.tracker_path, 'w') as fp:
            pass

    def is_processed(self):
        return os.path.exists(self.tracker_path)

    def cleanup(self):
        if os.path.exists(self.tracker_path):
            try:
                os.remove(self.tracker_path)
            except Exception as e:
                logging.error("unable to delete {}: {}".format(self.tracker_path, e))

class AnalysisRequest(LocalLockableObject):
    def __init__(self, target, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.uuid = target.uuid
        self.storage_dir = target.storage_dir

class TerminatingMarker(object):
    pass

class TestEngineBase(Engine):
        
    @property
    def name(self):
        return 'unittest'

    def enable_module(self, module_name):
        """Adds a module to be enabled."""
        saq.CONFIG[module_name]['enabled'] = 'yes'
        saq.CONFIG['engine_unittest'][module_name] = 'yes'

class BasicEngine(TestEngineBase):
    def collect(self):
        self.stop_collection()

class CollectionEngine(TestEngineBase):
    def __init__(self, work, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.work = work

    def collect(self):
        if not self.work:
            self.stop_collection()
            return None

        target = self.work[0]
        self.work = self.work[1:]
        return self.add_work_item(target)

    def process(self, work_item):
        if isinstance(work_item, TerminatingMarker):
            self.controlled_stop()
            return

        assert isinstance(work_item, TrackableWorkItem)
        work_item.mark_processed()

class AnalysisEngine(TestEngineBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inbound_queue = Queue()

    def queue_work_item(self, work_item):
        self.inbound_queue.put_nowait(work_item)
        
    def collect(self):
        try:
            work_item = self.inbound_queue.get(True, 1.0)
        except Empty:
            return

        if isinstance(work_item, TerminatingMarker):
            self.stop_collection()

        self.add_work_item(work_item)

    def process(self, work_item):
        if isinstance(work_item, TerminatingMarker):
            self.controlled_stop()
            return

        if isinstance(work_item, str):
            root = RootAnalysis(storage_dir=work_item)
            root.load()
        elif isinstance(work_item, AnalysisRequest):
            root = RootAnalysis(storage_dir=work_item.storage_dir)
            root.load()
            work_item.transfer_locks_to(root)
        else:
            raise ValueError("invalid work item: {}".format(type(work_item)))

        self.analyze(root)

    def post_analysis(self, root):
        pass

class NetworkEngine(SSLNetworkServer, AnalysisEngine):
    def handle_network_item(self, storage_dir):
        pass

class MySQLEngine(MySQLCollectionEngine, AnalysisEngine):
    def collect(self):
        # check to see if something was passed locally first
        AnalysisEngine.collect(self)
        # and then check SQL
        MySQLCollectionEngine.collect(self)

    def reset(self):
        """Clear the workload table."""
        with get_db_connection('workload') as db:
            c = db.cursor()
            c.execute("""DELETE FROM workload""") 
            db.commit()

class ANPEnabledEngine(ANPNodeEngine, AnalysisEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.anp_command_handler_event = Event()
        self.collect_client_mode_event = Event()
        self.collect_server_mode_event = Event()
        self.collect_local_mode_event = Event()

    def anp_command_handler(self, anp, command):
        """Called when an ANP message is received."""
        self.anp_command_handler_event.set()

    def collect_client_mode(self):
        """Called to collect work to perform and submit it to a remote ANP node."""
        self.collect_client_mode_event.set()

    def collect_server_mode(self):
        """Called when work is submitted from a client."""
        self.collect_server_mode_event.set()

    def collect_local_mode(self):
        """Called when the node is operating in local mode (not using ANP at all.)"""
        self.collect_local_mode_event.set()

class EngineTestCase(ACEEngineTestCase):

    @modify_logging_level(logging.ERROR)
    def test_engine_000_basic_engine_controlled_stop(self):

        engine = BasicEngine()

        try:
            engine.start()
            engine.controlled_stop()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    @modify_logging_level(logging.ERROR)
    def test_engine_001_basic_engine_immediate_stop(self):

        engine = BasicEngine()

        try:
            engine.start()
            engine.stop()
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    @modify_logging_level(logging.ERROR)
    def test_engine_002_basic_engine_signal_terminate(self):

        engine = BasicEngine()

        try:
            engine.start()
            os.kill(os.getpid(), signal.SIGTERM)
            engine.wait()
        except KeyboardInterrupt:
            engine.stop()
            engine.wait()

    def verify_work_items_processed(self, work):
        for item in work:
            if isinstance(item, TrackableWorkItem):
                self.assertTrue(item.is_processed())

    def cleanup_work_items(self, work):
        for item in work:
            if isinstance(item, TrackableWorkItem):
                item.cleanup()

    @modify_logging_level(logging.ERROR)
    def test_engine_003_single_collection(self):
        work = [TerminatingMarker()]
        engine = CollectionEngine(work)
        self.execute_engine_test(engine)
        self.verify_work_items_processed(work)
        self.cleanup_work_items(work)

    @modify_logging_level(logging.ERROR)
    def test_engine_004_multiple_collection(self):
        work = [TrackableWorkItem() for _ in range(10)]
        work.append(TerminatingMarker())
        engine = CollectionEngine(work)
        self.execute_engine_test(engine)
        self.verify_work_items_processed(work)
        self.cleanup_work_items(work)

    def basic_analysis_test(self, count):
        if count > 1:
            saq.CONFIG['engine_unittest']['analysis_pool_size'] = str(count)

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)

        o_uuids = {} # key = storage_dir, value = o_uuid

        for i in range(count):
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.initialize_storage()
            o_uuids[root.storage_dir] = root.add_observable(F_TEST, 'test_1').id
            root.save()
            engine.queue_work_item(root.storage_dir)

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        from saq.modules.test import BasicTestAnalysis

        for storage_dir in o_uuids.keys():
            root = create_root_analysis(storage_dir=storage_dir)
            root.load()
            analysis = root.get_observable(o_uuids[storage_dir]).get_analysis(BasicTestAnalysis)
            self.assertTrue(analysis.test_result)

    def test_engine_005_basic_analysis(self):
        self.basic_analysis_test(1)

    def test_engine_005_2_no_analysis(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_2')
        root.save()
        engine.queue_work_item(root.storage_dir)

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)

        from saq.modules.test import BasicTestAnalysis
        
        self.assertTrue(isinstance(observable.get_analysis(BasicTestAnalysis), bool))
        self.assertFalse(observable.get_analysis(BasicTestAnalysis))

    def test_engine_005_3_no_analysis_no_return(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        engine.queue_work_item(root.storage_dir)

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        observable = root.get_observable(observable.id)

        from saq.modules.test import BasicTestAnalysis
        
        # so what happens here is even though you return nothing from execute_analysis
        # execute_final_analysis defaults to returning False
        self.assertFalse(observable.get_analysis(BasicTestAnalysis))

    def delayed_analysis_test(self, count):
        if count > 1:
            saq.CONFIG['engine_unittest']['analysis_pool_size'] = str(count)

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)

        o_uuids = {} # key = storage_dir, value = o_uuid
        
        for i in range(count):
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.initialize_storage()
            o_uuids[root.storage_dir] = root.add_observable(F_TEST, '0:01|0:05').id
            root.save()
            engine.queue_work_item(root.storage_dir)

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        from saq.modules.test import DelayedAnalysisTestAnalysis

        for storage_dir in o_uuids.keys():
            root = create_root_analysis(storage_dir=storage_dir)
            root.load()
            analysis = root.get_observable(o_uuids[storage_dir]).get_analysis(DelayedAnalysisTestAnalysis)
            self.assertTrue(analysis.initial_request)
            self.assertTrue(analysis.delayed_request)
            self.assertEquals(analysis.request_count, 2)
            self.assertTrue(analysis.completed)
        
    @cleanup_delayed_analysis
    def test_engine_006_delayed_analysis(self):
        self.delayed_analysis_test(1)

    @cleanup_delayed_analysis
    @clear_log
    def test_engine_007_delayed_analysis_timing(self):
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)
        root_1 = create_root_analysis(uuid=str(uuid.uuid4()))
        root_1.initialize_storage()
        o_1_uuid = root_1.add_observable(F_TEST, '0:02|0:10').id
        root_1.save()
        engine.queue_work_item(root_1.storage_dir)
        root_2 = create_root_analysis(uuid=str(uuid.uuid4()))
        root_2.initialize_storage()
        o_2_uuid = root_2.add_observable(F_TEST, '0:01|0:10').id
        root_2.save()
        engine.queue_work_item(root_2.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)
        
        # we're expecting 2 here
        # 1 fires right away because when we add a delayed analysis request to the system
        # it forces the whole thing to cycle
        # so the initial request ends up getting looked at twice

        self.assertEquals(log_count('is not ready current time'), 2)

        from saq.modules.test import DelayedAnalysisTestAnalysis

        # the second one should finish before the first one
        root_1 = RootAnalysis(storage_dir=root_1.storage_dir)
        root_1.load()
        analysis_1 = root_1.get_observable(o_1_uuid).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis_1.initial_request)
        self.assertTrue(analysis_1.delayed_request)
        self.assertEquals(analysis_1.request_count, 2)
        self.assertTrue(analysis_1.completed)

        root_2 = RootAnalysis(storage_dir=root_2.storage_dir)
        root_2.load()
        analysis_2 = root_2.get_observable(o_2_uuid).get_analysis(DelayedAnalysisTestAnalysis)
        self.assertTrue(analysis_2.initial_request)
        self.assertTrue(analysis_2.delayed_request)
        self.assertEquals(analysis_2.request_count, 2)
        self.assertTrue(analysis_2.completed)
        
        self.assertLess(analysis_2.complete_time, analysis_1.complete_time)

    @clear_log
    def test_engine_010_signals(self):
        engine = AnalysisEngine()
        self.start_engine(engine)
        # sending a signal to the main parent process will resend to child processes
        os.kill(os.getpid(), signal.SIGHUP)
        self.assertTrue(wait_for_log_entry(lambda event: 'reloading collection configuration' in event.getMessage(), timeout=5))
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)
        # we rely on the logs to tell us that something happened that we expect
        self.assertEquals(log_count('reloading collection configuration'), 1)

    @track_io
    def test_engine_011_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, 'test_1').id
        root.save() 
        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        # at this point it should have loaded the root analysis
        # and then saved it again along with the details for the BasicTestAnalysis
        self.assertEquals(_get_io_write_count(), 3) 
        self.assertEquals(_get_io_read_count(), 1)

        from saq.modules.test import BasicTestAnalysis

        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        self.assertEquals(_get_io_write_count(), 3)
        self.assertEquals(_get_io_read_count(), 2)
        analysis = root.get_observable(o_uuid).get_analysis(BasicTestAnalysis)
        self.assertEquals(_get_io_read_count(), 2) # should not have loaded details yet...
        self.assertTrue(analysis.test_result)
        self.assertEquals(_get_io_read_count(), 3) 

    @track_io
    def test_engine_012_delayed_analysis_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_delayed_analysis')
        self.start_engine(engine)
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, '00:01|00:05').id
        root.save() 
        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

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

        root = create_root_analysis(storage_dir=root.storage_dir)
        self.assertTrue(root.load())
        self.assertEquals(_get_io_write_count(), 5)
        self.assertEquals(_get_io_read_count(), 4)
        analysis = root.get_observable(o_uuid).get_analysis(DelayedAnalysisTestAnalysis)
        
        self.assertIsNotNone(analysis)
        self.assertEquals(_get_io_read_count(), 4) # should not have loaded details yet...
        self.assertTrue(analysis.delayed_request)
        self.assertEquals(_get_io_read_count(), 5) 

    @unittest.skipIf(cpu_count() < 2, "skipping multi cpu tests (single core system detected)")
    def test_engine_013_basic_analysis_multi_process(self):
        self.basic_analysis_test(cpu_count())

    @cleanup_delayed_analysis
    @unittest.skipIf(cpu_count() < 2, "skipping multi cpu tests (single core system detected)")
    def test_engine_014_delayed_analysis_multi_process(self):
        if cpu_count() == 1:
            return

        self.delayed_analysis_test(cpu_count())
        
    def test_engine_015_locking(self):  
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_engine_locking')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.add_observable(F_TEST, 'test')
        root.save()

        # using an AnalysisRequest is required here to test the locking
        engine.queue_work_item(AnalysisRequest(root))
        engine.queue_work_item(TerminatingMarker())

        # wait for the analysis module to signal it's processing it
        message = recv_test_message()
        is_locked = root.is_locked()
        can_lock = root.lock()
        send_test_message('ok')
        self.wait_engine(engine)

        self.assertTrue(is_locked)
        self.assertFalse(can_lock)
        self.assertFalse(root.is_locked()) # should not be locked when we're done

    def test_engine_016_delayed_analysis_locking(self):  
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_engine_locking')
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.add_observable(F_TEST, 'test')
        root.save()

        # using an AnalysisRequest is required here to test the locking
        engine.queue_work_item(AnalysisRequest(root))
        engine.queue_work_item(TerminatingMarker())

        # wait for the analysis module to signal it's processing it
        message = recv_test_message()
        is_locked = root.is_locked()
        can_lock = root.lock()
        send_test_message('ok')
        self.wait_engine(engine)

        self.assertTrue(is_locked)
        self.assertFalse(can_lock)

    def test_engine_017_expected_function_calls(self):
        class TestEngine(AnalysisEngine):
            def post_analysis(self, root):
                root.add_observable(F_TEST, 'post_analysis')

        engine = TestEngine()
        self.start_engine(engine)

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.save()

        # using an AnalysisRequest is required here to test the locking
        engine.queue_work_item(AnalysisRequest(root))
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        self.assertTrue(root.has_observable(F_TEST, 'post_analysis'))

    @clear_log
    def test_engine_018_final_analysis(self):
        """Test final analysis execution."""
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_final_analysis')
        self.start_engine(engine)
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, 'test').id
        root.save() 
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        # we should have a single observable now
        root = create_root_analysis(storage_dir=root.storage_dir)
        root.load()
        self.assertEquals(len(root.all_observables), 1)
        self.assertTrue(root.has_observable(F_TEST, 'test'))
        from saq.modules.test import FinalAnalysisTestAnalysis
        analysis = root.get_observable(o_uuid).get_analysis(FinalAnalysisTestAnalysis)
        self.assertIsNotNone(analysis)
        # we should have seen this twice since the modification of adding an analysis will triggert
        # final analysis again
        self.assertEquals(log_count('entering final analysis for '), 2)

    @track_io
    @clear_log
    def test_engine_019_final_analysis_io_count(self):
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_final_analysis')
        self.start_engine(engine)
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, 'test').id
        root.save() 
        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)
        self.assertEquals(_get_io_write_count(), 3) 
        self.assertEquals(_get_io_read_count(), 1)
        self.assertEquals(log_count('entering final analysis for '), 2)

    @track_io
    @clear_log
    def test_engine_020_final_analysis_io_count_2(self):
        """Same thing as before but we test with multiple observables."""
        self.assertEquals(_get_io_write_count(), 0)
        self.assertEquals(_get_io_read_count(), 0)
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_test_final_analysis')
        self.start_engine(engine)
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        o_uuid_1 = root.add_observable(F_TEST, 'test_01').id
        o_uuid_2 = root.add_observable(F_TEST, 'test_02').id
        root.save() 
        self.assertEquals(_get_io_write_count(), 1)
        self.assertEquals(_get_io_read_count(), 0)
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)
        self.assertEquals(_get_io_write_count(), 4) 
        self.assertEquals(_get_io_read_count(), 1)
        self.assertEquals(log_count('entering final analysis for '), 3)

    def test_engine_021_network_engine_startup(self):
        engine = NetworkEngine()
        self.start_engine(engine)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

    def test_engine_022_network_engine_submit(self):
        class _custom_engine(NetworkEngine):
            def handle_network_item(self, tar_path):
                storage_dir = tempfile.mkdtemp(dir=saq.test.test_dir)
                with tarfile.open(tar_path) as t:
                    t.extractall(path=storage_dir)
                os.remove(tar_path)
                root = create_root_analysis(storage_dir=storage_dir)
                root.load()
                send_test_message(root.details)

        engine = _custom_engine()
        self.start_engine(engine)

        root = create_root_analysis()
        root.details = 'testing'
        root.save()

        submit_alerts('127.0.0.1', 
                      engine.config.getint('server_port'),
                      engine.config['ssl_cert_path'],
                      engine.config['ssl_hostname'],
                      engine.config['ssl_key_path'],
                      engine.config['ssl_ca_path'],
                      [ root.storage_dir ])

        # wait for the engine to send us the details back
        response = recv_test_message()
        self.assertEquals(response, root.details)
        
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

    def test_engine_023_mysql_engine_startup(self):
        engine = MySQLEngine()
        self.start_engine(engine)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

    def test_engine_024_mysql_engine_submit(self):
        class _custom_engine(MySQLEngine):
            def process(self, work_item):
                if isinstance(work_item, TerminatingMarker):
                    return AnalysisEngine.process(self, work_item)

                root = RootAnalysis(storage_dir=work_item)
                root.load()
                send_test_message(root.details)

        engine = _custom_engine()
        engine.reset()
        self.start_engine(engine)
        root = create_root_analysis()
        root.details = 'test'
        root.save()

        # what is happening here?
        engine.add_sql_work_item(root.storage_dir)

        # wait for the engine to process the 
        message = recv_test_message()
        self.assertEquals(message, root.details)
        
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

    # ensure that post analysis is executed even if delayed analysis times out
    def test_engine_025_delayed_analysis_timeout(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_delayed_analysis_timeout')
        engine.enable_module('analysis_module_test_post_analysis')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, '0:01|0:01')
        root.save()

        engine.queue_work_item(root.storage_dir)

        # wait for delayed analysis to time out
        wait_for_log_count('has timed out', 1)

        # shut down the engine
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        # post analysis should have executed
        self.assertEquals(log_count('execute_post_analysis called'), 1)

    def test_engine_026_wait_for_analysis(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))

        self.assertEquals(log_count("depends on"), 1)

    def test_engine_027_wait_for_disabled_analysis(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        #engine.enable_module('analysis_module_test_wait_b')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_B))

        #self.assertEquals(log_count("requested to wait for disabled (or missing) module"), 1)

    @clear_log
    def test_engine_028_wait_for_analysis_circ_dep(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_2')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_B))

        self.assertEquals(log_count("CIRCULAR DEPENDENCY ERROR"), 1)

    @clear_log
    def test_engine_029_wait_for_analysis_missing_analysis(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_3')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertFalse(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))

        # we would only see this log if A waited on B
        #self.assertEquals(log_count("did not generate analysis to resolve dep"), 1)

    @clear_log
    def test_engine_030_wait_for_analysis_circ_dep_chained(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.enable_module('analysis_module_test_wait_c')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_B))
        self.assertIsNone(test_observable.get_analysis(WaitAnalysis_C))

        self.assertEquals(log_count("CIRCULAR DEPENDENCY ERROR"), 1)

    @clear_log
    def test_engine_031_wait_for_analysis_chained(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.enable_module('analysis_module_test_wait_c')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_5')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_C))

        self.assertEquals(log_count("CIRCULAR DEPENDENCY ERROR"), 0)

    @clear_log
    def test_engine_032_wait_for_analysis_delayed(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_6')
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_B))

    @clear_log
    def test_engine_032a_wait_for_analysis_rejected(self):

        from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C, \
                                     WaitAnalyzerModule_B

        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_wait_a')
        engine.enable_module('analysis_module_test_wait_b')
        engine.enable_module('analysis_module_test_wait_c')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_engine_032a')
        test_observable.exclude_analysis(WaitAnalyzerModule_B)
        root.save()

        engine.queue_work_item(root.storage_dir)
        root.save()

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        self.assertIsNotNone(test_observable)
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_A))
        self.assertFalse(test_observable.get_analysis(WaitAnalysis_B))
        self.assertIsNotNone(test_observable.get_analysis(WaitAnalysis_C))

    @clear_log
    def test_engine_033_post_analysis_after_false_return(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_test_post_analysis')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()

        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)

        from saq.modules.test import PostAnalysisTestResult
        self.assertFalse(test_observable.get_analysis(PostAnalysisTestResult))
        self.assertEquals(log_count('execute_post_analysis called'), 1)

    @clear_log
    def test_engine_034_maximum_cumulative_analysis_warning_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_cumulative_analysis_warning_time'] = '0'
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)
        
        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        self.assertEquals(log_count('ACE has been analyzing'), 1)

    @clear_log
    def test_engine_034_maximum_cumulative_analysis_fail_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_cumulative_analysis_fail_time'] = '0'
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)
        
        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        self.assertEquals(log_count('ACE took too long to analyze'), 1)

    @clear_log
    def test_engine_035_maximum_analysis_time(self):
        # setting this to zero should cause it to happen right away
        saq.CONFIG['global']['maximum_analysis_time'] = '0'
        
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)
        
        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test_4')
        root.save()
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        # will fire again in final analysis
        self.assertEquals(log_count('excessive time - analysis module'), 2)

    def test_engine_036_is_module_enabled(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_dependency_test')
        self.start_engine(engine)

        root = create_root_analysis()
        test_observable = root.add_observable(F_TEST, 'test')
        root.save()
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

        root.load()
        test_observable = root.get_observable(test_observable.id)
        
        from saq.modules.test import DependencyTestAnalysis, KEY_SUCCESS, KEY_FAIL
        analysis = test_observable.get_analysis(DependencyTestAnalysis)
        for key in analysis.details[KEY_SUCCESS].keys():
            self.assertTrue(analysis.details[KEY_SUCCESS][key])
        for key in analysis.details[KEY_FAIL].keys():
            self.assertFalse(analysis.details[KEY_FAIL][key])

    def test_engine_037_merge(self):
        engine = self.create_engine(AnalysisEngine)
        engine.enable_module('analysis_module_basic_test')
        engine.enable_module('analysis_module_merge_test')
        self.start_engine(engine)

        # first analysis
        root_1 = create_root_analysis()
        test_observable_1 = root_1.add_observable(F_TEST, 'test_1')
        existing_user_observable = root_1.add_observable(F_USER, 'admin')
        root_1.save()
        engine.queue_work_item(root_1.storage_dir)

        # second analysis we want to merge into the first
        root_2 = create_root_analysis(uuid=str(uuid.uuid4()))
        test_observable_2 = root_2.add_observable(F_TEST, 'merge_test_1')
        root_2.save()
        engine.queue_work_item(root_2.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

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
    def test_engine_038_error_reporting(self):
        # trigger the failure this way
        saq.CONFIG['global']['maximum_cumulative_analysis_fail_time'] = '0'

        # remember what was already in the error reporting directory
        def _enum_error_reporting():
            return set(os.listdir(os.path.join(saq.SAQ_HOME, 'error_reports')))

        existing_reports = _enum_error_reporting()

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)

        root = create_root_analysis()
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_3')
        root.save()
        engine.queue_work_item(root.storage_dir)

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

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

    def test_engine_039_stats(self):
        # clear engine statistics
        if os.path.exists(os.path.join(saq.MODULE_STATS_DIR, 'unittest')):
            shutil.rmtree(os.path.join(saq.MODULE_STATS_DIR, 'unittest'))

        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)

        root = create_root_analysis()
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_1')
        root.save()
        engine.queue_work_item(root.storage_dir)

        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

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

    def test_engine_040_exclusion(self):
        
        engine = AnalysisEngine()
        engine.enable_module('analysis_module_basic_test')
        self.start_engine(engine)

        root = create_root_analysis()
        root.initialize_storage()
        observable = root.add_observable(F_TEST, 'test_6')
        root.save()
        engine.queue_work_item(root.storage_dir)
        engine.queue_work_item(TerminatingMarker())
        self.wait_engine(engine)

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

    def test_engine_041_anp_node_engine_modes(self):

        from saq.engine import MODE_CLIENT, MODE_SERVER, MODE_LOCAL

        # test the various modes to ensure all the functions are called that are supposed to be called
        engine = self.create_engine(ANPEnabledEngine)
        engine.mode = MODE_SERVER
        self.start_engine(engine)

        self.assertTrue(engine.collect_server_mode_event.wait(5))
        self.stop_tracked_engine()
        
        engine = self.create_engine(ANPEnabledEngine)
        engine.mode = MODE_CLIENT
        self.start_engine(engine)

        self.assertTrue(engine.collect_client_mode_event.wait(5))
        self.stop_tracked_engine()

        engine = self.create_engine(ANPEnabledEngine)
        engine.mode = MODE_LOCAL
        self.start_engine(engine)

        self.assertTrue(engine.collect_local_mode_event.wait(5))
        self.stop_tracked_engine()

    @clear_log
    def test_engine_042_anp_mode_server(self):

        from saq.engine import MODE_SERVER

        # test the various modes to ensure all the functions are called that are supposed to be called
        engine = self.create_engine(ANPEnabledEngine)
        engine.mode = MODE_SERVER
        self.start_engine(engine)

        wait_for_log_count('listening for connections', 1, 5)

        anp = anp_connect(engine.anp_listening_address, engine.anp_listening_port)
        anp.send_message(ANPCommandPING('testing'))

        self.assertTrue(engine.anp_command_handler_event.wait(5))
        self.stop_tracked_engine()

    def test_engine_043_anp_mode_client(self):
        
        import threading
        from saq.engine import MODE_CLIENT

        control_event = threading.Event()

        def command_handler(anp, command):
            control_event.set()
            anp.send_message(ANPCommandOK())

        listening_address = saq.CONFIG['engine_unittest']['anp_listening_address']
        listening_port = saq.CONFIG['engine_unittest'].getint('anp_listening_port')

        # create an anp server that will process the requests
        server = ACENetworkProtocolServer(listening_address, listening_port, command_handler)
        server.start()

        wait_for_log_count('listening for connections', 1, 5)

        # create an engine in client mode that will submit commands to the server
        class custom_engine(ANPEnabledEngine):
            def collect_client_mode(self):
                self.submit_command(ANPCommandPING('test'))
                self.stop_collection()
        
        # test the various modes to ensure all the functions are called that are supposed to be called
        engine = self.create_engine(custom_engine)
        engine.mode = MODE_CLIENT
        self.start_engine(engine)

        self.assertTrue(control_event.wait(5))
        server.stop()

    @reset_config
    @clear_log
    def test_engine_044_anp_mode_client_multiple_target_nodes(self):

        import threading
        from saq.engine import MODE_CLIENT

        control_event_1 = threading.Event()
        received_commands_1 = []

        def command_handler_1(anp, command):
            received_commands_1.append(command)
            if len(received_commands_1) == 2:
                control_event_1.set()

            anp.send_message(ANPCommandOK())

        listening_address_1 = saq.CONFIG['engine_unittest']['anp_listening_address']
        listening_port_1 = saq.CONFIG['engine_unittest'].getint('anp_listening_port')

        server_1 = ACENetworkProtocolServer(listening_address_1, listening_port_1, command_handler_1)
        server_1.start()

        control_event_2 = threading.Event()
        received_commands_2 = []

        def command_handler_2(anp, command):
            received_commands_2.append(command)
            control_event_2.set()
            anp.send_message(ANPCommandOK())

        listening_address_2 = saq.CONFIG['engine_unittest']['anp_listening_address']
        listening_port_2 = saq.CONFIG['engine_unittest'].getint('anp_listening_port') + 1

        server_2 = ACENetworkProtocolServer(listening_address_2, listening_port_2, command_handler_2)
        server_2.start()

        wait_for_log_count('listening for connections on {} port {}'.format(listening_address_1, listening_port_1), 1, 5)
        wait_for_log_count('listening for connections on {} port {}'.format(listening_address_2, listening_port_2), 1, 5)

        class custom_engine(ANPEnabledEngine):
            def collect_client_mode(self):
                self.submit_command(ANPCommandPING('test_1'))
                self.submit_command(ANPCommandPING('test_2'))
                self.submit_command(ANPCommandPING('test_3'))
                self.stop_collection()
        
        # test the various modes to ensure all the functions are called that are supposed to be called
        saq.CONFIG['engine_unittest']['anp_nodes'] = '{}:{},{}:{}'.format(listening_address_1, listening_port_1,
                                                                          listening_address_2, listening_port_2)
        engine = self.create_engine(custom_engine)
        engine.mode = MODE_CLIENT
        self.start_engine(engine)

        self.assertTrue(control_event_1.wait(5))
        self.assertTrue(control_event_2.wait(5))

        self.assertEquals(len(received_commands_1), 2)
        self.assertEquals(len(received_commands_2), 1)

        self.assertEquals(received_commands_1[0].message, 'test_1')
        self.assertEquals(received_commands_1[1].message, 'test_3')
        self.assertEquals(received_commands_2[0].message, 'test_2')

        server_1.stop()
        server_2.stop()

    @reset_config
    @clear_log
    def test_engine_045_anp_node_busy(self):

        import threading
        from saq.engine import MODE_CLIENT

        control_event_1 = threading.Event()
        control_event_3 = threading.Event()

        def command_handler_1(anp, command):
            if not control_event_1.is_set():
                control_event_1.set()
                anp.send_message(ANPCommandBUSY())
                return

            anp.send_message(ANPCommandOK())
            control_event_3.set()

        listening_address_1 = saq.CONFIG['engine_unittest']['anp_listening_address']
        listening_port_1 = saq.CONFIG['engine_unittest'].getint('anp_listening_port')

        server_1 = ACENetworkProtocolServer(listening_address_1, listening_port_1, command_handler_1)
        server_1.start()

        control_event_2 = threading.Event()
        received_commands_2 = []

        def command_handler_2(anp, command):
            received_commands_2.append(command)
            if len(received_commands_2) == 3:
                control_event_2.set()
            anp.send_message(ANPCommandOK())

        listening_address_2 = saq.CONFIG['engine_unittest']['anp_listening_address']
        listening_port_2 = saq.CONFIG['engine_unittest'].getint('anp_listening_port') + 1

        server_2 = ACENetworkProtocolServer(listening_address_2, listening_port_2, command_handler_2)
        server_2.start()

        wait_for_log_count('listening for connections on {} port {}'.format(listening_address_1, listening_port_1), 1, 5)
        wait_for_log_count('listening for connections on {} port {}'.format(listening_address_2, listening_port_2), 1, 5)

        class custom_engine(ANPEnabledEngine):
            def collect_client_mode(self):
                if control_event_1.is_set():
                    if control_event_3.is_set():
                        self.stop_collection()
                        return True

                    self.submit_command(ANPCommandPING('test_finish'))
                    return True

                if not control_event_1.is_set():
                    self.submit_command(ANPCommandPING('test_1')) # should go to server_1 but gets routed to server_2
                    self.submit_command(ANPCommandPING('test_2'))
                    self.submit_command(ANPCommandPING('test_3'))

                return True
        
        # test the various modes to ensure all the functions are called that are supposed to be called
        saq.CONFIG['engine_unittest']['anp_nodes'] = '{}:{},{}:{}'.format(listening_address_1, listening_port_1,
                                                                          listening_address_2, listening_port_2)
        saq.CONFIG['engine_unittest']['anp_retry_timeout'] = '3'
        saq.CONFIG['engine_unittest']['collection_frequency'] = '1'
        engine = self.create_engine(custom_engine)
        engine.mode = MODE_CLIENT
        self.start_engine(engine)

        self.assertTrue(control_event_1.wait(5))
        self.assertTrue(control_event_2.wait(5))

        #self.assertEquals(len(received_commands_1), 0)
        self.assertGreater(len(received_commands_2), 2)

        self.assertEquals(received_commands_2[0].message, 'test_1')
        self.assertEquals(received_commands_2[1].message, 'test_2')
        self.assertEquals(received_commands_2[2].message, 'test_3')

        self.assertTrue(control_event_3.wait(5))

        server_1.stop()
        server_2.stop()

    @reset_config
    @clear_log
    def test_engine_046_anp_node_unavailable(self):

        import threading
        from saq.engine import MODE_CLIENT

        control_event = threading.Event()

        def command_handler(anp, command):
            control_event.set()
            anp.send_message(ANPCommandOK())

        listening_address = saq.CONFIG['engine_unittest']['anp_listening_address']
        listening_port = saq.CONFIG['engine_unittest'].getint('anp_listening_port')

        # create an anp server that will process the requests
        server = ACENetworkProtocolServer(listening_address, listening_port, command_handler)
        #server.start() # don't start the server yet

        #wait_for_log_count('listening for connections', 1, 5)

        # create an engine in client mode that will submit commands to the server
        class custom_engine(ANPEnabledEngine):
            def collect_client_mode(self):
                result = self.submit_command(ANPCommandPING('test'))
                if result is None:
                    return True

                self.stop_collection()

        saq.CONFIG['engine_unittest']['anp_retry_timeout'] = '2'
        saq.CONFIG['engine_unittest']['collection_frequency'] = '1'
        
        # test the various modes to ensure all the functions are called that are supposed to be called
        engine = self.create_engine(custom_engine)
        engine.mode = MODE_CLIENT
        self.start_engine(engine)

        wait_for_log_count('unable to connect to', 1, 5)
        server.start()

        self.assertTrue(control_event.wait(5))
        server.stop()
