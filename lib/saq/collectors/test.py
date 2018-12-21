# vim: sw=4:ts=4:et

import datetime
import os
import pickle
import tempfile
import threading

import saq
from saq.constants import *
from saq.database import use_db, get_db_connection
from saq.engine import Engine
from saq.test import *
from . import Collector, Submission, RemoteNode

class TestCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(workload_type='test', *args, **kwargs)

    def get_next_submission(self):
        return None

success_event = None
fail_event = None

class _custom_submission(Submission):
    def __init__(self):
        super().__init__(
        description='test_description',
        analysis_mode='analysis',
        tool='unittest_tool',
        tool_instance='unittest_tool_instance',
        type='unittest_type',
        event_time=datetime.datetime.now(),
        details={'hello': 'world'},
        observables=[],
        tags=[],
        files=[])

    def success(self, result):
        global success_event
        success_event.set()

    def fail(self):
        global fail_event
        fail_event.set()

class CollectorBaseTestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        with get_db_connection() as db:
            c = db.cursor()
            c.execute("DELETE FROM work_distribution_groups")
            c.execute("DELETE FROM incoming_workload")
            c.execute("DELETE FROM workload")
            c.execute("UPDATE nodes SET last_update = SUBTIME(NOW(), '01:00:00')")
            db.commit()

        # default engines to support any analysis mode
        saq.CONFIG['engine']['local_analysis_modes'] = ''

class CollectorTestCase(CollectorBaseTestCase):
    def create_submission(self):
        return Submission(
            description='test_description',
            analysis_mode='analysis',
            tool='unittest_tool',
            tool_instance='unittest_tool_instance',
            type='unittest_type',
            event_time=datetime.datetime.now(),
            details={'hello': 'world'},
            observables=[],
            tags=[],
            files=[])

    @use_db
    def test_add_group(self, db, c):
        collector = TestCollector()
        collector.add_group('test', 100, True, 'ace')
        
        c.execute("SELECT id, name FROM work_distribution_groups")
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        row = result[0]
        group_id = row[0]
        self.assertEquals(row[1], 'test')

        # when we do it a second time, we should get the name group ID since we used the same name
        collector = TestCollector()
        collector.add_group('test', 100, True, 'ace')
        
        c.execute("SELECT id, name FROM work_distribution_groups")
        result = c.fetchall()
        self.assertEquals(len(result), 1)
        row = result[0]
        self.assertEquals(row[0], group_id)
        self.assertEquals(row[1], 'test')

    def test_load_groups(self):

        collector = TestCollector()
        collector.load_groups()
        
        self.assertEquals(len(collector.remote_node_groups), 1)
        self.assertEquals(collector.remote_node_groups[0].name, 'unittest')
        self.assertEquals(collector.remote_node_groups[0].coverage, 100)
        self.assertEquals(collector.remote_node_groups[0].full_delivery, True)
        self.assertEquals(collector.remote_node_groups[0].database, 'ace')

    def test_missing_groups(self):
        # a collector cannot be started without adding at least one group
        collector = TestCollector()
        with self.assertRaises(RuntimeError):
            collector.start()

    def test_startup(self):
        # make sure we can start one up, see it collect nothing, and then shut down gracefully
        collector = TestCollector()
        collector.add_group('test', 100, True, 'ace')
        collector.start()

        wait_for_log_count('no work available for', 1, 5)
        collector.stop()
        collector.wait()

    @use_db
    def test_work_item(self, db, c):
        class _custom_collector(TestCollector):
            def get_next_submission(_self):
                if not hasattr(_self, 'submitted'):
                    _self.submitted = True
                    return self.create_submission()

                return None

        collector = _custom_collector()
        collector.add_group('test_group_1', 100, True, 'ace')
        collector.add_group('test_group_2', 100, True, 'ace')
        collector.start()

        wait_for_log_count('scheduled test_description mode analysis', 1, 5)

        # we should have a single entry in the incoming_workload table
        c.execute("SELECT id, mode, work FROM incoming_workload")
        work = c.fetchall()
        self.assertEquals(len(work), 1)
        work = work[0]
        _id, mode, blob = work
        self.assertEquals(mode, 'analysis')
        submission = pickle.loads(blob)
        self.assertTrue(isinstance(submission, Submission))
        self.assertEquals(submission.description, 'test_description')
        self.assertEquals(submission.details, {'hello': 'world'})

        # and then we should have two assignments for the two groups
        c.execute("SELECT group_id, work_id, status FROM work_distribution WHERE work_id = %s", (_id,))
        assignments = c.fetchall()
        self.assertEquals(len(assignments), 2)
        for group_id, work_id, status in assignments:
            self.assertEquals(status, 'READY')

        collector.stop()
        collector.wait()

    @use_db
    def test_submit(self, db, c):

        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.available_work = [self.create_submission() for _ in range(1)]

            def get_next_submission(_self):
                if not self.available_work:
                    return None

                return self.available_work.pop()

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        self.start_api_server()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, True, 'ace') # 100% coverage
        collector.start()

        # we should see 1 of these
        wait_for_log_count('scheduled test_description mode analysis', 1, 5)
        wait_for_log_count('submitting 1 items', 1, 5)

        collector.stop()
        collector.wait()

        # both the incoming_workload and work_distribution tables should be empty
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        self.assertEquals(c.fetchone()[0], 0)
        c.execute("SELECT COUNT(*) FROM incoming_workload")
        self.assertEquals(c.fetchone()[0], 0)

        # and we should have one item in the engine workload
        c.execute("SELECT COUNT(*) FROM workload ")
        self.assertEquals(c.fetchone()[0], 1)

    @use_db
    def test_coverage(self, db, c):

        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.available_work = [self.create_submission() for _ in range(10)]

            def get_next_submission(_self):
                if not self.available_work:
                    return None

                return self.available_work.pop()

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        self.start_api_server()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, True, 'ace') # 100% coverage
        tg2 = collector.add_group('test_group_2', 50, True, 'ace') # 50% coverage
        tg3 = collector.add_group('test_group_3', 10, True, 'ace') # 10% coverage
        collector.start()

        # we should see 10 of these
        wait_for_log_count('scheduled test_description mode analysis', 1, 5)
        # and then 16 of these
        wait_for_log_count('got submission result', 16, 5)

        collector.stop()
        collector.wait()

        # both the incoming_workload and work_distribution tables should be empty
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        self.assertEquals(c.fetchone()[0], 0)
        # both the incoming_workload and work_distribution tables should be empty
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg2.group_id,))
        self.assertEquals(c.fetchone()[0], 0)
        # both the incoming_workload and work_distribution tables should be empty
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg3.group_id,))
        self.assertEquals(c.fetchone()[0], 0)
        c.execute("SELECT COUNT(*) FROM incoming_workload")
        self.assertEquals(c.fetchone()[0], 0)

        # and we should have 16 in the engine workload
        c.execute("SELECT COUNT(*) FROM workload ")
        self.assertEquals(c.fetchone()[0], 16)

        # there should be 10 of these messages for test_group_1
        self.assertEquals(len(search_log_condition(lambda r: 'test_group_1' in r.getMessage() 
                                                   and 'got submission result' in r.getMessage())), 10)
        # and then 5 for this one
        self.assertEquals(len(search_log_condition(lambda r: 'test_group_2' in r.getMessage() 
                                                   and 'got submission result' in r.getMessage())), 5)
        # and just 1 for this one
        self.assertEquals(len(search_log_condition(lambda r: 'test_group_3' in r.getMessage() 
                                                   and 'got submission result' in r.getMessage())), 1)

    @use_db
    def test_fail_submit_full_coverage(self, db, c):
        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.available_work = [self.create_submission() for _ in range(1)]

            def get_next_submission(_self):
                if not self.available_work:
                    return None

                return self.available_work.pop()

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        # we do NOT start the API server making it unavailable
        #self.start_api_server()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, True, 'ace') # 100% coverage
        collector.start()

        # we should see 1 of these
        wait_for_log_count('scheduled test_description mode analysis', 1, 5)

        # watch for the failure
        wait_for_log_count('unable to submit work item', 1, 5)

        collector.stop()
        collector.wait()

        # both the work_distribution and incoming_workload tables should have entries for the work item
        # that has not been sent yet
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        self.assertEquals(c.fetchone()[0], 1)
        # both the incoming_workload and work_distribution tables should be empty
        c.execute("SELECT COUNT(*) FROM incoming_workload")
        self.assertEquals(c.fetchone()[0], 1)

        # and we should have 0 in the engine workload
        c.execute("SELECT COUNT(*) FROM workload ")
        self.assertEquals(c.fetchone()[0], 0)

    @use_db
    def test_fail_submit_no_coverage(self, db, c):
        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.available_work = [self.create_submission() for _ in range(1)]

            def get_next_submission(_self):
                if not self.available_work:
                    return None

                return self.available_work.pop()

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        # we do NOT start the API server making it unavailable
        #self.start_api_server()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, False, 'ace') # 100% coverage, full_coverage = no
        collector.start()

        # we should see 1 of these
        wait_for_log_count('scheduled test_description mode analysis', 1, 5)

        # watch for the failure
        wait_for_log_count('unable to submit work item', 1, 5)

        collector.stop()
        collector.wait()

        # everything should be empty at this point since we do not have full coverage
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        self.assertEquals(c.fetchone()[0], 0)
        # both the incoming_workload and work_distribution tables should be empty
        c.execute("SELECT COUNT(*) FROM incoming_workload")
        self.assertEquals(c.fetchone()[0], 0)

        # and we should have 0 in the engine workload
        c.execute("SELECT COUNT(*) FROM workload ")
        self.assertEquals(c.fetchone()[0], 0)

    @use_db
    def test_submission_success_fail(self, db, c):

        # make sure the collector calls success() on successful submission
        # and fail() on failed submission

        global success_event
        success_event = threading.Event()
        global fail_event
        fail_event = threading.Event()

        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                _self.success_tested = False
                _self.fail_tested = False
                _self.success_signal = False
                _self.fail_signal = False

            def get_next_submission(_self):
                if not _self.success_tested:
                    if _self.success_signal:
                        _self.success_tested = True
                        return _custom_submission()

                if not _self.fail_tested:
                    if _self.fail_signal:
                        _self.fail_tested = True
                        return _custom_submission()

                return None

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        self.start_api_server()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, False, 'ace') # 100% coverage, no full delivery
        collector.start()

        # trigger the "success" test
        collector.success_signal = True
        self.assertTrue(success_event.wait(5))

        self.stop_api_server()

        # trigger the "fail" test
        collector.fail_signal = True
        self.assertTrue(fail_event.wait(5))

        collector.stop()
        collector.wait()

    @use_db
    def test_cleanup_files(self, db, c):

        fp, file_path = tempfile.mkstemp(dir=saq.TEMP_DIR)
        os.write(fp, b'Hello, world!')
        os.close(fp)

        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(delete_files=True, *args, **kwargs)
                self.work = self.create_submission()
                self.work.files=[file_path]

            def get_next_submission(_self):
                if self.work:
                    result = self.work
                    self.work = None
                    return result

                return None

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        self.start_api_server()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, True, 'ace') # 100% coverage
        collector.start()

        wait_for_log_count('scheduled test_description mode analysis', 1, 5)
        wait_for_log_count('submitting 1 items', 1, 5)

        collector.stop()
        collector.wait()

        # the file should have been deleted
        self.assertFalse(os.path.exists(file_path))

    @use_db
    def test_recovery(self, db, c):
        class _custom_collector(TestCollector):
            def __init__(_self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.available_work = [self.create_submission() for _ in range(10)]

            def get_next_submission(_self):
                if not self.available_work:
                    return None

                return self.available_work.pop()

        class _custom_collector_2(TestCollector):
            def get_next_submission(_self):
                return None

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        collector = _custom_collector()
        tg1 = collector.add_group('test_group_1', 100, True, 'ace') # 100% coverage
        collector.start()

        # the API server is not running so these will fail
        wait_for_log_count('scheduled test_description mode analysis', 10, 5)
        wait_for_log_count('unable to submit work item', 10, 5)

        # then we "shut down"
        collector.stop()
        collector.wait()

        # both the incoming_workload and work_distribution tables should have all 10 items
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        self.assertEquals(c.fetchone()[0], 10)
        c.execute("SELECT COUNT(*) FROM incoming_workload")
        self.assertEquals(c.fetchone()[0], 10)

        # and we should have no items in the engine workload
        c.execute("SELECT COUNT(*) FROM workload ")
        self.assertEquals(c.fetchone()[0], 0)
        db.commit()

        # NOW start the API server
        self.start_api_server()

        # and then start up the collector
        collector = _custom_collector_2()
        tg1 = collector.add_group('test_group_1', 100, True, 'ace') # 100% coverage
        collector.start()

        # with the API server running now we should see these go out
        wait_for_log_count('completed work item', 10, 5)

        collector.stop()
        collector.wait()

        # now these should be empty
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        self.assertEquals(c.fetchone()[0], 0)
        c.execute("SELECT COUNT(*) FROM incoming_workload")
        self.assertEquals(c.fetchone()[0], 0)

        # and we should have 10 workload entries
        c.execute("SELECT COUNT(*) FROM workload ")
        self.assertEquals(c.fetchone()[0], 10)

    @use_db
    def test_node_translation(self, db, c):

        # start an engine to get a node created
        engine = Engine()
        engine.start()
        wait_for_log_count('updated node', 1, 5)
        engine.controlled_stop()
        engine.wait()

        # get the current node settings from the database
        c.execute("SELECT id, name, location, company_id, last_update, is_primary, any_mode, is_local FROM nodes")
        node_id, name, location, _, last_update, _, any_mode, _ = c.fetchone()

        # add a configuration to map this location to a different location
        saq.CONFIG['node_translation']['unittest'] = '{},test:443'.format(location)

        remote_node = RemoteNode(node_id, name, location, any_mode, last_update, ANALYSIS_MODE_ANALYSIS, 0)
        self.assertEquals(remote_node.location, 'test:443')
