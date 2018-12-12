# vim: sw=4:ts=4:et:cc=120

import datetime
import glob
import os, os.path
import pickle
import shutil

import saq
import saq.collectors

from saq.test import *
from saq.collectors.cb_binaries import CarbonBlackBinaryCollector
from saq.collectors.test import CollectorBaseTestCase

# NOTE for testing we set the initial_search_offset to 0 so that we just start
# pulling every binary available this ensures we get some data to work with
def _clear_persistence(collector):
    for file_path in [ collector.last_search_time_path,
                       collector.current_query_path,
                       collector.current_index_path,
                       collector.current_result_count_path]:
        if os.path.exists(file_path):
            os.remove(file_path)

def _clear_storage(collector):
    if os.path.isdir(collector.storage_dir):
        shutil.rmtree(collector.storage_dir)

class TestCase(CollectorBaseTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # make sure we have a connection to carbon black
        import cbapi_legacy as cbapi
        cb_url = saq.CONFIG['carbon_black']['url']
        cb_token = saq.CONFIG['carbon_black']['token']
        cb = cbapi.CbApi(cb_url, token=cb_token, ssl_verify=False) # XXX <-- get rid of that

        try:
            info = cb.info()
        except Exception as e:
            self.skipTest("carbon black not available at {}".format(cb_url))
    
    def test_startup(self):
        collector = CarbonBlackBinaryCollector(test_mode=saq.collectors.TEST_MODE_STARTUP)
        collector.load_groups()
        collector.start()
        wait_for_log_count('no work available', 1, 5)
        collector.stop()
        collector.wait()

    def test_processing(self):
        # start with initial_search_offset at 0 to start pulling all binaries
        collector = CarbonBlackBinaryCollector(initial_search_offset=0, download_batch_size=1)
        _clear_persistence(collector)
        _clear_storage(collector)
        collector.load_groups()
        collector.start()

        # see that we downloaded something
        wait_for_log_count('downloaded {}'.format(collector.storage_dir), 1, 30)
        # see that we scheduled someting for analysis
        wait_for_log_count('scheduled Carbon Black binary', 1, 30)
        # see that no remote nodes are available
        wait_for_log_count('no remote nodes are avaiable', 1, 30)
    
        collector.stop()
        collector.wait()

        # we should have a last update time stored
        for file_path, _type in [ (collector.last_search_time_path, datetime.datetime),
                                  (collector.current_query_path, str),
                                  (collector.current_index_path, int),
                                  (collector.current_result_count_path, int) ]:
            with self.subTest(file_path=file_path, _type=_type):
                self.assertTrue(os.path.exists(file_path))
                with open(file_path, 'rb') as fp:
                    self.assertTrue(isinstance(pickle.load(fp), _type))

        # we should have a single executable inside our storage
        for subdir in os.listdir(collector.storage_dir):
            subdir = os.path.join(collector.storage_dir, subdir)
            files = os.listdir(subdir)
            # there should be two files in here
            self.assertEquals(len(files), 2)
            # one should be a .json file
            self.assertEquals(len(glob.glob('{}/*.json'.format(subdir))), 1)

        # test the persistence
        new_collector = CarbonBlackBinaryCollector(initial_search_offset=0, download_batch_size=1)
        new_collector.load_persistence()
        self.assertEquals(new_collector.last_search_time, collector.last_search_time)
        self.assertEquals(new_collector.current_query, collector.current_query)
        self.assertEquals(new_collector.current_index, collector.current_index)
        self.assertEquals(new_collector.current_result_count, collector.current_result_count)

class EngineTestCase(CollectorBaseTestCase, ACEEngineTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # make sure we have a connection to carbon black
        import cbapi_legacy as cbapi
        cb_url = saq.CONFIG['carbon_black']['url']
        cb_token = saq.CONFIG['carbon_black']['token']
        cb = cbapi.CbApi(cb_url, token=cb_token, ssl_verify=False) # XXX <-- get rid of that

        try:
            info = cb.info()
        except Exception as e:
            self.skipTest("carbon black not available at {}".format(cb_url))

    def test_complete_processing(self):

        # testing a carbon black binary analysis from start to finish

        self.start_api_server()

        engine = TestEngine(local_analysis_modes=['binary'], 
                            analysis_pools={'binary': 1},
                            default_analysis_mode='binary')
        engine.start()

        collector = CarbonBlackBinaryCollector(initial_search_offset=0, download_batch_size=1, 
                                               test_mode=saq.collectors.TEST_MODE_SINGLE_SUBMISSION)
        _clear_persistence(collector)
        _clear_storage(collector)
        collector.load_groups()
        collector.start()

        # see that we downloaded something
        wait_for_log_count('downloaded {}'.format(collector.storage_dir), 1, 30)
        # see that we scheduled someting for analysis
        wait_for_log_count('scheduled Carbon Black binary', 1, 30)
        # see one complete
        wait_for_log_count('completed analysis RootAnalysis', 1, 20)

        collector.stop()
        collector.wait()

        engine.stop()
        engine.wait()

        # we should have a single executable inside our storage
        for subdir in os.listdir(collector.storage_dir):
            subdir = os.path.join(collector.storage_dir, subdir)
            files = os.listdir(subdir)
            # there should be two files in here
            self.assertEquals(len(files), 3)
            # one should be a .json file
            self.assertEquals(len(glob.glob('{}/*.json'.format(subdir))), 1)
            # one should be a .submit file
            self.assertEquals(len(glob.glob('{}/*.submit'.format(subdir))), 1)

    def test_extended_processing(self):

        self.start_api_server()

        engine = TestEngine(local_analysis_modes=['binary'], analysis_pools={'binary': 1})
        engine.start()

        collector = CarbonBlackBinaryCollector(initial_search_offset=0, download_batch_size=2)
        _clear_persistence(collector)
        _clear_storage(collector)
        collector.load_groups()
        collector.start()

        # see that we downloaded 6 binaries (3 iterations)
        wait_for_log_count('downloaded {}'.format(collector.storage_dir), 6, 30)
        # see that we scheduled then for analysis
        wait_for_log_count('scheduled Carbon Black binary', 6, 30)
        # and see them complete
        wait_for_log_count('completed analysis RootAnalysis', 6, 30)

        collector.stop()
        collector.wait()

        engine.stop()
        engine.wait()

        file_count = 0
        json_count = 0
        submit_count = 0

        for subdir in os.listdir(collector.storage_dir):
            subdir = os.path.join(collector.storage_dir, subdir)
            file_count += len(os.listdir(subdir))
            json_count += len(glob.glob('{}/*.json'.format(subdir)))
            submit_count += len(glob.glob('{}/*.submit'.format(subdir)))

        self.assertGreaterEqual(file_count, 6 * 3)
        self.assertGreaterEqual(json_count, 6)
        self.assertGreaterEqual(submit_count, 6)
