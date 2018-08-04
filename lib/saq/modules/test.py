# vim: sw=4:ts=4:et:cc=120
#
# collection of modules used for unit testing
#

import datetime
import logging
import os, os.path
import time
import re

import saq
from saq.constants import *
from saq.analysis import Analysis
from saq.modules import AnalysisModule
from saq.test import *

KEY_TEST_RESULT = 'test_result'
KEY_ACTUAL_VALUE = 'actual'
KEY_EXPECTED_VALUE = 'expected'
KEY_COMPLETE_TIME = 'complete_time'
KEY_INITIAL_REQUEST = 'initial_request'
KEY_DELAYED_REQUEST = 'delayed_request'
KEY_REQUEST_COUNT = 'request_count'

class TestAnalysis(Analysis):
    @property
    def test_result(self):
        return self.details_property(KEY_TEST_RESULT)

class BasicTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

class BasicTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BasicTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_1':
            return self.execute_analysis_1(test)
        elif test.value == 'test_2':
            return self.execute_analysis_2(test)
        elif test.value == 'test_3':
            return self.execute_analysis_3(test)
        elif test.value == 'test_4':
            return self.execute_analysis_4(test)
        elif test.value == 'test_5':
            return self.execute_analysis_5(test)
        elif test.value == 'test_6':
            return self.execute_analysis_6(test)
        else:
            return False

    def execute_analysis_1(self, test):
        analysis = self.create_analysis(test)
        return True

    def execute_analysis_2(self, test):
        return False

    def execute_analysis_3(self, test):
        pass # <-- intentional

    def execute_analysis_4(self, test):
        time.sleep(2) # take too long
        return True

    def execute_analysis_6(self, test):
        analysis = self.create_analysis(test)
        new_observable = analysis.add_observable(F_TEST, 'result_1')
        # exclude by instance
        new_observable.exclude_analysis(self)

        new_observable = analysis.add_observable(F_TEST, 'result_2')
        # exclude by type
        new_observable.exclude_analysis(BasicTestAnalyzer)
        return True

class MergeTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

class MergeTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MergeTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'merge_test_1':
            return self.execute_analysis_1(test)
        else:
            return False

    def execute_analysis_1(self, test):
        analysis = self.create_analysis(test)
        output_observable = analysis.add_observable(F_TEST, 'test_output')
        output_observable.add_tag('test')

        output_path = os.path.join(self.root.storage_dir, 'sample.txt')
        with open(output_path, 'w') as fp:
            fp.write('test')

        file_observable = analysis.add_observable(F_FILE, os.path.relpath(output_path, start=self.root.storage_dir))
        url_observable = analysis.add_observable(F_URL, 'http://google.com')
        file_observable.add_relationship(R_DOWNLOADED_FROM, url_observable)

        # we also add an existing observable
        user_observable = analysis.add_observable(F_USER, 'admin')
        return True

KEY_SUCCESS = 'success'
KEY_FAIL = 'fail'
KEY_BY_MODULE_TYPE = 'module_type'
KEY_BY_MODULE_STR = 'module_str'
KEY_BY_MODULE_NAME = 'module_name'
KEY_BY_ANALYSIS_TYPE = 'analysis_type'
KEY_BY_ANALYSIS_STR = 'analysis_str'

class DependencyTestAnalysis(TestAnalysis):

    def initialize_details(self):
        self.details = {
            KEY_SUCCESS: {
                KEY_BY_MODULE_TYPE: None,
                KEY_BY_MODULE_STR: None,
                KEY_BY_MODULE_NAME: None,
                KEY_BY_ANALYSIS_TYPE: None,
                KEY_BY_ANALYSIS_STR: None,
            },
            KEY_FAIL: {
                KEY_BY_MODULE_TYPE: None,
                KEY_BY_MODULE_STR: None,
                KEY_BY_MODULE_NAME: None,
                KEY_BY_ANALYSIS_TYPE: None,
                KEY_BY_ANALYSIS_STR: None,
            },
        }

class DependencyTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return DependencyTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)

        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_TYPE] = self.engine.is_module_enabled(DependencyTestAnalyzer)
        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_STR] = self.engine.is_module_enabled(str(DependencyTestAnalyzer))
        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_NAME] = self.engine.is_module_enabled('analysis_module_dependency_test')
        analysis.details[KEY_SUCCESS][KEY_BY_ANALYSIS_TYPE] = self.engine.is_module_enabled(DependencyTestAnalysis)
        analysis.details[KEY_SUCCESS][KEY_BY_ANALYSIS_STR] = self.engine.is_module_enabled(str(DependencyTestAnalysis))

        analysis.details[KEY_FAIL][KEY_BY_MODULE_TYPE] = self.engine.is_module_enabled(BasicTestAnalyzer)
        analysis.details[KEY_FAIL][KEY_BY_MODULE_STR] = self.engine.is_module_enabled(str(BasicTestAnalyzer))
        analysis.details[KEY_FAIL][KEY_BY_MODULE_NAME] = self.engine.is_module_enabled('analysis_module_basic_test')
        analysis.details[KEY_FAIL][KEY_BY_ANALYSIS_TYPE] = self.engine.is_module_enabled(BasicTestAnalysis)
        analysis.details[KEY_FAIL][KEY_BY_ANALYSIS_STR] = self.engine.is_module_enabled(str(BasicTestAnalysis))

        return True

class DelayedAnalysisTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = {
            KEY_INITIAL_REQUEST: True,
            KEY_DELAYED_REQUEST: False,
            KEY_REQUEST_COUNT: 1,
            KEY_COMPLETE_TIME: None,
        }
        
    @property
    def complete_time(self):
        return self.details_property(KEY_COMPLETE_TIME)

    @property
    def initial_request(self):
        return self.details_property(KEY_INITIAL_REQUEST)

    @property
    def delayed_request(self):
        return self.details_property(KEY_DELAYED_REQUEST)

    @property
    def request_count(self):
        return self.details_property(KEY_REQUEST_COUNT)

class DelayedAnalysisTestModule(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return DelayedAnalysisTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = test.get_analysis(DelayedAnalysisTestAnalysis)
        if not analysis:
            analysis = self.create_analysis(test)
            # the observable value is the format M:SS|M:SS
            delay, timeout = test.value.split('|')
            delay_minutes, delay_seconds = map(int, delay.split(':'))
            timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
            return self.delay_analysis(test, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                       timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

        analysis.details[KEY_DELAYED_REQUEST] = True
        analysis.details[KEY_REQUEST_COUNT] += 1
        analysis.details[KEY_COMPLETE_TIME] = datetime.datetime.now()
        return True

class EngineLockingTestAnalysis(Analysis):
    def initialize_details(self):
        pass

class EngineLockingTestModule(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return EngineLockingTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, t):
        analysis = self.create_analysis(t)
        # let the main process know we're executing now
        send_test_message('ok')
        # wait for main process to say we're good to go
        result = recv_test_message()

class FinalAnalysisTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

class FinalAnalysisTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FinalAnalysisTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        pass

    def execute_final_analysis(self, test):
        analysis = self.create_analysis(test)

class PostAnalysisTestResult(TestAnalysis):
    def initialize_details(self):
        pass

class PostAnalysisTest(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PostAnalysisTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, *args, **kwargs):
        return False

    def execute_post_analysis(self):
        logging.info("execute_post_analysis called")

class DelayedAnalysisTimeoutTestResult(TestAnalysis):
    def initialize_details(self):
        pass

class DelayedAnalysisTimeoutTest(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return DelayedAnalysisTimeoutTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = test.get_analysis(DelayedAnalysisTimeoutTestResult)
        if not analysis:
            analysis = self.create_analysis(test)

        # the observable value is the format M:SS|M:SS
        delay, timeout = test.value.split('|')
        delay_minutes, delay_seconds = map(int, delay.split(':'))
        timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
        return self.delay_analysis(test, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                   timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

class WaitAnalysis_A(Analysis):
    def initialize_details(self):
        pass

class WaitAnalyzerModule_A(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_A

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_1':
            return self.execute_analysis_01(test)
        elif test.value == 'test_2':
            return self.execute_analysis_02(test)
        elif test.value == 'test_3':
            return self.execute_analysis_03(test)
        elif test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_6':
            return self.execute_analysis_06(test)
        elif test.value == 'test_engine_032a':
            return self.execute_analysis_test_engine_032a(test)
        
    def execute_analysis_01(self, test):
        # NOTE the execution order of modules happens to (currently) be the order they are defined 
        # in the configuration file
        analysis = self.wait_for_analysis(test, WaitAnalysis_B)
        if not analysis:
            return False

        self.create_analysis(test)
        return True

    def execute_analysis_02(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_03(self, test):
        return False

    def execute_analysis_04(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_05(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_06(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_test_engine_032a(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

class WaitAnalysis_B(Analysis):
    def initialize_details(self):
        pass

class WaitAnalyzerModule_B(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_B

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_1':
            return self.execute_analysis_01(test)
        elif test.value == 'test_2':
            return self.execute_analysis_02(test)
        elif test.value == 'test_3':
            return self.execute_analysis_03(test)
        elif test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_6':
            return self.execute_analysis_06(test)

    def execute_analysis_01(self, test):
        self.create_analysis(test)
        return True

    def execute_analysis_02(self, test):
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return True

    def execute_analysis_03(self, test):
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return True

    def execute_analysis_04(self, test):
        self.wait_for_analysis(test, WaitAnalysis_C)
        self.create_analysis(test)
        return True

    def execute_analysis_05(self, test):
        self.wait_for_analysis(test, WaitAnalysis_C)
        self.create_analysis(test)
        return True

    def execute_analysis_06(self, test):
        analysis = test.get_analysis(WaitAnalysis_B)
        if analysis:
            return True

        analysis = self.create_analysis(test)
        return self.delay_analysis(test, analysis, seconds=2)

class WaitAnalysis_C(Analysis):
    def initialize_details(self):
        pass

class WaitAnalyzerModule_C(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_C

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_engine_032a':
            return self.execute_analysis_test_engine_032a(test)

    def execute_analysis_04(self, test):
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return True

    def execute_analysis_05(self, test):
        self.create_analysis(test)
        return True

    def execute_analysis_test_engine_032a(self, test):
        self.create_analysis(test)
        return True
