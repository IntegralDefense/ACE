import logging
import pymysql
from hashlib import md5
from contextlib import closing
import saq
from saq.analysis import Analysis
from saq.constants import *
from saq.modules import AnalysisModule
import ntpath
import os

class CollectFileAnalysis(Analysis):

    def initialize_details(self):
        self.details = { }

    @property
    def task_id(self):
        if self.details is None:
            self.details = { 'task_id' : None }
        return self.details['task_id']

    @task_id.setter
    def task_id(self, value):
        if self.details is None:
            self.details = { 'task_id' : None }
        self.details['task_id'] = value

    def generate_summary(self):
        return None

class CollectFileAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('frequency')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def chronos_host(self):
        return saq.CONFIG['chronos']['host']

    @property
    def chronos_port(self):
        return saq.CONFIG['chronos'].getint('port')

    @property
    def chronos_path(self):
        return saq.CONFIG['chronos']['path']

    @property
    def generated_analysis_type(self):
        return CollectFileAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE_LOCATION

    @property
    def required_directives(self):
        return [ DIRECTIVE_COLLECT_FILE ]

    def execute_analysis(self, file_location):
        from chronosapi import Chronos

        # create analysis object if it does not already exist
        analysis = file_location.get_analysis(CollectFileAnalysis)
        if analysis is None:
            analysis = self.create_analysis(file_location)
            analysis = CollectFileAnalysis()
            file_location.add_analysis(analysis)

        # create new chronos instance
        chronos = Chronos("{}:{}/{}".format(self.chronos_host, self.chronos_port, self.chronos_path))

        # tell chronos to collect file from a machine if we haven't already
        if analysis.task_id is None:
            hostname = file_location.hostname
            location = file_location.full_path
            analysis.task_id = chronos.collect_file(hostname, location)

        # wait until task is done
        status = chronos.task_status(analysis.task_id)
        if (status == 'queued' or status == 'running'):
            return self.delay_analysis(file_location, analysis, seconds=self.frequency)

        # if task was successful then get result
        elif status == 'complete':
            result = chronos.task_result(analysis.task_id)

            # get file md5
            md5_hasher = md5()
            md5_hasher.update(result)
            file_md5 = md5_hasher.hexdigest().upper()

            # get file name
            file_name = os.path.basename(file_location.full_path)
            if '\\' in file_location.full_path:
                file_name = ntpath.basename(file_location.full_path)

            # create file path
            path = os.path.join(self.root.storage_dir, "collect_file")
            if not os.path.isdir(path):
                os.mkdir(path)
            path = os.path.join(path, file_md5)
            if not os.path.isdir(path):
                os.mkdir(path)
            path = os.path.join(path, file_name)

            # write result to file and add observable
            with open(path, "wb") as fh:
                fh.write(result)

            analysis.add_observable(F_FILE, os.path.relpath(path, start=self.root.storage_dir))

        return True
