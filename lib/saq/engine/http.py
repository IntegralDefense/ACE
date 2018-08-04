import logging
import os
import os.path
import shutil
import uuid

import saq

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.engine import Engine, MySQLCollectionEngine
from saq.error import report_exception

class HTTPScanningEngine(MySQLCollectionEngine, Engine):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # if set to True then we don't delete the work directories
        self.keep_work_dir = False

    @property
    def name(self):
        return 'http_scanner'

    def process(self, path):

        root = RootAnalysis()
        root.storage_dir = path

        try:
            root.load()
        except Exception as e:
            logging.error("unable to load {}: {}".format(root, e))
            report_exception()

        # now analyze the file
        try:
            self.analyze(root)
        except Exception as e:
            logging.error("analysis failed for {}: {}".format(path, e))
            report_exception()

    def post_analysis(self, root):
        if self.should_alert(root):
            root.submit()
            self.cancel_analysis()
        else:
            # any outstanding analysis left?
            if root.delayed:
                logging.debug("{} has delayed analysis -- waiting for cleanup...".format(root))
                return

    def root_analysis_completed(self, root):
        if root.delayed:
            return

        if not self.keep_work_dir:
            root.delete()
