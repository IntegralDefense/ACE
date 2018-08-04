import saq
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *
import re
import logging
import os
import os.path
import yara_scanner

#
# XXX these classes are deprecated
# this funcitonality was moved to the file_analysis module
#

class YaraScannerAnalysis(Analysis):
    @property
    def jinja_should_render(self):
        return False

class YaraAnalysis(Analysis):
    @property
    def jinja_should_render(self):
        return False
