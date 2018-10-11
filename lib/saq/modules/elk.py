# vim: sw=4:ts=4:et

import logging

from saq.analysis import Analysis
from saq.constants import *
from saq.modules import ELKAnalysisModule

class ELKAnalysis(Analysis):
    """Base class for analysis results based on Elasticsearch queries."""

    def __init__(self, summary_prefix, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.summary_prefix = summary_prefix

    def initialize_details(self):
        self.details = None 

    @property
    def jinja_template_path(self):
        return "analysis/es.html"

    def generate_summary(self):
        if self.details is None:
            return None

        if not isinstance(self.details, dict):
            return None

        if 'hits' not in self.details:
            return None

        if self.details['hits']['total'] == 0:
            return None

        return '{} ({} results)'.format(self.summary_prefix, self.details['hits']['total'])

class SnortAlertsAnalysis(ELKAnalysis):
    """What are all the snort alerts for this ip address?"""
    def __init__(self, *args, **kwargs):
        super().__init__('Snort Alerts', *args, **kwargs)

class SnortAlertsAnalyzer(ELKAnalysisModule):
    @property
    def generated_analysis_type(self):
        return SnortAlertsAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def execute_analysis(self, ipv4):

        search_results = self.search('snort', 'src_ip:{} OR dest_ip:{}'.format(ipv4.value, ipv4.value))
        if search_results is None:
            return False

        analysis = self.create_analysis(ipv4)
        analysis.details = search_results
        return True
