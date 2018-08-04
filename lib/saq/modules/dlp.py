# vim: sw=4:ts=4:et

import saq
from saq.analysis import Analysis, Observable
from saq.database import Alert
from saq.modules import SplunkAnalysisModule, splunktime_to_saqtime
from saq.modules.asset import AssetAnalysis, ActiveDirectoryAnalysis
from saq.constants import *
import re
import uuid
import logging
import hashlib

def hash_dlp_entry(row):
    """Utility function to return the MD5 hash of a given dlp entry, used for baselining."""
    hasher = hashlib.md5()
    hasher.update('{}:{}{}:{}'.format(
        row['MD5_Checksum'], row['Application_Directory'], row['Application'], row['Product_Version']).encode())
    return hasher.hexdigest()

class DLPProcessAnalysis(Analysis):
    """What processes were executing on this asset?  What is the frequency analysis of these processes?"""

    def initialize_details(self):
        self.details = None # free form

    @property
    def jinja_template_path(self):
        return "analysis/dlp_process_analysis.html"

    @property
    def jinja_details(self):
        if not hasattr(self, '_jinja_details'):
            # add an "id" element to each entry so that we can reference them in to GUI
            for x in self.details:
                x['id'] = str(uuid.uuid4())

            setattr(self, '_jinja_details', True)

        return self.details

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "DLP Process Analysis ({} processes)".format(len(self.details))

        return None

class DLPProcessAnalyzer(SplunkAnalysisModule):

    @property
    def generated_analysis_type(self):
        return DLPProcessAnalysis

    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    def execute_analysis(self, hostname):

        # XXX use SPLUNK to do the summary
        # the call to the baseline uses a different timespec 
        self.relative_duration_before = self.config['baseline_relative_duration_before']
        self.relative_duration_after = self.config['baseline_relative_duration_after']
        self.splunk_query('index=dlp_logs sourcetype="digitalguardian:process" {0} | fields _time Application Application_Directory Application_Full_Name Computer_Name Computer_Type, MD5_Checksum Company_Name Product_Name Product_Version User_Name | rename Computer_Name AS Full_Computer_Name | rename User_Name AS Full_User_Name | rex field=Full_Computer_Name "^[^/]+?/(?<Computer_Name>.+)$" | rex field=Full_User_Name "^[^/]+?/(?<User_Name>.+)$" | sort _time'.format(hostname.value),
            self.root.event_time_datetime if hostname.time_datetime is None else hostname.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        search_results = self.json()
        if len(search_results) == 0:
            logging.debug("no dlp results for {0}".format(hostname))
            return False

        baseline_analysis = {}

        for row in search_results:
            try:
                md5_hash = hash_dlp_entry(row)

                try:
                    baseline_analysis[md5_hash] += 1
                except KeyError:
                    baseline_analysis[md5_hash] = 1
            except Exception as e:
                logging.warning("unable to hash dlp row {}: {}".format(row, e))
                continue

        self.relative_duration_before = self.config['relative_duration_before']
        self.relative_duration_after = self.config['relative_duration_after']
        self.splunk_query('index=dlp_logs sourcetype="digitalguardian:process" {0} | fields _time Application Application_Directory Application_Full_Name Computer_Name Computer_Type, MD5_Checksum Company_Name Product_Name Product_Version User_Name | rename Computer_Name AS Full_Computer_Name | rename User_Name AS Full_User_Name | rex field=Full_Computer_Name "^[^/]+?/(?<Computer_Name>.+)$" | rex field=Full_User_Name "^[^/]+?/(?<User_Name>.+)$" | sort _time'.format(hostname.value),
            self.root.event_time_datetime if hostname.time_datetime is None else hostname.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(hostname)
        analysis.details = self.json()

        if isinstance(analysis.details, list) and len(analysis.details) > 0:
            # apply the local baseline to this analysis
            for row in analysis.details:
                md5_hash = hash_dlp_entry(row)
                try:
                    row['baseline_score'] = baseline_analysis[md5_hash]
                except KeyError:
                    row['baseline_score'] = 0

            # now run the global baseline

            self.relative_duration_before = self.config['global_baseline_relative_duration_before']
            self.relative_duration_after = self.config['global_baseline_relative_duration_after']
            self.splunk_query('index=dlp_logs sourcetype="digitalguardian:process" AND ( {0} ) | stats dc(Computer_Name) as Global_Count by MD5_Checksum'.format(
                ' OR '.join(list(set(['MD5_Checksum = {0}'.format(x['MD5_Checksum']) for x in analysis.details])))),
                self.root.event_time_datetime if hostname.time_datetime is None else hostname.time_datetime)

            if self.search_results is None:
                logging.debug("missing search results after global baseline splunk query")
                return True

            global_baseline_details = self.json()
            global_baseline_scores = {}
            for row in global_baseline_details:
                global_baseline_scores[row['MD5_Checksum']] = row['Global_Count']

            for row in analysis.details:
                try:
                    row['global_baseline_score'] = global_baseline_scores[row['MD5_Checksum']]
                except:
                    row['global_baseline_score'] = 0

        return True
