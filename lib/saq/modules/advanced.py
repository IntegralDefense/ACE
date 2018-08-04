# vim: sw=4:ts=4:et

import logging
import re

from urllib.parse import urlparse

import saq
from saq.analysis import Analysis, Observable, search_down
from saq.constants import *
from saq.modules import AnalysisModule
from saq.util import is_ipv4

KEY_SUSPICIOUS_URL = 'suspicious_url'

class EmailLinkAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_SUSPICIOUS_URL: False,
        }
        
    def generate_summary(self):
        if not self.details:
            return None

        if not self.suspicious_url:
            return None

        result = "Email Link Analysis"
        if self.suspicious_url:
            result += ' (suspicious url) '

        return result

    @property
    def suspicious_url(self):
        if not self.details:
            return None

        if not KEY_SUSPICIOUS_URL in self.details:
            return None

        return self.details[KEY_SUSPICIOUS_URL]

class EmailLinkAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailLinkAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, url):

        parsed_url = None

        try:
            parsed_url = urlparse(url.value)
        except Exception as e:
            logging.debug("unable to parse url {}: {}".format(url.value, e))
            return False

        url_path = parsed_url.path

        from saq.modules.email import EmailAnalysis

        # did this link come from an email?
        # examples
        # email --> word_document --> link
        # rfc822 (file) --> html attachment (file) --> link (url)

        email = search_down(url, lambda x: isinstance(x, EmailAnalysis))
        if email is None:
            return False

        # this link (ultimately) came from an email
        # is it a link to something that should not come from an email?

        def _susp_url(url_path):
            for ext in [ 'vbs','jse','exe','jar','lnk','ps1','bat','scr',
                         'hta','wsf','cmd','vbe','wsc', 'uue' ]:
                # urls that look like .exe?blah=something are typically CGI 
                if parsed_url.query == '' and url_path.lower().endswith('.{}'.format(ext)):
                    return True

            return False

        if _susp_url(url_path):
            analysis = self.create_analysis(url)
            url.add_detection_point("link to suspicious file extension from an email")
            url.add_directive(DIRECTIVE_FORCE_DOWNLOAD)
            analysis.details[KEY_SUSPICIOUS_URL] = True
            return True
        
        return False

SINGLE_FILE_REGEX = re.compile(r'^/[^/.]+\.[^/]+$')

class AdvancedLinkAnalysis(Analysis):

    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        if not self.details:
            return None

        return "Advanced Link Analysis: anomoly detected"

class AdvancedLinkAnalyzer(AnalysisModule):
        
    @property
    def generated_analysis_type(self):
        return AdvancedLinkAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, url):
        from saq.modules.cloudphish import CloudphishAnalysis
        from saq.cloudphish import SCAN_RESULT_ERROR, SCAN_RESULT_PASS

        cloudphish_analysis = self.wait_for_analysis(url, CloudphishAnalysis)
        if cloudphish_analysis is None:
            return False

        # is this a URL to an IP address to a single file in the root directory?
        # example: http://220.218.70.160/sec.hta

        try:
            parsed_url = urlparse(url.value)
        except Exception as e:
            logging.debug("unable to parse url {}: {}".format(url.value, e))
            return False

        # define what is considered suspicious to find in the root dir
        def _susp_file(path):
            for ext in [ 'doc','docx','docm','xls','xlsx','xlsm','ppt','pptx','pptm','pdf','js',
                         'vbs','jse','exe','swf','jar','lnk','ps1','rtf','chm','bat','scr',
                         'hta','cab','pif','au3','a3x','eps','xla','pptm','pps','dot','dotm','pub',
                         'wsf','cmd','ps','vbe','wsc' ]:
                if path.lower().endswith('.{}'.format(ext)):
                    return True

            return False

        analysis = self.create_analysis(url)

        if parsed_url.hostname and parsed_url.path:
            if is_ipv4(parsed_url.hostname) and SINGLE_FILE_REGEX.match(parsed_url.path):
                # ignore a link to a URL in the local network (common for companies to do locally)
                if not any([parsed_url.hostname in cidr for cidr in saq.MANAGED_NETWORKS]):
                    # and then the file extension must end in something suspicious
                    if _susp_file(parsed_url.path):
                        analysis.details = True
                        url.add_detection_point("URL to ipv4 to suspicious file in root directory")
                        url.add_directive(DIRECTIVE_FORCE_DOWNLOAD)

        # is the URL to an actual internet host?
        if parsed_url.hostname and '.' in parsed_url.hostname:
            # did this URL come from a stream file from an office document?
            stream_file = search_down(url, lambda x: isinstance(x, Observable) and x.type == F_FILE and '.officeparser/stream' in x.value)
            if stream_file:
                # what did cloudphish think of this url?
                if cloudphish_analysis.analysis_result not in [ SCAN_RESULT_ERROR, SCAN_RESULT_PASS ]:
                    #analysis.details = True
                    #url.add_detection_point("uncommon URL in ole stream file")
                    url.add_directive(DIRECTIVE_FORCE_DOWNLOAD)

        return True
