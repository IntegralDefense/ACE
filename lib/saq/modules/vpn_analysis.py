# vim: sw=4:ts=4:et

import logging

from datetime import timedelta

import saq
from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import SplunkAnalysisModule, splunktime_to_saqtime, splunktime_to_datetime
from saq.modules.asset import NetworkIdentifierAnalysis

KEY_LOGS = 'logs'
KEY_TIME = 'time'

class VPNAnalysis(Analysis):
    """Was this user logged into VPN at this time?"""

    def initialize_details(self):
        self.details = {
            KEY_LOGS: [],
            KEY_TIME: None
        }
    
    @property
    def jinja_template_path(self):
        return "analysis/vpn_analysis.html"

    @property
    def logs(self):
        return self.details[KEY_LOGS]

    @logs.setter
    def logs(self, value):
        self.details[KEY_LOGS] = value

    @property
    def time(self):
        return self.details[KEY_TIME]

    @time.setter
    def time(self, value):
        self.details[KEY_TIME] = value

    @property
    def was_on_vpn(self):
        return self.time is not None

    def upgrade(self):
        if KEY_LOGS not in self.details:
            logging.debug("upgrading {0}".format(self))
            self.details = {
                KEY_LOGS: self.details,
                KEY_TIME: None }

    def generate_summary(self):
        if self.was_on_vpn:
            return 'VPN Analysis - logged in at {0}'.format(self.time)

        return None

class VPNAnalyzer(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return VPNAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    def execute_analysis(self, user):

        # query radius logs to get VPN login information
        self.splunk_query('index=radius User_Name="{0}" ( Acct_Status_Type=Stop OR Acct_Status_Type=Start ) | fields User_Name Acct_Status_Type Framed_IP_Address Calling_Station_ID Acct_Session_Time | sort _time'.format(
            user.value.upper()), self.root.event_time_datetime if user.time_datetime is None else user.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(user)
        analysis.logs = self.json()

        # was this user logged into VPN when the event occured?
        user_login_time = None
        for index, entry in enumerate(analysis.logs):
            if 'Acct_Status_Type' not in entry:
                continue

            dt = splunktime_to_datetime(entry['_time'])

            if entry['Acct_Status_Type'] == 'Stop':
                # the Stop event logs the amount of the time the user was on VPN
                if self.root.event_time_datetime >= dt - timedelta(seconds=int(entry['Acct_Session_Time'])) and self.root.event_time_datetime <= dt:
                    analysis.time = splunktime_to_datetime(entry['_time'])
                    break

            # did this event happen before any recorded VPN activity?
            # note the check above would catch if the alert happend before the first alert and the first alert was a Stop alert
            if index == 0 and self.root.event_time_datetime < dt:
                logging.debug("first event and alert is before this event")
                break

            # if this is the last alert and the last event we see is a stop event then we're out of range again
            if index == len(analysis.logs) - 1 and entry['Acct_Status_Type'] == 'Stop':
                logging.debug("last event and alert is after this stop event")
                break

            # if the last event we see is a Start then they are currently on VPN
            if ( index == len(analysis.logs) - 1 
                and entry['Acct_Status_Type'] == 'Start' 
                and self.root.event_time_datetime >= splunktime_to_datetime(analysis.logs[index]['_time'])):
                logging.debug("last event is start event")
                analysis.time = splunktime_to_datetime(analysis.logs[index]['_time'])
                break

            # is this between and start and a stop?
            if index > 0:
                if ( analysis.logs[index - 1]['Acct_Status_Type'] == 'Start' 
                    and self.root.event_time_datetime >= splunktime_to_datetime(analysis.logs[index - 1]['_time'])
                    and entry['Acct_Status_Type'] == 'Stop'
                    and self.root.event_time_datetime <= dt ):
                    logging.debug("found event inside start/stop")
                    analysis.time = splunktime_to_datetime(analysis.logs[index - 1]['_time'])
                    break

        return True
