# vim: sw=4:ts=4:et

import os
import os.path
import logging
import re
import sys
import json

import saq
from saq.error import report_exception
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule, LDAPAnalysisModule
from saq.constants import *

class UserTagAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    @property
    def jinja_should_render(self):
        return False

class UserTaggingAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return UserTagAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    @property
    def json_path(self):
        return os.path.join(saq.SAQ_HOME, self.config['json_path'])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapping = None # dict of key = username (lowercase), value = [ tags ]
        self.watch_file(self.json_path, self.load_tags)

    def load_tags(self):
        # if we haven't loaded it or if it has changed since the last time we loaded it
        logging.debug("loading {}".format(self.json_path))
        with open(self.json_path, 'r') as fp:
            self.mapping = json.load(fp)

    def execute_analysis(self, user):

        analysis = self.create_analysis(user)

        # does this user ID exist in our list of userIDs to tag?
        if user.value.lower().strip() in self.mapping:
            for tag in self.mapping[user.value.lower().strip()]:
                user.add_tag(tag)

        return True

class EmailAddressAnalysis(Analysis):
    """Who is the user associated to this email address?"""

    def initialize_details(self):
        self.details = {} # free form from ldap query

    def generate_summary(self):
        if self.details is not None:
            if 'uid' in self.details:
                return "Email Analysis - {0} - {1}".format(
                    self.details['uid'],
                    self.details['cn'] if 'cn' in self.details else '?')
            else:
                return "Email Analysis - {0} - {1}".format(
                    self.details['cn'] if 'cn' in self.details else '?', 
                    self.details['displayName'] if 'displayName' in self.details else '?')

        return None

class EmailAddressAnalyzer(LDAPAnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailAddressAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def execute_analysis(self, email_address):

        m = re.match(r'^<?([^>]+)>?$', email_address.value.strip())
        if m is None:
            logging.debug("unable to parse email address {}".format(email_address.value))
            return False

        normalized_email_address = m.group(1)

        ldap_result = self.ldap_query("mail={}".format(normalized_email_address))
        tivoli_ldap_result = self.tivoli_ldap_query("mail={}".format(normalized_email_address))
        if ldap_result is None and tivoli_ldap_result is None: 
            logging.debug("no results for {}".format(normalized_email_address))
            return False

        analysis = self.create_analysis(email_address)
        analysis.details = ldap_result
        if analysis.details is not None:
            if 'cn' in analysis.details:
                analysis.add_observable(F_USER, analysis.details['cn'])
                return True

        analysis.details = tivoli_ldap_result
        if analysis.details is not None:
            if 'uid' in analysis.details:
                analysis.details['cn'] = analysis.details['cn'][0] if 'cn' in analysis.details else ''
                analysis.details['uid'] = analysis.details['uid'][0] if 'uid' in analysis.details else ''
                analysis.add_observable(F_USER, analysis.details['uid'])
                return True

        return False

class UserAnalysis(Analysis):
    """What is the contact information for this user?  What is their position?  Who do they work for?"""

    def initialize_details(self):
        return None # free form from ldap query

    @property
    def jinja_template_path(self):
        return "analysis/user.html"

    def generate_summary(self):
        if not self.details:
            return None

        if not self.details['ldap']:
            return None

        if 'uid' in self.details['ldap']:
            return "User Analysis (Tivoli) - {} - {} - {}".format(
                self.details['ldap']['cn'] if 'cn' in self.details['ldap'] else '',
                self.details['ldap']['companyName'] if 'companyName' in self.details['ldap'] else '',
                self.details['ldap']['orgLevel4'] if 'orgLevel4' in self.details['ldap'] else '')

        return "User Analysis - {} - {} - {} - {}".format(
            self.details['ldap']['displayName'] if 'displayName' in self.details['ldap'] else '',
            self.details['ldap']['company'] if 'company' in self.details['ldap'] else '',
            self.details['ldap']['l'] if 'l' in self.details['ldap'] else '',
            self.details['ldap']['title'] if 'title' in self.details['ldap'] else '')

    def always_visible(self):
        return True

class UserAnalyzer(LDAPAnalysisModule):
    @property
    def generated_analysis_type(self):
        return UserAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    def _ldap_query_user(self, username):
        return self.ldap_query("cn={}*".format(username))

    def _tivoli_ldap_query_user(self, username):
        return self.tivoli_ldap_query("uid={}*".format(username))

    def execute_analysis(self, user):

        ldap_result = self._ldap_query_user(user.value)
        tivoli_ldap_result = self._tivoli_ldap_query_user(user.value)

        # try to look up the manager
        manager_result = None
        if ldap_result is None:
            logging.debug("did not find an ldap result for {}".format(user.value))
        elif 'manager' in ldap_result:
            for name_value_pair in ldap_result['manager'].split(','):
                (name, value) = name_value_pair.split('=', 2)
                if name == 'CN':
                    logging.debug("performing LDAP query for manager CN {} of user {}".format(
                        value, user.value))
                    manager_result = self._ldap_query_user(value)
                    if manager_result is not None and 'displayName' in manager_result:
                        logging.debug("got manager {} for user {}".format(manager_result['displayName'], user.value))

        # try again with tivoli
        if manager_result is None:
            if tivoli_ldap_result is None:
                logging.debug("did not find an tivoli ldap result for {}".format(user.value))
            elif 'managerID' in tivoli_ldap_result:
                manager_value = tivoli_ldap_result['managerID']
                logging.debug("performing LDAP query for manager CN {} of user {}".format(
                    manager_value, user.value))
                manager_result = self._ldap_query_user(manager_value)
                if manager_result is not None and 'displayName' in manager_result:
                    logging.debug("got manager {} for user {}".format(manager_result['displayName'], user.value))

        analysis = self.create_analysis(user)

        if ldap_result is None:
            analysis.details = { 'ldap': tivoli_ldap_result, 'manager_ldap': manager_result }
            # 'mail' and 'cn' return lists, take first entry or add_observable will error
            for key in [ 'mail', 'cn' ]:
                if key in analysis.details['ldap'] and isinstance(analysis.details['ldap'][key], list):
                    analysis.details['ldap'][key] = analysis.details['ldap'][key][0]
                else:
                    analysis.details['ldap'][key] = ''
        else:
            analysis.details = { 'ldap': ldap_result, 'manager_ldap': manager_result }

        # did we get an email address?
        if 'mail' in analysis.details['ldap'] and analysis.details['ldap']['mail']:
            analysis.add_observable(F_EMAIL_ADDRESS, analysis.details['ldap']['mail'])

        return True
