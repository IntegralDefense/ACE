# vim: sw=4:ts=4:et

import email.utils
import json
import logging
import re
import urllib.parse

from bson import json_util
from bson.objectid import ObjectId
from pymongo import MongoClient

import saq
from saq.analysis import Analysis, DetectionPoint, Observable
from saq.constants import *
from saq.crits import update_status
from saq.modules import AnalysisModule

KEY_INDICATORS = 'indicators'

def is_subdomain(a, b):
    """Returns True if a is equal to or a subdomain of b."""
    if a is None or b is None or a == '' or b == '':
        return False

    if a == b:
        return True

    a_split = a.split('.')
    a_split.reverse()

    b_split = b.split('.')
    b_split.reverse()

    # b = evil.com [com, evil]
    # a = malware.evil.com [com, evil, malware]

    # b = google.com [com, google]
    # a = malware.evil.com [com, evil, malware]

    # b = su
    # a = malware.evil.su

    # len(a) = 3
    # len(b) = 2
    # a[0] == b[0]
    # a[1] == a[1]
    # i = 2

    i = 0
    while True:
        if a_split[i] != b_split[i]:
            return False

        i += 1
        if i >= len(a_split):
            return False

        if i >= len(b_split):
            return True
    
class CritsObservableAnalysis(Analysis):
    """Is this in CRITS?"""
    
    def initialize_details(self):
        self.details = {
            KEY_INDICATORS: [] }

    @property
    def indicators(self):
        if not self.details:
            return []

        if KEY_INDICATORS not in self.details:
            return []

        return self.details[KEY_INDICATORS]

    def generate_summary(self):
        if not self.details:
            return None

        if not self.indicators:
            return None

        return "CRITS Indicator Lookup ({} matches)".format(len(self.details[KEY_INDICATORS]))

class CritsObservableAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return CritsObservableAnalysis

    @property
    def valid_observable_types(self):
        return ( F_IPV4, F_FQDN, F_URL, F_FILE_PATH, F_FILE_NAME, F_EMAIL_ADDRESS, F_MD5, F_SHA1, F_SHA256 )
    
    def execute_analysis(self, observable):

        analysis = self.create_analysis(observable)

        client = MongoClient(saq.CONFIG['crits']['mongodb_uri'])
        db = client['crits']
        collection = db['indicators']

        indicators = set() # temp storage for uniq
        analysis.details = { KEY_INDICATORS: [] }

        logging.debug("searching crits for {}".format(observable))

        if observable.type == F_IPV4:
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'Address - ipv4-addr',
                'value': observable.value }):
                indicators.add(str(indicator['_id']))

            # IP addresses do not have letters, so no need for re.IGNORECASE here.
            for indicator in collection.find({
                '$or': [ {'type': 'URI - Domain Name'}, {'type': 'URI - URL'}, {'type': 'URI - Path'} ],
                'status': 'Analyzed',
                'value': {'$regex': '{}'.format(re.escape(observable.value))}}):
                indicators.add(str(indicator['_id']))

        elif observable.type == F_FQDN:
            # make sure this is really a FQDN
            if '.' not in observable.value:
                logging.debug("{} is not actually an FQDN".format(observable))
            else:
                # Need to use re.IGNORECASE for domains.
                for indicator in collection.find({
                    '$or': [ {'type': 'Email - Address'}, {'type': 'URI - Domain Name'}, {'type': 'URI - URL'}, {'type': 'URI - Path'} ],
                    'status': 'Analyzed',
                    'value': re.compile(re.escape(observable.value), re.IGNORECASE)}):
                    indicators.add(str(indicator['_id']))

                # is the observed domain equal to or a subdomain of anything in crits?
                for indicator in collection.find({'type': 'URI - Domain Name', 'status': 'Analyzed'}):
                    if is_subdomain(observable.value, indicator['value']):
                        logging.debug("{} matches domain {}".format(observable, indicator['value']))
                        indicators.add(str(indicator['_id']))

        elif observable.type == F_URL:
            # URI - URL have to be an exact match (with re.IGNORECASE)
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'URI - URL',
                'value': re.compile('^{}$'.format(re.escape(observable.value)), re.IGNORECASE)}):
                #logging.debug("MARKER: exact match {}".format(indicator['_id']))
                indicators.add(str(indicator['_id']))

            # for this part we have to parse the URL if we can
            try:
                parsed_url = urllib.parse.urlparse(observable.value)

                if parsed_url.path is not None and len(parsed_url.path) > 0:
                    # look for just the path (with re.IGNORECASE)
                    for indicator in collection.find({
                        'status': 'Analyzed',
                        'type': 'URI - Path',
                        'value': re.compile('^{}$'.format(re.escape(parsed_url.path)), re.IGNORECASE)}):
                        #logging.debug("MARKER: path match {} - {}".format(parsed_url.path, indicator['_id']))
                        indicators.add(str(indicator['_id']))

                # and then look for the hostname/path (with re.IGNORECASE)
                if parsed_url.netloc is not None and len(parsed_url.netloc) > 0 and parsed_url.path is not None and len(parsed_url.netloc) > 0:
                    #logging.debug("looking up {}{}".format(parsed_url.netloc.lower(), parsed_url.path.lower()))
                    for indicator in collection.find({
                        'status': 'Analyzed',
                        'type': 'URI - Path',
                        'value': re.compile(re.escape('{}{}'.format(parsed_url.netloc, parsed_url.path)), re.IGNORECASE)}):
                        #logging.debug("MARKER: hostname path match {}".format(indicator['_id']))
                        indicators.add(str(indicator['_id']))

            except Exception as e:
                logging.debug("unable to parse url {}: {}".format(observable.value, str(e)))

        # File names need re.IGNORECASE
        elif observable.type == F_FILE_NAME:
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'Windows - FileName',
                'value': re.compile(re.escape(observable.value), re.IGNORECASE)}):
                indicators.add(str(indicator['_id']))

        # File paths need re.IGNORECASE
        elif observable.type == F_FILE_PATH:
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'Windows - FilePath',
                'value': re.compile(re.escape(observable.value), re.IGNORECASE)}):
                indicators.add(str(indicator['_id']))

        # E-mail addresses need re.IGNORECASE
        elif observable.type == F_EMAIL_ADDRESS:
            # make sure this is really an email address
            if '@' not in observable.value:
                logging.debug("{} appears to not be an actual email address".format(observable.value))
            else:
                # try to parse the email address
                try:
                    name, address = email.utils.parseaddr(observable.value)
                    for indicator in collection.find({
                        'status': 'Analyzed',
                        'type': 'Email - Address',
                        'value': re.compile(re.escape(address), re.IGNORECASE)}):
                        indicators.add(str(indicator['_id']))
                    
                except Exception as e:
                    logging.debug("unable to parse {} as an email address: {}".format(observable.value, str(e)))

        # All Hash - * indicators need re.IGNORECASE but can skip re.escape since they can't have regex chars in them.
        elif observable.type == F_MD5:
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'Hash - MD5',
                'value': re.compile(observable.value, re.IGNORECASE)}):
                indicators.add(str(indicator['_id']))

        elif observable.type == F_SHA1:
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'Hash - SHA1',
                'value': re.compile(observable.value, re.IGNORECASE)}):
                indicators.add(str(indicator['_id']))

        elif observable.type == F_SHA256:
            for indicator in collection.find({
                'status': 'Analyzed',
                'type': 'Hash - SHA256',
                'value': re.compile(observable.value, re.IGNORECASE)}):
                indicators.add(str(indicator['_id']))
            
        analysis.indicators.extend(list(indicators))
        for indicator in analysis.indicators:
            analysis.add_observable(F_INDICATOR, indicator)

        return True

class CritsAnalysis(Analysis):
    """What are the CRITS details of this indicator?"""

    def initialize_details(self):
        self.details = {} # free form from json query

    @property
    def jinja_template_path(self):
        return 'analysis/crits.html'

    def generate_summary(self):
        if self.details is None:
            return None

        if 'campaign' not in self.details or \
           'source' not in self.details or \
           'type' not in self.details or \
           'value' not in self.details:
            return 'CRITS Analysis - ERROR: response is missing fields because MongoDB is horrible'

        # create a nice visual summary
        campaigns = ''
        sources = ''

        if 'campaign' in self.details:
            campaigns = ','.join([x['name'] for x in self.details['campaign']])

        if 'source' in self.details:
            sources = ','.join([x['name'] for x in self.details['source']])
        
        return 'CRITS Analysis - [{0}] [{1}] [{2}] [{3}]'.format(
            campaigns, sources, self.details['type'], self.details['value'])

class CritsAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return CritsAnalysis

    @property
    def valid_observable_types(self):
        return F_INDICATOR
    
    def execute_analysis(self, indicator):

        analysis = self.create_analysis(indicator)

        # download the crits indicator JSOn directly from the crits mongo database
        client = MongoClient(saq.CONFIG['crits']['mongodb_uri'])
        db = client['crits']
        collection = db['indicators']

        mongo_object = analysis.details = collection.find_one({'_id' : ObjectId(indicator.value)})

        if analysis.details is None:
            logging.error("unable to find details of indicator {}".format(indicator.value))
            return False
        
        # this extra step is required to remove the ObjectId objects in the JSON result
        analysis.details = json.loads(json.dumps(analysis.details, default=json_util.default))

        # extract any tags (buckets) associated with the indicator
        if 'bucket_list' in mongo_object and isinstance(mongo_object['bucket_list'], list):
            for tag in mongo_object['bucket_list']:
                indicator.add_tag(tag)

        # add any associated campaigns as tags as well
        if 'campaign' in analysis.details:
            for actor in analysis.details['campaign']:
                indicator.add_tag('apt:{0}'.format(actor['name']))

        return True

class FAQueueAlertAnalysis(Analysis):
    """Update crits with the status of the disposition of alerts generated by faqueue."""
    def initialize_details(self):
        pass

    def generate_summary(self):
        return None

class FAQueueAlertAnalyzer(AnalysisModule):
    """Update crits with the status of the disposition of alerts generated by faqueue."""

    @property
    def generated_analysis_type(self):
        return FAQueueAlertAnalysis

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, obj):
        return False
    
    def execute_post_analysis(self):
        import saq.database

        if not isinstance(self.root, saq.database.Alert):
            logging.error("the FAQueueAlertAnalyzer module is only intended to be executed in the  "
                          "correlation engine")
            return False

        # we only look at faqueue alerts
        if not self.root.alert_type == 'faqueue':
            logging.debug("{} is not the correct type".format(self.root))
            return False

        if not self.root.disposition:
            logging.debug("{} does not have a disposition yet".format(self.root))
            return False

        # has the disposition changed?
        if self.state and self.root.disposition == self.state:
            logging.debug("disposition for alert {} has not changed".format(self.root))
            return False

        # remember the disposition
        self.state = self.root.disposition

        crits_analysis_value = None
        if self.root.disposition == DISPOSITION_FALSE_POSITIVE:
            crits_analysis_value = 'Informational'
        else: 
            crits_analysis_value = 'Analyzed'

        if 'indicator' not in self.root.details:
            logging.error("missing indicator key in faqueue alert {}".format(self.root))
            return False

        if 'crits_id' not in self.root.details['indicator']:
            logging.error("missing crits_id key in faqueue alert {}".format(self.root))
            return False

        # update mongo
        crits_id = self.root.details['indicator']['crits_id']
        logging.info("updating crits_id {} to status {}".format(crits_id, crits_analysis_value))
        total_crits_indicators_updated = update_status(crits_id, crits_analysis_value)
        logging.info("updated {} crits indicators".format(total_crits_indicators_updated))

        return True
