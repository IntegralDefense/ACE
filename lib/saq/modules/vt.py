# vim: sw=4:ts=4:et

import json
import logging
import os
import shutil

import saq
from saq.analysis import Analysis, Observable
from saq.modules.file_analysis import FileHashAnalysis
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.constants import *

import requests

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

VT_KEY_RESPONSE_CODE = 'response_code'
VT_KEY_POSITIVES = 'positives'
VT_KEY_TOTAL = 'total'
VT_KEY_PERMALINK = 'permalink'
VT_KEY_MD5 = 'md5'
VT_KEY_SHA1 = 'sha1'
VT_KEY_SHA256 = 'sha256'
VT_KEY_SCANS = 'scans'

KEY_DOWNLOADED = 'downloaded'

class VTHashFileDownloaderAnalysis(Analysis):
    """What is the binary content of the file with this hash?"""

    def initialize_details(self):
        self.details = {
            KEY_DOWNLOADED: False,
        }

    def generate_summary(self):
        if self.details is not None:
            return 'File Downloaded from VirusTotal'
        return None

class VTHashFileDownloader(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return VTHashFileDownloaderAnalysis

    @property
    def valid_observable_types(self):
        return F_MD5, F_SHA1, F_SHA256

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.api_key = saq.CONFIG['virus_total']['api_key']
        self.download_url = saq.CONFIG['virus_total']['download_url']
        self.cache_dir = os.path.join(saq.SAQ_HOME, saq.CONFIG['virus_total']['cache_dir'])

        if not os.path.isdir(self.cache_dir):
            try:
                os.makedirs(self.cache_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(self.cache_dir, str(e)))
                report_exception()

    def execute_analysis(self, _hash):
        # need the VT hash analysis first
        hash_analysis = self.wait_for_analysis(_hash, VTHashAnalysis)
        if not hash_analysis:
            return False

        analysis = self.create_analysis(_hash)

        # if this is a hash for a file that we already have then we don't need to download it
        for f in self.root.all_observables:
            if f.type == F_FILE:
                a = f.get_analysis(FileHashAnalysis)
                if a:
                    for h in a.observables:
                        if h == _hash and f.exists:
                            logging.debug("hash {} belongs to file {} -- not downloading".format(_hash, f))
                            return False

        if not hash_analysis.is_known():
            logging.debug("hash {} is unknown to VT -- will not download".format(_hash))
            return False

        if VT_KEY_MD5 not in hash_analysis.details:
            logging.error("missing {} in hash analysis".format(VT_KEY_MD5))

        md5_hash = hash_analysis.details[VT_KEY_MD5]
        download_storage_dir = os.path.join(self.root.storage_dir, 'vt_downloads')
        if not os.path.exists(download_storage_dir):
            try:
                os.makedirs(download_storage_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(download_storage_dir, e))
                report_exception()
                return False

        dest_path = os.path.join(download_storage_dir, md5_hash)

        # does this MD5 already exist in the cache?
        cache_path_subdir = os.path.join(self.cache_dir, md5_hash[0:2])
        if not os.path.isdir(cache_path_subdir):
            try:
                os.makedirs(cache_path_subdir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(cache_path_subdir, e))
                report_exception()
                return False
        
        cache_path = os.path.join(cache_path_subdir, md5_hash)
        
        if not os.path.exists(cache_path):
            # download it from VT
            logging.info("attempting to download {} from virus total to cache".format(md5_hash))
            params = {
                'apikey': self.api_key,
                'hash': md5_hash }

            r = requests.get(self.download_url, params=params, proxies=saq.PROXIES)
            if r.status_code == 200:
                file_content = r.content
                # then save it to the cache
                with open(cache_path, 'wb') as fp:
                    fp.write(file_content)
                    logging.debug("saved {} to vt cache {}".format(_hash, cache_path))
            else:
                logging.error("unable to download file: {} ({})".format(r.status_code, r.reason))
                return False

        if os.path.exists(cache_path):
            logging.debug("found {} in cache".format(md5_hash))
            # copy it to this local directory
            try:
                logging.debug("copying from cache {} to {}".format(cache_path, dest_path))
                shutil.copy(cache_path, dest_path)
            except Exception as e:
                logging.error("unable to copy: {}".format(e))
                report_exception()
                return False
            
            analysis = self.create_analysis(_hash)
            analysis.details = { 'downloaded': True }
            file_observable = analysis.add_observable(F_FILE, os.path.relpath(dest_path, start=self.root.storage_dir))

            # if the hash has been tagged as malicious then this file is also malicious and we want to sandbox it
            if file_observable and hash_analysis.has_tag('malicious'):
                file_observable.add_tag('malicious')
                file_observable.add_directive(DIRECTIVE_SANDBOX)

            return True

class VTHashAnalysis(Analysis):
    """What is the Virus Total analysis of this hash?"""

    def initialize_details(self):
        self.details = None # we use whatever is returned by VT

    @property
    def response_code(self):
        try:
            return self.details[VT_KEY_RESPONSE_CODE]
        except KeyError:
            return None

    @property
    def positives(self):
        try:
            return self.details[VT_KEY_POSITIVES]
        except KeyError:
            return None

    @property
    def total(self):
        try:
            return self.details[VT_KEY_TOTAL]
        except KeyError:
            return None

    @property
    def permalink(self):
        try:
            return self.details[VT_KEY_PERMALINK]
        except KeyError:
            return None

    @property
    def md5(self):
        try:
            return self.details[VT_KEY_MD5]
        except KeyError:
            return None

    @property
    def sha1(self):
        try:
            return self.details[VT_KEY_SHA1]
        except KeyError:
            return None

    @property
    def sha256(self):
        try:
            return self.details[VT_KEY_SHA256]
        except KeyError:
            return None

    @property
    def scans(self):
        try:
            return self.details[VT_KEY_SCANS]
        except KeyError:
            return None

    def check_keys(self):
        for key in [
            VT_KEY_RESPONSE_CODE,
            VT_KEY_POSITIVES,
            VT_KEY_TOTAL,
            VT_KEY_PERMALINK,
            VT_KEY_MD5,
            VT_KEY_SHA1,
            VT_KEY_SHA256,
            VT_KEY_SCANS ]:

            if key not in self.details:
                logging.error("missing key {0}".format(key))
                return False

        return True

    def is_known(self):
        """Returns True if the hash is known to VT, False if not, or None on error."""
        if self.details is None:
            return None
            
        if VT_KEY_RESPONSE_CODE not in self.details:
            logging.error("missing response_code")
            return None

        return self.response_code != 0

    def generate_summary(self):
        if not self.check_keys:
            return 'VT Analysis - ERROR - missing keys (check logs)'

        if not self.is_known():
            return 'VT Analysis - UNKNOWN'

        result = 'VT Analysis - {0}/{1}'.format(
            self.positives,
            self.total)

        if self.scans is not None:
            additional_details = []
            for av_vendor in self.scans.keys():
                if self.scans[av_vendor]['detected']:
                    additional_details.append('{0}:{1}'.format(
                        av_vendor,
                        self.scans[av_vendor]['result']))

            if len(additional_details) > 0:
                result = '{0} {1}'.format(result, ', '.join(additional_details))

        return result

class VTHashAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return VTHashAnalysis

    @property
    def valid_observable_types(self):
        return F_MD5, F_SHA1, F_SHA256

    def __init__(self, *args, **kwargs):
        super(VTHashAnalyzer, self).__init__(*args, **kwargs)

        #self.api_key = saq.CONFIG['virus_total']['api_key']
        self.query_url = self.config['query_url']
        self.proxies = saq.PROXIES if self.config.getboolean('use_proxy') else {}
        if 'ignored_vendors' in self.config:
            self.ignored_vendors = set([x.strip().lower() for x in self.config['ignored_vendors'].split(',')])
        else:
            self.ignored_vendors = set()

    def execute_analysis(self, _hash):

        # it is possible that you are looking at an MD5 but you already have the analysis of the SHA1
        # but you don't know that the MD5 and the SHA1 are hashes of the same thing
        # VT analysis will you tell that
        for a in self.root.all_analysis:
            if isinstance(a, VTHashAnalysis):
                if a.details is not None:
                    if VT_KEY_MD5 in a.details and VT_KEY_SHA1 in a.details and VT_KEY_SHA256 in a.details:
                        if ( (_hash.type == F_MD5 and _hash.value == a.details[VT_KEY_MD5])
                            or (_hash.type == F_SHA1 and _hash.value == a.details[VT_KEY_SHA1])
                            or (_hash.type == F_SHA256 and _hash.value == a.details[VT_KEY_SHA256])):
                            logging.debug("found existing VT analysis for {}".format(_hash))
                            return False

        # for each hash, look to see if it came from a FileHashAnalysis
        for analysis in self.root.iterate_all_references(_hash):
            if isinstance(analysis, FileHashAnalysis):
                # have we already queried VT another hash?
                for hash_type in [F_MD5, F_SHA1, F_SHA256]:
                    for other_hash in analysis.get_observables_by_type(hash_type):
                        if other_hash.get_analysis(VTHashAnalysis):
                            logging.debug("found VT lookup for hash {} related to {}".format(other_hash, _hash))
                            return False


        logging.debug("looking up VT report for {}".format(_hash))

        try:
            #r = requests.get(self.query_url, params={
                #'resource': _hash.value,
                #'apikey': self.api_key}, proxies=saq.PROXIES, timeout=5)

            r = requests.get(self.query_url, params={ 'h': _hash.value }, proxies=self.proxies, timeout=5, verify=False)

        except Exception as e:
            logging.error("unable to query VT: {}".format(e))
            return False

        if r.status_code == 403:
            logging.error("invalid virus total api key!")
            return False

        if r.status_code != 200:
            logging.debug("got invalid HTTP result {}: {}".format(r.status_code, r.reason))
            return False

        analysis = self.create_analysis(_hash)

        # note that here were just using whatever virus total sends
        # if they change their JSON structure we'll probably break

        logging.debug("got valid vt result for {}".format(_hash))
        analysis.details = json.loads(r.content.decode())
        
        # 4/28/2016 - looks like they now return an array of results
        if isinstance(analysis.details, list):
            analysis.details = analysis.details[0]

        if not isinstance(analysis.details, dict):
            logging.error("expecting dict but got {} for analysis.details of vt".format(type(analysis.details)))
            return False

        # do any vendors outside of our excluded list of vendors think this is "bad"
        if 'scans' in analysis.details:
            if isinstance(analysis.details['scans'], dict):
                for vendor in analysis.details['scans'].keys():
                    if vendor.lower() in self.ignored_vendors:
                        continue

                    vendor_report = analysis.details['scans'][vendor]
                    if isinstance(vendor_report, dict):
                        if 'detected' in vendor_report:
                            if vendor_report['detected']:
                                logging.info("vt vendor {} says {} is malicious".format(vendor, _hash.value))
                                _hash.add_tag('malicious')
                                return True

        logging.debug("nothing malicious in vt report for {}".format(_hash.value))
        return True
        
