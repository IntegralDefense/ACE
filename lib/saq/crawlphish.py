# vim: sw=4:ts=4:et:cc=120
#

import sqlite3
import logging
import os.path
import re
from ipaddress import IPv4Network
from urllib.parse import urlparse, ParseResult, urlunparse

import saq
from saq.brocess import query_brocess_by_fqdn, add_httplog
from saq.error import report_exception
from saq.util import is_ipv4, is_subdomain, iterate_fqdn_parts

analysis_module = 'analysis_module_crawlphish'

REASON_ERROR =          'ERROR'
REASON_UNKNOWN =        'UNKNOWN'
REASON_WHITELISTED =    'WHITELISTED'
REASON_BLACKLISTED =    'BLACKLISTED'
REASON_CRITS =          'CRITS'
REASON_COMMON_NETWORK = 'COMMON_NETWORK'
REASON_DIRECT_IPV4 =    'DIRECT_IPV4'
REASON_OK =             'OK'

# crits constants
CRITS_IPV4 = 'Address - ipv4-addr'
CRITS_FQDN = 'URI - Domain Name'
CRITS_URL = 'URI - URL'
CRITS_URL_PATH = 'URI - Path'
CRITS_FILE_NAME = 'Windows - FileName'

SCHEMA_REGEX = re.compile('^[a-zA-Z]+://')

def process_url(url):
    m = SCHEMA_REGEX.search(url)
    if m is None:
        logging.debug("adding missing schema to url {}".format(url))
        url = 'http://{}'.format(url)

    # make sure the url is valid
    parsed_url = urlparse(url)

    if not parsed_url.netloc:
        logging.debug("no netloc for {}".format(url))
        return None

    return parsed_url

class FilterResult(object):
    def __init__(self):
        # was it filtered
        self.filtered = False
        # why was it filtered (or not filtered)
        self.reason = REASON_UNKNOWN
        # result of urlparse on reformatted url
        self.parsed_url = None

    def __bool__(self):
        return self.filtered

class CrawlphishURLFilter(object):

    #def __init__(self):
        #self.reason = REASON_UNKNOWN
        #self.parsed_url = None

    def load(self):
        self.load_whitelist()
        self.load_blacklist()
        self.load_path_regexes()

    @property
    def whitelist_path(self):
        path = saq.CONFIG[analysis_module]['whitelist_path']
        if os.path.isabs(path):
            return path

        return os.path.join(saq.SAQ_HOME, path)

    @property
    def blacklist_path(self):
        path = saq.CONFIG[analysis_module]['blacklist_path']
        if os.path.isabs(path):
            return path

        return os.path.join(saq.SAQ_HOME, path)

    @property
    def regex_path(self):
        path = saq.CONFIG[analysis_module]['regex_path']
        if os.path.isabs(path):
            return path

        return os.path.join(saq.SAQ_HOME, path)

    def load_whitelist(self):
        logging.debug("loading whitelist from {}".format(self.whitelist_path))
        whitelisted_fqdn = []
        whitelisted_cidr = []

        try:
            with open(self.whitelist_path, 'r') as fp:
                for line in fp:
                    line = line.strip()

                    # skip comments
                    if line.startswith('#'):
                        continue

                    # skip blank lines
                    if line == '':
                        continue

                    if is_ipv4(line):
                        whitelisted_cidr.append(IPv4Network(line))
                    else:
                        whitelisted_fqdn.append(line)

            self.whitelisted_cidr = whitelisted_cidr
            self.whitelisted_fqdn = whitelisted_fqdn
            logging.debug("loaded {} cidr {} fqdn whitelisted items".format(
                           len(self.whitelisted_cidr),
                           len(self.whitelisted_fqdn)))

        except Exception as e:
            logging.error("unable to load whitelist {}: {}".format(self.whitelist_path, e))
            report_exception()

    def is_whitelisted(self, value):
        if is_ipv4(value):
            for cidr in self.whitelisted_cidr:
                if value in cidr:
                    logging.debug("{} matches whitelisted cidr {}".format(value, cidr))
                    return True

            return False

        for dst in self.whitelisted_fqdn:
            if is_subdomain(value, dst):
                logging.debug("{} matches whitelisted fqdn {}".format(value, dst))
                return True

        return False

    def load_blacklist(self):
        logging.debug("loading blacklist from {}".format(self.blacklist_path))
        blacklisted_fqdn = []
        blacklisted_cidr = []

        try:
            with open(self.blacklist_path, 'r') as fp:
                for line in fp:
                    line = line.strip()

                    # skip comments
                    if line.startswith('#'):
                        continue

                    # skip blank lines
                    if line == '':
                        continue

                    if is_ipv4(line):
                        blacklisted_cidr.append(IPv4Network(line))
                    else:
                        blacklisted_fqdn.append(line)

            self.blacklisted_cidr = blacklisted_cidr
            self.blacklisted_fqdn = blacklisted_fqdn
            logging.debug("loaded {} cidr {} fqdn blacklisted items".format(
                           len(self.blacklisted_cidr),
                           len(self.blacklisted_fqdn)))

        except Exception as e:
            logging.error("unable to load blacklist {}: {}".format(self.blacklist_path, e))
            report_exception()

    def load_path_regexes(self):
        logging.debug("loading path regexes from {}".format(self.regex_path))
        path_regexes = []

        try:
            with open(self.regex_path, 'r') as fp:
                for line in fp:
                    line = line.strip()

                    # skip comments
                    if line.startswith('#'):
                        continue

                    # skip blank lines
                    if line == '':
                        continue

                    # try to compile it
                    try:
                        path_regexes.append(re.compile(line, re.I))
                    except Exception as e:
                        logging.error("regular expression {} does not compile: {}".format(line, e))

            self.path_regexes = path_regexes
            logging.debug("loaded {} path regexes".format(len(self.path_regexes)))

        except Exception as e:
            logging.error("unable to load path regexes from {}: {}".format(self.regex_path, e))
            report_exception()

    def is_blacklisted(self, value):
        if is_ipv4(value):
            for cidr in self.blacklisted_cidr:
                try:
                    if value in cidr:
                        logging.debug("{} matches blacklisted cidr {}".format(value, cidr))
                        return True
                except Exception as e:
                    logging.error("failed to compare {} to {}: {}".format(value, cidr, e))
                    report_exception()

            return False

        for dst in self.blacklisted_fqdn:
            if is_subdomain(value, dst):
                logging.debug("{} matches blacklisted fqdn {}".format(value, dst))
                return True

        return False

    def matches_path_regex(self, url):
        for path_regex in self.path_regexes:
            if path_regex.search(url):
                logging.debug("{} matches patch regex {}".format(url, path_regex))
                return True

        return False

    def is_in_crits(self, value):
        try:
            return self._is_in_crits(value)
        except Exception as e:
            logging.error("is_in_crits failed: {}".format(e))

    def _is_in_crits(self, value):
        """Is this URL in crits?  value is the result of calling process_url on a URL."""
        assert isinstance(value, ParseResult)

        cache_path = os.path.join(saq.SAQ_HOME, saq.CONFIG['crits']['cache_db_path'])
        with sqlite3.connect('file:{}?mode=ro'.format(cache_path), uri=True) as db:
            db_cursor = db.cursor()
            row = None

            # check ipv4
            if is_ipv4(value.hostname):
                db_cursor.execute("SELECT id FROM indicators WHERE type = ? AND value = ?", 
                                 (CRITS_IPV4, value.hostname))

                row = db_cursor.fetchone()
                if row:
                    logging.debug("{} matched crits ipv4 indicator {}".format(value.hostname, row[0]))
                    return True
            else:
                # check fqdn
                for partial_fqdn in iterate_fqdn_parts(value.hostname):
                    #logging.debug("checking crits for {}".format(partial_fqdn))
                    db_cursor.execute("SELECT id FROM indicators WHERE type = ? AND value = ?",
                                     (CRITS_FQDN, partial_fqdn.lower()))

                    row = db_cursor.fetchone()
                    if row:
                        logging.debug("{} matched crits fqdn indicator {}".format(partial_fqdn, row[0]))
                        return True
                        
            # check full url
            db_cursor.execute("SELECT id FROM indicators WHERE type = ? AND value = LOWER(?)",
                             (CRITS_URL, value.geturl()))

            row = db_cursor.fetchone()
            if row:
                logging.debug("{} matched crits url indicator{}".format(value.geturl(), row[0]))
                return True

            # check url path
            path = urlunparse(('', '', value.path, value.params, value.query, value.fragment))
            if path:
                db_cursor.execute("SELECT id FROM indicators WHERE type = ? AND value = LOWER(?)",
                                 (CRITS_URL_PATH, path))

                row = db_cursor.fetchone()
                if row:
                    logging.debug("{} matched crits url_path indicator {}".format(value.path, row[0]))
                    return True

            # check url file name
            if value.path:
                if not value.path.endswith('/'):
                    file_name = value.path.split('/')[-1]
                    db_cursor.execute("SELECT id FROM indicators WHERE type = ? AND value = LOWER(?)",
                                     (CRITS_FILE_NAME, file_name))

                    row = db_cursor.fetchone()
                    if row:
                        logging.debug("{} matched crits file_name indicator {}".format(file_name, row[0]))
                        return True

            #logging.debug("{} {} in crits".format(value, 'is' if result else 'is not'))
            return False

    def _is_uncommon_fqdn(self, fqdn):
        """Returns True if the given fqnd is considered "uncommon"."""
        # consider a.b.c.d
        # if d is common then we want to see if c.d is uncommon
        # if c.d is common then we look at b.c.d, and so forth
        # if they are all common then we return False
        for partial_fqdn in iterate_fqdn_parts(fqdn):
            count = query_brocess_by_fqdn(partial_fqdn)

            if count is None:
                continue

            if count < saq.CONFIG[analysis_module].getint('uncommon_network_threshold'):
                logging.info("{} is an uncommon network with count {}".format(partial_fqdn, count))
                return True
            else:
                pass
                #logging.debug("{} is a common network with count {}".format(partial_fqdn, count))

        return False
        
    def is_uncommon_network(self, value):
        try:
            return self._is_uncommon_fqdn(value)
        except Exception as e:
            logging.error("unable to query brocess: {}".format(e))
            report_exception()
            return False

    def filter(self, url):
        """Returns True if the given URL should be filtered (not crawled).  Check the reason property
           the reason the url is filtered."""
        result = FilterResult()
        result.filtered = False
        result.reason = REASON_UNKNOWN

        result.parsed_url = process_url(url)
        if not result.parsed_url:
            logging.debug("unable to process url {}".format(url))
            result.reason = REASON_ERROR
            return result

        logging.debug("analyzing scheme {} netloc {} hostname {} path {} params {} query {} fragment {}".format(
                      result.parsed_url.scheme,
                      result.parsed_url.netloc,
                      result.parsed_url.hostname,
                      result.parsed_url.path,
                      result.parsed_url.params,
                      result.parsed_url.query,
                      result.parsed_url.fragment))

        # if the URL is just to an IP address then we crawl that no matter what
        if is_ipv4(result.parsed_url.hostname):
            result.reason = REASON_DIRECT_IPV4
            result.filtered = False
            return result

        if self.is_whitelisted(result.parsed_url.hostname):
            result.reason = REASON_WHITELISTED
            result.filtered = False
            return result

        if result.parsed_url.path:
            if self.matches_path_regex(result.parsed_url.path):
                result.reason = REASON_WHITELISTED
                result.filtered = False
                return result

        if self.is_blacklisted(result.parsed_url.hostname):
            result.reason = REASON_BLACKLISTED
            result.filtered = True
            return result
            
        if self.is_in_crits(result.parsed_url):
            result.reason = REASON_CRITS
            result.filtered = False
            return result

        if not self.is_uncommon_network(result.parsed_url.hostname):
            result.reason = REASON_COMMON_NETWORK
            result.filtered = True
            return result

        result.filtered = False
        result.reason = REASON_OK
        return result
