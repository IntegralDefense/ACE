# vim: sw=4:ts=4:et

import csv
import logging
import os.path
import re

import saq
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.modules.asset import NetworkIdentifierAnalysis
from saq.constants import *

from iptools import IpRange

KEY_CIDR = 'cidr'
KEY_ASN = 'asn'
KEY_ORGANIZATION = 'org'

class ASNAnalysis(Analysis):
    """What organization owns this ip address?  What is the general physical location?"""

    @property
    def cidr(self):
        if not isinstance(self.details, dict) or KEY_CIDR not in self.details:
            return None
        return self.details[KEY_CIDR]

    @property
    def asn(self):
        if not isinstance(self.details, dict) or KEY_ASN not in self.details:
            return None
        return self.details[KEY_ASN]

    @property
    def organization(self):
        if not isinstance(self.details, dict) or KEY_ORGANIZATION not in self.details:
            return None
        return self.details[KEY_ORGANIZATION]

    def generate_summary(self):
        if self.cidr is not None or self.asn is not None or self.organization is not None:
            return "ASN Analysis - Netblock {0} ASN {1} - {2}".format(
                self.cidr, self.asn, self.organization)
        return None

class ASNAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('netmask_to_asn_file')
        self.verify_config_exists('netmask_to_asn_file_encoding')
        self.verify_config_exists('asn_to_owner_file')
        self.verify_config_exists('asn_to_owner_file_encoding')
        self.verify_path_exists(self.config['netmask_to_asn_file'])
        self.verify_path_exists(self.config['asn_to_owner_file'])

    @property
    def generated_analysis_type(self):
        return ASNAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # how we map these things
        # a.b.c.d 
        # self.internet[a] = [ list of cidrs that start with a ]
        # self.internet[a.b] = [ list of cidrs that start with a.b ]
        # self.internet [a.b.c] = [ list of cidrs that start with a.b.c ]
        # 
        # to search, start with a.b.c, then a.b, then a

        # map of the internet
        self.internet = {} # huge dict
        netmask_to_asn_file_path = os.path.join(saq.SAQ_HOME, saq.CONFIG.get(self.config_section, 'netmask_to_asn_file'))
        netmask_to_asn_file_encoding = saq.CONFIG.get(self.config_section, 'netmask_to_asn_file_encoding')
        line_number = 0

        # TODO need to find a way to only do this once
        logging.debug("loading internet BGP routing tables...")
        with open(netmask_to_asn_file_path, 'r', encoding=netmask_to_asn_file_encoding) as cidr_fp:
            while True:
                try:
                    line = next(cidr_fp)
                    line_number += 1
                except StopIteration:
                    break
                except Exception as e:
                    logging.error("unable to load line {0} from {1}: {2}".format(line_number, netmask_to_asn_file_path, str(e)))
                    continue

                line = line.strip()
                m = re.match(r'^(\S+)\s+(\d+)$', line)
                if m is None:
                    logging.error("error parsing line {0} in {1}".format(line, netmask_to_asn_file_path))
                    continue

                (cidr, owner_id) = m.groups()
                m = re.match(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$', cidr)
                if m is None:
                    logging.error("regex failed for cidr {0}".format(cidr))
                    continue

                (a, b, c, d, net) = m.groups()
                for key in [ '{0}'.format(a), '{0}.{1}'.format(a, b), '{0}.{1}.{2}'.format(a, b, c) ]:
                    if key not in self.internet:
                        self.internet[key] = []
                    self.internet[key].append((cidr, owner_id))

        logging.debug("loaded {0} ASN lookup indexes".format(len(self.internet)))
        logging.debug("loading ASN ownership")
        asn_to_owner_file_path = os.path.join(saq.SAQ_HOME, saq.CONFIG.get(self.config_section, 'asn_to_owner_file'))
        asn_to_owner_file_encoding = saq.CONFIG.get(self.config_section, 'asn_to_owner_file_encoding')

        # also cache the owners
        self.owners = {} # key = str(owner_id), value = org_name
        line_number = 0
        with open(asn_to_owner_file_path, 'r', encoding=asn_to_owner_file_encoding) as owner_fp:
            while True:
                try:
                    line = next(owner_fp)
                    line_number += 1
                except StopIteration:
                    break
                except Exception as e:
                    logging.error("unable to parse line {0} data {1} from {2}: {3}".format(line_number, line, saq.CONFIG.get(self.config_section, 'asn_to_owner_file'), str(e)))
                    continue
            #for line in owner_fp:
                line = line.strip()
                m = re.match('^\s*(\d+)\s+(.*)$', line)
                if m is None:
                    logging.error("error parsing line {0} in {1}".format(line, saq.CONFIG.get(self.config_section, 'asn_to_owner_file')))
                    continue

                (assigned_id, owner) = m.groups()
                self.owners[assigned_id] = owner

        logging.debug("loaded {0} ASN ownership indexes".format(len(self.owners)))

    """Looks up ASN routes for an IP address."""
    def execute_analysis(self, ipv4):

        analysis = ASNAnalysis()
        ipv4.add_analysis(analysis)
        analysis.details = None

        logging.debug("scanning ASN routes for {0}".format(ipv4.value))
        
        m = re.match(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$', ipv4.value)
        if m is None:
            logging.error("regex failed for ipvr {0}".format(ipv4.value))
            return

        (a, b, c, d) = m.groups()

        logging.debug("performing ASN lookup for {0}".format(ipv4.value))
        for key in [ '{0}.{1}.{2}'.format(a, b, c), '{0}.{1}'.format(a, b), '{0}'.format(a) ]:
            try:
                for (cidr, owner_id) in self.internet[key]:
                    cidr_object = IpRange(cidr)
                    if ipv4.value in cidr_object:
                        logging.debug("found ASN {0} for ipv4 {1} in network {2}".format(owner_id, ipv4.value, cidr))
                        analysis.details = {
                            KEY_CIDR: cidr,
                            KEY_ASN: owner_id,
                            KEY_ORGANIZATION: self.owners[owner_id]  }
                        return
            except KeyError:
                pass
