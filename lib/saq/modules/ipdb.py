# vim: sw=4:ts=4:et

import csv
import logging
import os.path
import re

import saq
from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import AnalysisModule

from iptools import IpRange

NETWORK_NETWORK = 'network'
NETWORK_NAME = 'network_name'
NETWORK_CIDR = 'network_cidr'
ASSIGNMENT_IPV4 = 'ipv4'
ASSIGNMENT_TYPE = 'type'
ASSIGNMENT_DIVISION = 'division'
ASSIGNMENT_LOCATION = 'location'
ASSIGNMENT_NAME = 'name'
ASSIGNMENT_COMMENT = 'comment'

class IPDBNetwork(object):
    def __init__(self, network, name, cidr):
        self.network = network
        self.name = name
        self.cidr = cidr

    def __str__(self):
        return "IPDB Network {0} ({1})".format(self.name, self.network)

    @property
    def json(self):
        return {
            NETWORK_NETWORK: self.network,
            NETWORK_NAME: self.name,
            NETWORK_CIDR: str(self.cidr) }

class IPDBAssignment(object):
    def __init__(self, network, ipv4, _type, division, location, name, comment):
        self.network = network
        self.ipv4 = ipv4
        self._type = _type
        self.division = division
        self.location = location
        self.name = name
        self.comment = comment

    def __str__(self):
        return "IPDB Assignment {0} ({1})".format(self.ipv4, self.name)

    @property
    def json(self):
        return {
            ASSIGNMENT_IPV4: self.ipv4,
            ASSIGNMENT_TYPE: self._type,
            ASSIGNMENT_DIVISION: self.division,
            ASSIGNMENT_LOCATION: self.location,
            ASSIGNMENT_NAME: self.name,
            ASSIGNMENT_COMMENT: self.comment }

class IPDBAnalysis(Analysis):
    """What does our IPDB say about this ip address?"""

    def verify_environment(self):
        self.verify_config_exists('csv_file')
        self.verify_config_exists('csv_file_encoding')
        self.verify_path_exists(self.config['csv_file'])

    @property
    def csv_file(self):
        path = self.config['csv_file']
        if os.path.isabs(path):
            return path

        return os.path.join(saq.SAQ_HOME, path)

    @property
    def csv_file_encoding(self):
        return self.config['csv_file_encoding']

    @property
    def jinja_template_path(self):
        return "analysis/ipdb_analysis.html"

    def generate_summary(self): 
        if self.details is not None:
            if self.name is not None:
                return "IPDB Analysis ({0} - {1}) {2} {3} {4} {5}".format(
                    self.network_name,
                    self.network,
                    self.type,
                    self.location,
                    self.name,
                    self.comment)
            else:
                return "IPDB Analysis ({0} - {1})".format(
                    self.network,
                    self.network_name)

        return None

    @property
    def network(self):
        if NETWORK_NETWORK in self.details:
            return self.details[NETWORK_NETWORK]
        return None

    @property
    def network_name(self):
        if NETWORK_NAME in self.details:
            return self.details[NETWORK_NAME]
        return None

    @property
    def network_cidr(self):
        if NETWORK_CIDR in self.details:
            return self.details[NETWORK_CIDR]
        return None

    @property
    def ipv4(self):
        if ASSIGNMENT_IPV4 in self.details:
            return self.details[ASSIGNMENT_IPV4]
        return None

    @property
    def type(self):
        if ASSIGNMENT_TYPE in self.details:
            return self.details[ASSIGNMENT_TYPE]
        return None

    @property
    def division(self):
        if ASSIGNMENT_DIVISION in self.details:
            return self.details[ASSIGNMENT_DIVISION]
        return None

    @property
    def location(self):
        if ASSIGNMENT_LOCATION in self.details:
            return self.details[ASSIGNMENT_LOCATION]
        return None

    @property
    def name(self):
        if ASSIGNMENT_NAME in self.details:
            return self.details[ASSIGNMENT_NAME]
        return None

    @property
    def comment(self):
        if ASSIGNMENT_COMMENT in self.details:
            return self.details[ASSIGNMENT_COMMENT]
        return None

class IPDBAnalyzer(AnalysisModule):
    """Look up an IP address in the exported IPDB CSV file."""

    @property
    def generated_analysis_type(self):
        return IPDBAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.networks = [] # list of IPDBNetwork objects
        self.assignments = {} # key = ipv4, value = IPDBAssignment

        # load the ipdb csv
        self.watch_file(self.csv_file, self.load_csv_file)

    @property
    def csv_file(self):
        return self.config['csv_file']

    @property
    def csv_file_encoding(self):
        return self.config['csv_file_encoding']

    def load_csv_file(self):
        line_number = 0
        with open(self.csv_file, 'r', encoding=self.csv_file_encoding) as fp:
            reader = csv.reader(fp)
            header = next(reader) # skip the header
            line_number += 1
            skip_mode = True # state variable, to skip over invalid network specs
            current_network = None
            while True: 
                try:
                    row = next(reader)
                    line_number += 1
                except Exception as e:
                    logging.debug("unable to read line {0} from {1}: {2}".format(line_number, self.csv_file, str(e)))
                    break
                except StopIteration:
                    break

                try:
                
                    # network specifications are two columns
                    if len(row) < 2:
                        continue

                    if len(row) == 2:
                        (count, network) = row
                        if network.strip() == '':
                            continue
                        if network.startswith('000.000.000.000'):
                            skip_mode = True
                            continue
                        else:
                            m = re.match(r'^([0-9]{3}\.[0-9]{3}\.[0-9]{3}\.[0-9]{3})\s+-\s+(.*)$', network)
                            if m is None:
                                #logging.debug("unable to parse network spec out of {0}".format(network))
                                current_network = None
                                continue

                            network = m.group(1)
                            name = m.group(2)

                            # turn the nnn.nnn.nnn.nnn into an actual IP address
                            m = re.match(r'([0-9]{3})\.([0-9]{3})\.([0-9]{3})\.([0-9]{3})$', network)
                            (a,b,c,d) = m.groups()
                            network = '{0}.{1}.{2}'.format(str(int(a)), str(int(b)), str(int(c)))
                            cidr = IpRange('{0}.0/24'.format(network)) # assuming they are all /24 specs
                            current_network = IPDBNetwork(network, name, cidr)
                            self.networks.append(current_network)
                            skip_mode = False
                            #logging.debug("loaded {0}".format(current_network))

                        continue

                    if len(row) != 8:
                        logging.debug("invalid row count {0} for row {1}".format(
                            len(row), ','.join(row)))
                        continue

                    (count, network, host, _type, division, location, name, comment) = row

                    # skipping over assets assigned to 0.0.0.0 network
                    # I assume this is the "these assets are not on the network" flag for networking group
                    if skip_mode:
                        continue

                    if current_network is None:
                        #logging.debug("current_network is not set while parsing {0}".format(','.join(row)))
                        continue

                    try:
                        ipv4 = str(int(host))
                    except Exception as e:
                        #logging.debug("value {0} specified for host column is invalid in {1}: {2}".format(
                            #host, ','.join(row), str(e)))
                        continue

                    ipv4 = '{0}.{1}'.format(current_network.network, ipv4)
                    assignment = IPDBAssignment(current_network, ipv4, _type, division, location, name, comment)
                    #if ipv4 in self.assignments:
                        #logging.warning("duplicate ipv4 assignment for {0}".format(ipv4))

                    self.assignments[ipv4] = assignment
                    #logging.debug("loaded {0}".format(assignment))

                except Exception as e:
                    logging.debug("trouble reading ipbd file: {0}".format(str(e)))
                    continue
        
        logging.debug("loaded {0} ipdb networks and {1} ipdb assignments".format(len(self.networks), len(self.assignments)))

    def execute_analysis(self, ipv4):

        # the result is json of the IPDBAssignment
        analysis = IPDBAnalysis()
        analysis.details = None

        # first check for the ipv4 direct mapping
        try:
            analysis.details = self.assignments[ipv4.value].json
            logging.debug("got ipdb match for {0}: {1}".format(ipv4.value, self.assignments[ipv4.value]))
        except KeyError:
            # try to look for the network assignment instead
            for network in self.networks:
                try:
                    if ipv4.value in network.cidr:
                        analysis.details = network.json
                        logging.debug("got ipdb network match for {0}: {1}".format(ipv4.value, network))
                except TypeError:
                    pass

        ipv4.add_analysis(analysis)

