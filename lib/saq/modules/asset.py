# vim: sw=4:ts=4:et

import logging
import os.path
from subprocess import Popen, PIPE, DEVNULL
import re
import socket
import tempfile
import json
import csv
from datetime import datetime

import saq
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule, LDAPAnalysisModule, CarbonBlackAnalysisModule
from saq.constants import *

import iptools

ANALYSIS_DNS_RESOLVED = 'resolved'
ANALYSIS_DNS_FQDN = 'fqdn'
ANALYSIS_DNS_HOSTNAME = 'hostname'
ANALYSIS_DNS_IPV4 = 'ipv4'

ANALYSIS_NETBIOS_OPEN = 'netbios_open'
ANALYSIS_NETBIOS_NAME = 'netbios_name'
ANALYSIS_NETBIOS_USER = 'netbios_user'
ANALYSIS_NETBIOS_MAC = 'netbios_mac'
ANALYSIS_NETBIOS_DOMAIN = 'netbios_domain'

# some utility functions
valid_ipv4_regex = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
def is_ipv4(value):
    return valid_ipv4_regex.match(value) is not None

valid_hostname_regex = re.compile(r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$')
def is_hostname(value):
    if value == '':
        return False

    if is_ipv4(value):
        return False

    return valid_hostname_regex.match(value) is not None

def is_fqdn(value):
    if not is_ipv4(value) and not is_hostname(value) and '.' in value:
        return True

    return False

class _NetworkDefinition(object):
    def __init__(self, cidr, name):
        self.cidr = cidr
        self.name = name

class NetworkIdentifierAnalysis(Analysis):
    """Is this a managed IP address?  What is the general network location?"""

    def initialize_details(self):
        self.details = []

    @property
    def jinja_template_path(self):
        return "analysis/network_identifier.html"

    @property
    def identified_networks(self):
        """Returns the list of networks identified for this ipv4."""
        return self.details

    @property
    def is_asset(self):
        return len(self.details) > 0

    def generate_summary(self):
        if len(self.identified_networks) > 0:
            return "Network Identification Analysis ({0})".format(', '.join(self.identified_networks))
        return None

class NetworkIdentifier(AnalysisModule):
    """Looks up what network(s) a given IP address belong to."""

    def verify_environment(self):
        self.verify_config_exists('csv_file')
        self.verify_path_exists(self.config['csv_file'])

    @property
    def generated_analysis_type(self):
        return NetworkIdentifierAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4
    
    def __init__(self, *args, **kwargs):
        super(NetworkIdentifier, self).__init__(*args, **kwargs)
        self._networks = [] # list of _NetworkDefinition
        
        # load the network definitions from the CSV file
        with open(os.path.join(saq.SAQ_HOME, saq.CONFIG.get(self.config_section, 'csv_file')), 'r') as fp:
            reader = csv.reader(fp)
            # these are pulled from splunk and these are the header names
            header = next(reader)
            assert header[0] == 'Indicator'
            assert header[1] == 'Indicator_Type'
            for row in reader:
                #logging.debug("loading {0} = {1}".format(row[0], row[1]))
                self._networks.append(_NetworkDefinition(iptools.IpRange(row[0]), row[1]))

        logging.debug("loaded {0} network definitions".format(len(self._networks)))

    def execute_analysis(self, observable):

        # results contain a list of the names of the networks this IP address is in
        analysis = self.create_analysis(observable)

        for network in self._networks:
            try:
                if observable.value in network.cidr:
                    analysis.details.append(network.name)
            except Exception as e:
                logging.error("invalid ipv4 {}: {}".format(observable.value, str(e)))
                continue

        #analysis.details = [x.name for x in self._networks if observable.value in x.cidr]
        observable.add_analysis(analysis)

        # if this ipv4 has at least one identified network then we can assume it's an asset
        if len(analysis.identified_networks) > 0:
            analysis.add_observable(F_ASSET, observable.value)

        return True

# jdavison@NAKYLEXSEC101:~/saq$ sudo nmap -sU --script /usr/share/nmap/scripts/nbstat.nse -p137 149.55.130.115

# Starting Nmap 6.40 ( http://nmap.org ) at 2014-10-03 16:00 EDT
# Nmap scan report for 149.55.130.115
# Host is up (0.011s latency).
# PORT    STATE SERVICE
# 137/udp open  netbios-ns

# Host script results:
# | nbstat:
# |   NetBIOS name: PCN0117337, NetBIOS user: <unknown>, NetBIOS MAC: 28:d2:44:51:01:7b (Lcfc(hefei) Electronics Technology Co.)
# |   Names
# |     PCN0117337<00>       Flags: <unique><active>
# |     ASHLAND<00>          Flags: <group><active>
# |     PCN0117337<20>       Flags: <unique><active>
# |_    ASHLAND<1e>          Flags: <group><active>

# Nmap done: 1 IP address (1 host up) scanned in 1.54 seconds

class NetBIOSAnalysis(Analysis):
    """What are the NetBIOS query results for this asset?"""

    def initialize_details(self):
        self.details = {
            ANALYSIS_NETBIOS_OPEN: False,
            ANALYSIS_NETBIOS_NAME: None,
            ANALYSIS_NETBIOS_USER: None,
            ANALYSIS_NETBIOS_MAC: None,
            ANALYSIS_NETBIOS_DOMAIN: None
        }

    @property
    def netbios_open(self):
        return self.details[ANALYSIS_NETBIOS_OPEN]

    @netbios_open.setter
    def netbios_open(self, value):
        assert isinstance(value, bool)
        self.details[ANALYSIS_NETBIOS_OPEN] = value

    @property
    def netbios_name(self):
        return self.details[ANALYSIS_NETBIOS_NAME]

    @netbios_name.setter
    def netbios_name(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_NAME] = value

    @property
    def netbios_mac(self):
        return self.details[ANALYSIS_NETBIOS_MAC]

    @netbios_mac.setter
    def netbios_mac(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_MAC] = value

    @property
    def netbios_user(self):
        return self.details[ANALYSIS_NETBIOS_USER]

    @netbios_user.setter
    def netbios_user(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_USER] = value

    @property
    def netbios_domain(self):
        return self.details[ANALYSIS_NETBIOS_DOMAIN]

    @netbios_domain.setter
    def netbios_domain(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_DOMAIN] = value

    def generate_summary(self):
        if self.netbios_open:
            return 'NetBIOS Analysis: Name {0} Domain {1} User {2} MAC {3}'.format(
                self.netbios_name if self.netbios_name is not None else '?', 
                self.netbios_domain if self.netbios_domain is not None else '?', 
                self.netbios_user if self.netbios_user is not None else '?', 
                self.netbios_mac if self.netbios_mac is not None else '?')

        return None

class NetBIOSAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_program_exists('nmap')
        self.verify_path_exists('/usr/share/nmap/scripts/nbstat.nse')

    @property
    def generated_analysis_type(self):
        return NetBIOSAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET

    def execute_analysis(self, asset):

        logging.debug("performing netbios query against {}".format(asset))
        
        analysis = self.create_analysis(asset)

        args = [
            'sudo', '/usr/bin/nmap', 
            '-sU', 
            '--script', '/usr/share/nmap/scripts/nbstat.nse', 
            '-p137', asset.value]

        # are we executing this from a host in a target network?
        if self.config['ssh_host']:
            args.insert(0, self.config['ssh_host'])
            args.insert(0, 'ssh')

        with tempfile.TemporaryFile(dir=os.path.join(saq.SAQ_HOME, saq.CONFIG.get('global', 'tmp_dir'))) as fp:
            p = Popen(args, stdout=fp)
            p.wait()

            fp.seek(0)

            for line in fp:
                if re.match(r'^137/udp\s+open\s+netbios-ns$', line.decode(saq.DEFAULT_ENCODING)):
                    logging.debug("{} responded to a netbios query".format(asset))
                    analysis.netbios_open = True
                    continue

                if not analysis.netbios_open:
                    continue

                m = re.search(r'NetBIOS name: ([^,]+), NetBIOS user: ([^,]+), NetBIOS MAC: (..:..:..:..:..:..)', line.decode(saq.DEFAULT_ENCODING))
                if m:
                    (name, user, mac) = m.groups()
                    analysis.netbios_name = name
                    analysis.netbios_user = user
                    analysis.netbios_mac = mac
                    
                    logging.debug("found netbios_name {0} netbios_user {1} netbios_mac {2} for asset {3}".format(
                        name, user, mac, asset))
                    continue

                m = re.search(r'\s([^<\s]+)<00>\s+Flags:\s+<group><active>', line.decode(saq.DEFAULT_ENCODING))
                if m:
                    (domain,) = m.groups()
                    analysis.netbios_domain = domain
                    logging.debug("found netbios_domain {0} for asset {1}".format(domain, asset))
                    continue

        asset.add_analysis(analysis)

        if analysis.netbios_open:
            if analysis.netbios_name is not None and analysis.netbios_name != '<unknown>':
                analysis.add_observable(F_HOSTNAME, analysis.netbios_name)

            if analysis.netbios_user is not None and analysis.netbios_user != '<unknown>':
                analysis.add_observable(F_USER, analysis.netbios_user)

        return True

#(env)jdavison@NAKYLEXSEC101:~/saq$ dig -x 162.128.155.20

#; <<>> DiG 9.9.5-3-Ubuntu <<>> -x 162.128.155.20
#;; global options: +cmd
#;; Got answer:
#;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15793
#;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

#;; OPT PSEUDOSECTION:
#; EDNS: version: 0, flags:; udp: 4000
#;; QUESTION SECTION:
#;20.155.128.162.in-addr.arpa.   IN      PTR

#;; ANSWER SECTION:
#20.155.128.162.in-addr.arpa. 1200 IN    PTR     nakylexadc106.ashland.ad.ai.

#;; Query time: 0 msec
#;; SERVER: 162.128.155.16#53(162.128.155.16)
#;; WHEN: Mon Oct 06 13:59:43 EDT 2014
#;; MSG SIZE  rcvd: 97

class DNSAnalysis(Analysis):
    """What is the DNS resolution of this asset?"""

    def initialize_details(self):
        self.details = {
            ANALYSIS_DNS_RESOLVED: False,
            ANALYSIS_DNS_HOSTNAME: None,
            ANALYSIS_DNS_FQDN: None,
            ANALYSIS_DNS_IPV4: []
        }

    @property
    def dns_resolved(self):
        return self.details_property(ANALYSIS_DNS_RESOLVED)

    @dns_resolved.setter
    def dns_resolved(self, value):
        assert isinstance(value, bool)
        self.details[ANALYSIS_DNS_RESOLVED] = value

    @property
    def dns_hostname(self):
        return self.details_property(ANALYSIS_DNS_HOSTNAME)

    @dns_hostname.setter
    def dns_hostname(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_DNS_HOSTNAME] = value

    @property
    def dns_fqdn(self):
        return self.details_property(ANALYSIS_DNS_FQDN)

    @dns_fqdn.setter
    def dns_fqdn(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_DNS_FQDN] = value

    @property
    def dns_ipv4(self):
        return self.details_property(ANALYSIS_DNS_IPV4)

    def generate_summary(self):
        if self.dns_resolved:
            return "DNS Analysis (hostname: {0} fqdn {1} ipv4 {2})".format(
                self.dns_hostname,
                self.dns_fqdn,
                self.dns_ipv4)

        return None

class DNSAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('local_domains')
        self.verify_program_exists('dig')
    
    @property
    def generated_analysis_type(self):
        return DNSAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET, F_FQDN, F_HOSTNAME

    def execute_analysis(self, observable):
        # TODO turn this into a common global function
        # we only want to resolve for local networks
        # at least for now... TODO XXX NOTE
        if observable.type == F_FQDN:
            is_local_domain = False
            if '.' in observable.value:
                domain = '.'.join(observable.value.split('.')[1:])
                if domain.startswith('.'):
                    domain = domain[1:]
                    if domain in [x.lower() for x in saq.CONFIG.get(self.config_section, 'local_domains').split(',')]:
                        logging.debug("{} identified as local domain".format(observable))
                        is_local_domain = True
            else:
                is_local_domain = True

            if not is_local_domain:
                logging.debug("not doing DNS resolution on non-local domain {}".format(observable))
                return False

        analysis = self.create_analysis(observable)

        logging.debug("performing DNS query for {}".format(observable))

        dig_process = ['dig']
        if observable.type == F_ASSET:
            dig_process.append('-x')
        else:
            dig_process.append('+search')
        dig_process.append(observable.value)

        # are we executing this from a host in a target network?
        if self.config['ssh_host']:
            dig_process.insert(0, self.config['ssh_host'])
            dig_process.insert(0, 'ssh')

        p = Popen(dig_process, stdout=PIPE, stderr=DEVNULL)
        try:
            answer_section = False # state flag
            for line in p.stdout:
                #logging.debug(line)
                if ';; ANSWER SECTION' in line.decode():
                    answer_section = True
                    continue

                if not answer_section:
                    continue

                m = re.match(r'^\S+\s+[0-9]+\s+IN\s+PTR\s+(\S+)$', line.decode(saq.DEFAULT_ENCODING))
                if m:
                    (fqdn,) = m.groups()
                    analysis.dns_resolved = True
                    analysis.dns_ipv4.append(observable.value)
                    if '.' in fqdn:
                        analysis.dns_hostname = fqdn.split('.')[0]
                    analysis.dns_fqdn = fqdn
                    continue

                # PCN0117337.ashland.ad.ai. 1200  IN      A       149.55.130.115
                m = re.match(r'^\S+\s+[0-9]+\s+IN\s+A\s+(\S+)$', line.decode())
                if m:
                    (ipv4,) = m.groups()
                    if ipv4 is not None:
                        logging.debug("hostname {} resolved to {}".format(observable.value, ipv4))
                        analysis.add_observable(F_IPV4, ipv4)
                        analysis.dns_resolved = True
                        if is_hostname(observable.value):
                            analysis.dns_hostname = observable.value
                        else:
                            analysis.dns_fqdn = observable.value

                        analysis.dns_ipv4.append(ipv4)
                    continue
        finally:
            p.wait()

        if not analysis.dns_resolved:
            logging.debug("reverse dns lookup failed for asset {}".format(observable))
        else:
            logging.debug("found fqdn {} hostname {} for asset {}".format(
                analysis.dns_fqdn, analysis.dns_hostname, observable))

        return True

class ActiveDirectoryAnalysis(Analysis):
    """What does Active Directory know about this asset?"""

    def initialize_details(self):
        self.details = None # free form from result

    @property
    def is_asset(self):
        return self.details is not None

    @property
    def fqdn(self):
        if 'dNSHostName' in self.details and len(self.details['dNSHostName']) > 0:
            return self.details['dNSHostName']
        return None

    # XXX pretty sure this is specific to Ashland
    @property
    def owner(self):
        if 'description' in self.details and len(self.details['description']) > 0:
            m = re.match(r'^(\S+) - (.+)$', self.details['description'][0])
            if m:
                (account, name) = m.groups()
                return (account, name)

        return None

    @property
    def operating_system(self):
        result = []
        if ('operatingSystem' in self.details
            and len(self.details['operatingSystem']) > 0):
            result.append(self.details['operatingSystem'])
        if ('operatingSystemServicePack' in self.details
            and len(self.details['operatingSystemServicePack']) > 0):
            result.append(self.details['operatingSystemServicePack'])
        if ('operatingSystemVersion' in self.details
            and len(self.details['operatingSystemVersion']) > 0):
            result.append(self.details['operatingSystemVersion'])
        
        if len(result) > 0:
            return ' '.join(result)
    
        return None

    def generate_summary(self):
        if self.details is None:
            return None

        result = 'Active Directory Analysis'

        if self.fqdn is not None:
            result += ' ({0})'.format(self.fqdn)

        # example: 'description': ['A346348 - Timothy Anderson'],
        if self.owner is not None:
            user, _ = self.owner
            user = user.strip()
            if user is not None and user != '-' and user != '':
                result += ' ({0})'.format(user)

        return result

class ActiveDirectoryAnalyzer(LDAPAnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return ActiveDirectoryAnalysis

    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    def execute_analysis(self, hostname):

        details = self.ldap_query_hostname(hostname.value)
        if details is None:
            logging.debug("no result received from ldap query for {}".format(hostname.value))
            return False

        analysis = self.create_analysis(hostname)
        analysis.details = details

        if analysis.fqdn is not None:
            analysis.add_observable(F_FQDN, analysis.fqdn)

        # example: 'description': ['A346348 - Timothy Anderson'],
        if analysis.owner is not None:
            user, _ = analysis.owner
            user = user.strip()
            if user is not None and user != '-' and user != '':
                analysis.add_observable(F_USER, user)

        return True

    def ldap_query_hostname(self, hostname):
        return self.ldap_query("cn={}".format(hostname))

class CarbonBlackAssetIdentAnalysis(Analysis):
    """What hosts have this IP address according to Carbon Black?"""

    KEY_SEARCH_RESULTS = 'search_results'
    KEY_DISCOVERED_HOSTNAMES = 'discovered_hostnames'

    def initialize_details(self):
        self.details = { 
            CarbonBlackAssetIdentAnalysis.KEY_SEARCH_RESULTS: [],
            CarbonBlackAssetIdentAnalysis.KEY_DISCOVERED_HOSTNAMES: [],
        }

    @property
    def search_results(self):
        return self.details_property(CarbonBlackAssetIdentAnalysis.KEY_SEARCH_RESULTS)

    @search_results.setter
    def search_results(self, value):
        self.details[CarbonBlackAssetIdentAnalysis.KEY_SEARCH_RESULTS] = value

    @property
    def discovered_hostnames(self):
        return self.details_property(CarbonBlackAssetIdentAnalysis.KEY_DISCOVERED_HOSTNAMES)

    @discovered_hostnames.setter
    def discovered_hostnames(self, value):
        self.details[CarbonBlackAssetIdentAnalysis.KEY_DISCOVERED_HOSTNAMES] = value

    def generate_summary(self):
        if not self.details:
            return None

        result = 'Carbon Black Asset Identification'

        if not self.discovered_hostnames:
            result = '{}: no hosts with this IP address'.format(result)
        else:
            result = '{}: {} host(s) with this IP address'.format(result, len(self.discovered_hostnames))

        return result

class CarbonBlackAssetIdentAnalyzer(CarbonBlackAnalysisModule):
    @property
    def generated_analysis_type(self):
        return CarbonBlackAssetIdentAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    @property
    def hostname_limit(self):
        """Maximum number of hostnames to add as observables in the case of multiple matches."""
        return self.config.getint('hostname_limit')

    def execute_analysis(self, ipv4):

        analysis = self.create_analysis(ipv4)

        from cbapi.response.models import Sensor

        query = self.cb.select(Sensor)
        query = query.where('ip:{}'.format(ipv4.value))
        for sensor in query:
            analysis.search_results.append(str(sensor))
            if sensor.hostname not in analysis.discovered_hostnames:
                analysis.discovered_hostnames.append(sensor.hostname)
            logging.info("found hostname {} for {}".format(sensor.hostname, ipv4.value))

        for hostname in analysis.discovered_hostnames[:self.hostname_limit]:
            hostname = analysis.add_observable(F_HOSTNAME, hostname)

        return True

# DEPRECATED
class ProxyAnalysis(Analysis):
    @property
    def jinja_template_path(self):
        return "analysis/bluecoat_proxy_requests.html"

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "Proxy Requests By Source ({0} events)".format(len(self.details))

        return None

_ASSET_HOSTNAME = 'hostname'
_ASSET_DOMAIN = 'domain'
_ASSET_MAC = 'mac'
_ASSET_FQDN = 'fqdn'
_ASSET_OWNER = 'owner'
_ASSET_OS = 'os'

class AssetAnalysis(Analysis):
    """What is the summary of all the analysis we've been able to do on this asset?"""

    def initialize_details(self):
        self.details = {
            _ASSET_HOSTNAME: None,
            _ASSET_DOMAIN: None,
            _ASSET_MAC: None,
            _ASSET_FQDN: None,
            _ASSET_OWNER: None,
            _ASSET_OS: None
        }
            
    @property
    def hostname(self):
        """Returns the (short) name of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_HOSTNAME]

    @hostname.setter
    def hostname(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_HOSTNAME] = value

    @property
    def domain(self):
        """Returns the (short) domain of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_DOMAIN]

    @domain.setter
    def domain(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_DOMAIN] = value

    @property
    def mac(self):
        """Returns the MAC address of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_MAC]

    @mac.setter
    def mac(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_MAC] = value

    @property
    def fqdn(self):
        """Returns the FQDN of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_FQDN]

    @fqdn.setter
    def fqdn(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_FQDN] = value

    @property
    def owner(self):
        """Returns the owner of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_OWNER]

    @owner.setter
    def owner(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_OWNER] = value

    @property
    def os(self):
        """Returns the operating system of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_OS]

    @os.setter
    def os(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_OS] = value
            
    @property
    def jinja_template_path(self):
        return "analysis/asset_analysis.html"

    def generate_summary(self):
        return 'Asset Analysis Summary - host: {0} domain {1} MAC {2} fqdn {3} owner {4} os {5}'.format(
            self.hostname,
            self.domain,
            self.mac,
            self.fqdn,
            self.owner,
            self.os)

class AssetAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return AssetAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET

    def get_hostname(self, asset):
        assert isinstance(asset, Observable)

        # check DNS resolution
        dns_analysis = asset.get_analysis(DNSAnalysis)
        if dns_analysis is not None and dns_analysis.dns_hostname is not None:
            return dns_analysis.dns_hostname

        # check NetBIOS query
        netbios_analysis = asset.get_analysis(NetBIOSAnalysis)
        if netbios_analysis is not None and netbios_analysis.netbios_name is not None:
            return netbios_analysis.netbios_name

        return None

    def get_domain(self, asset):
        assert isinstance(asset, Observable)

        # check NetBIOS query
        netbios_analysis = asset.get_analysis(NetBIOSAnalysis)
        if netbios_analysis is not None and netbios_analysis.netbios_domain is not None:
            return netbios_analysis.netbios_domain

        return None

    def get_mac(self, asset):
        assert isinstance(asset, Observable)

        # check NetBIOS query
        netbios_analysis = asset.get_analysis(NetBIOSAnalysis)
        if netbios_analysis is not None and netbios_analysis.netbios_mac is not None:
            return netbios_analysis.netbios_mac

        return None

    def get_fqdn(self, asset):
        assert isinstance(asset, Observable)

        # check DNS resolution
        dns_analysis = asset.get_analysis(DNSAnalysis)
        if dns_analysis is not None and dns_analysis.dns_fqdn is not None:
            return dns_analysis.dns_fqdn

        # check Active Directory
        ad_analysis = asset.get_analysis(ActiveDirectoryAnalysis)
        if ad_analysis is not None and ad_analysis.fqdn is not None:
            return ad_analysis.fqdn

        return None

    def get_owner(self, asset):
        assert isinstance(asset, Observable)

        # check Active Directory
        ad_analysis = asset.get_analysis(ActiveDirectoryAnalysis)
        if ad_analysis is not None and ad_analysis.owner is not None:
            #logging.debug("owner = {0}".format(ad_analysis.owner))
            return ad_analysis.owner[0] # XXX this is kind of a hack

        return None

    def get_os(self, asset):
        assert isinstance(asset, Observable)

        # check Active Directory
        ad_analysis = asset.get_analysis(ActiveDirectoryAnalysis)
        if ad_analysis is not None and ad_analysis.operating_system is not None:
            return ad_analysis.operating_system

        # TODO check qualys

        return None

    def execute_analysis(self, asset):

        if self.engine.is_module_enabled(DNSAnalysis):
            dns_analysis = self.wait_for_analysis(asset, DNSAnalysis)
        if self.engine.is_module_enabled(NetBIOSAnalysis):
            netbios_analysis = self.wait_for_analysis(asset, NetBIOSAnalysis)
        if self.engine.is_module_enabled(ActiveDirectoryAnalysis):
            active_directory_analysis = self.wait_for_analysis(asset, ActiveDirectoryAnalysis)

        analysis = self.create_analysis(asset)

        # figure out these properties
        analysis.hostname = self.get_hostname(asset)
        analysis.daomin = self.get_domain(asset)
        analysis.mac = self.get_mac(asset)
        analysis.fqdn = self.get_fqdn(asset)
        analysis.owner = self.get_owner(asset)
        analysis.os = self.get_os(asset)

        return True
