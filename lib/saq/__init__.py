# vim: sw=4:ts=4:et

import datetime
import locale
import logging
import logging.config
import os
import os.path
import shutil
import socket
import sys
import time
import traceback

from configparser import ConfigParser
from getpass import getpass

import ace_api
from saq.constants import *
from saq.messaging import initialize_message_system
from saq.network_semaphore import initialize_fallback_semaphores
from saq.remediation import initialize_remediation_system_manager
from saq.sla import SLA
from saq.util import create_directory

import pytz
import requests
import tzlocal

# this is set to True when unit testing, False otherwise
UNIT_TESTING = False

# disable the verbose logging in the requests module
logging.getLogger("requests").setLevel(logging.WARNING)

# local timezone
LOCAL_TIMEZONE = pytz.timezone(tzlocal.get_localzone().zone)

# the global sqlalchemy.orm.scoped_session object
# this object is used to get Session objects by ACE throughout the application
# except for the WSGI app which uses Flask
db = None # (see saq.database.initialize_database)

# the global message system, used to send external messages async
MESSAGE_SYSTEM = None

class CustomFileHandler(logging.StreamHandler):
    def __init__(self, log_dir=None, filename_format=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream = None

        # the directory to store the log files in
        self.log_dir = log_dir
        if self.log_dir is None:
            self.log_dir = '.'

        # the format to use to generate the filename
        self.filename_format = filename_format
        if self.filename_format is None:
            self.filename_format = '%Y-%m-%d-%H.log'

        # the current file name we're using
        self.current_filename = None
        self._update_stream()

    def _update_stream(self):
        # what should the file name be right now?
        current_filename = datetime.datetime.now().strftime(self.filename_format)

        # did the name change?
        if self.current_filename != current_filename:
            # close the current stream
            if self.stream:
                self.stream.close()
            
            # and open a new one
            self.stream = open(os.path.join(self.log_dir, current_filename), 'a')
            self.current_filename = current_filename

    def emit(self, record):
        self.acquire()
        try:
            self._update_stream()
            super().emit(record)
        finally:
            self.release()

# base configuration for logging
LOGGING_BASE_CONFIG = {
    'version': 1,
    'formatters': {
        'base': {
            'format': 
                '[%(asctime)s] [%(pathname)s:%(funcName)s:%(lineno)d] [%(threadName)s] [%(process)d] [%(levelname)s] - %(message)s',
        },
    },
}

def load_configuration():

    global CONFIG

    try:
        default_config = ConfigParser(allow_no_value=True)
        default_config.read(os.path.join(SAQ_HOME, 'etc', 'saq.default.ini'))

        for config_path in CONFIG_PATHS:
            override = ConfigParser(allow_no_value=True)
            #print("loading {}".format(config_path))
            override.read(config_path)

            # clobber defaults
            for section_name in override:
                if section_name in default_config:
                    for value_name in override[section_name]:
                        default_config[section_name][value_name] = override[section_name][value_name]
                else:
                    default_config[section_name] = override[section_name]

        # make sure all OVERRIDE settings are actually overridden
        errors = {}
        for section_name in default_config:
            for value_name in default_config[section_name]:
                if default_config[section_name][value_name] == 'OVERRIDE':
                    if section_name not in errors:
                        errors[section_name] = []
                    errors[section_name].append(value_name)

        if errors:
            for section_name in errors.keys():
                sys.stderr.write("[{}]\n".format(section_name))
                for value_name in errors[section_name]:
                    sys.stderr.write("{} = \n".format(value_name))
                sys.stderr.write("\n")
                
            sys.stderr.write("missing overrides detection in configuration settings\n")
            sys.stderr.write("you can copy-paste the above into your config file if you do not need these settings\n\n")
            sys.exit(1)

        CONFIG = default_config

    except Exception as e:
        logging.error("unable to load configuration: {}".format(e))
        traceback.print_exc()

def initialize_logging(logging_config_path):
    try:
        logging.config.fileConfig(logging_config_path, disable_existing_loggers=False)
    except Exception as e:
        sys.stderr.write("unable to load logging configuration: {}".format(e))
        raise e

    # log all SQL commands if we are running in debug mode
    if CONFIG['global'].getboolean('log_sql'):
        logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.dialects').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.pool').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.orm').setLevel(logging.DEBUG)

def set_node(name):
    """Sets the value for saq.SAQ_NODE. Typically this is auto-set using the local fqdn."""
    from saq.database import initialize_node
    global SAQ_NODE
    global SAQ_NODE_ID
    
    if name != SAQ_NODE:
        SAQ_NODE = name
        SAQ_NODE_ID = None
        initialize_node()

def initialize(saq_home=None, 
               config_paths=None, 
               logging_config_path=None, 
               args=None, 
               relative_dir=None, 
               unittest=False):

    from saq.database import initialize_database, initialize_node

    global API_PREFIX
    global CA_CHAIN_PATH
    global COMPANY_ID
    global COMPANY_NAME
    global CONFIG
    global CONFIG_PATHS
    global DAEMON_MODE
    global DATA_DIR
    global DEFAULT_ENCODING
    global DUMP_TRACEBACKS
    global ENCRYPTION_PASSWORD
    global EXCLUDED_SLA_ALERT_TYPES
    global EXECUTION_THREAD_LONG_TIMEOUT
    global FORCED_ALERTS
    global GLOBAL_SLA_SETTINGS
    global GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES
    global INSTANCE_TYPE
    global LOCK_TIMEOUT_SECONDS
    global LOG_DIRECTORY
    global LOG_LEVEL
    global MANAGED_NETWORKS
    global MODULE_STATS_DIR
    global OTHER_PROXIES 
    global OTHER_SLA_SETTINGS
    global PROXIES
    global SAQ_HOME
    global SAQ_NODE
    global SAQ_NODE_ID
    global SAQ_RELATIVE_DIR
    global SEMAPHORES_ENABLED
    global STATS_DIR
    global TEMP_DIR
    global TOR_PROXY
    global YSS_BASE_DIR
    global YSS_SOCKET_DIR

    SAQ_HOME = None
    SAQ_NODE = None
    SAQ_NODE_ID = None
    API_PREFIX = None
    SAQ_RELATIVE_DIR = None
    CONFIG = None
    CONFIG_PATHS = []
    DATA_DIR = None
    TEMP_DIR = None
    DEFAULT_ENCODING = None
    SEMAPHORES_ENABLED = False
    PROXIES = {}
    OTHER_PROXIES = {}
    TOR_PROXY = None
    # list of iptools.IpRange objects defined in [network_configuration]
    MANAGED_NETWORKS = None
    # set this to True to force all anlaysis to result in an alert being generated
    FORCED_ALERTS = False
    # the gpg private key password for encrypting/decrypting archive files
    # this can be provided on the command line so that these files can also be analyzed
    ENCRYPTION_PASSWORD = None

    # the global log level setting
    LOG_LEVEL = logging.INFO
    # global logging directory (relative to DATA_DIR)
    LOG_DIRECTORY = None

    # directory containing statistical runtime info
    STATS_DIR = None 
    MODULE_STATS_DIR = None

    # are we running as a daemon in the background?
    DAEMON_MODE = False

    # path to the certifcate chain used by all SSL certs
    CA_CHAIN_PATH = None

    # what type of instance is this?
    INSTANCE_TYPE = INSTANCE_TYPE_PRODUCTION

    # SLA settings
    GLOBAL_SLA_SETTINGS = None
    OTHER_SLA_SETTINGS = []
    EXCLUDED_SLA_ALERT_TYPES = []

    # Yara Scanner Server base directory
    YSS_BASE_DIR = None
    YSS_SOCKET_DIR = None

    # set to True to cause tracebacks to be dumped to standard output
    # useful when debugging or testing
    DUMP_TRACEBACKS = False

    # the amount of time (in seconds) that a lock in the locks table is valid
    LOCK_TIMEOUT_SECONDS = None

    # amount of time (in seconds) before a process blows up because a threaded module won't stop
    EXECUTION_THREAD_LONG_TIMEOUT = None

    # the company/custom this node belongs to
    COMPANY_NAME = None
    COMPANY_ID = None

    # go ahead and try to figure out what text encoding we're using
    DEFAULT_ENCODING = locale.getpreferredencoding()

    # list of observable types we want to exclude from whitelisting (via the GUI)
    GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES = []

    # do we want to force alerts?
    if args:
        FORCED_ALERTS = args.force_alerts

    # what is the root directory of the entire system?
    if saq_home is not None:
        SAQ_HOME = saq_home
    elif 'SAQ_HOME' in os.environ:
        SAQ_HOME = os.environ['SAQ_HOME']
    else:
        SAQ_HOME = '.'

    if not os.path.isdir(SAQ_HOME):
        sys.stderr.write("invalid root SAQ directory {0}\n".format(SAQ_HOME)) 
        sys.exit(1)

    # XXX not sure we need this SAQ_RELATIVE_DIR anymore -- check it out
    # this system was originally designed to run out of /opt/saq
    # later we modified to run out of anywhere for command line correlation
    # when running the GUI in apache you have no control over the current working directory
    # so we specify what directory we'd *want* to be running out of here (even if we're not actually)
    # this only matters when loading alerts
    # this defaults to the current working directory
    SAQ_RELATIVE_DIR = os.path.relpath(os.getcwd(), start=SAQ_HOME)
    if relative_dir:
        SAQ_RELATIVE_DIR = relative_dir

    # load configuration file
    # defaults to $SAQ_HOME/etc/saq.ini
    if args:
        if args.config_paths:
            config_paths = args.config_paths

    if config_paths is None:
        config_paths = []
    
    # make each relative config path absolute to SAQ_HOME
    CONFIG_PATHS = [os.path.join(SAQ_HOME, p) if not os.path.isabs(p) else p for p in config_paths]

    # add any config files specified in SAQ_CONFIG_PATHS env var (command separated)
    #sys.stderr.write("SAQ_CONFIG_PATHS = {}\n".format(os.environ['SAQ_CONFIG_PATHS']))
    if 'SAQ_CONFIG_PATHS' in os.environ:
        for config_path in os.environ['SAQ_CONFIG_PATHS'].split(','):
            config_path = config_path.strip()
            if not os.path.isabs(config_path):
                config_path = os.path.join(SAQ_HOME, config_path)
            if not os.path.exists(config_path):
                sys.stderr.write("WARNING: config path {} specified in SAQ_CONFIG_PATHS env var does not exist\n".format(config_path))
            else:
                if config_path not in CONFIG_PATHS:
                    CONFIG_PATHS.append(config_path)

    # if $SAQ_HOME/etc/saq.ini exists then we use that as the last config if it's not already specified
    default_config_path = os.path.join(SAQ_HOME, 'etc', 'saq.ini')

    # use unit test config if we are running a unit test
    if unittest:
        default_config_path = os.path.join(SAQ_HOME, 'etc', 'saq.unittest.ini')

    if os.path.exists(default_config_path):
        if default_config_path not in CONFIG_PATHS:
            CONFIG_PATHS.append(default_config_path)

    try:
        load_configuration()
    except Exception as e:
        sys.stderr.write("ERROR: unable to load configuration: {0}".format(str(e)))
        sys.exit(1)

    DATA_DIR = os.path.join(SAQ_HOME, CONFIG['global']['data_dir'])
    TEMP_DIR = os.path.join(DATA_DIR, CONFIG['global']['tmp_dir'])
    COMPANY_NAME = CONFIG['global']['company_name']
    COMPANY_ID = CONFIG['global'].getint('company_id')

    minutes, seconds = map(int, CONFIG['global']['lock_timeout'].split(':'))
    LOCK_TIMEOUT_SECONDS = (minutes * 60) + seconds
    EXECUTION_THREAD_LONG_TIMEOUT = CONFIG['global'].getint('execution_thread_long_timeout')

    # user specified log level
    LOG_LEVEL = logging.INFO
    if args:
        if args.log_level:
            LOG_LEVEL = args.log_level

    # make sure the logs directory exists
    LOG_DIRECTORY = os.path.join(DATA_DIR, 'logs')
    if not os.path.exists(LOG_DIRECTORY):
        try:
            os.mkdir(LOG_DIRECTORY)
        except Exception as e:
            sys.stderr.write("unable to mkdir {}: {}\n".format(LOG_DIRECTORY, e))
            sys.exit(1)

    # by default we log to the console
    if logging_config_path is None:
        logging_config_path = os.path.join(SAQ_HOME, 'etc', 'console_logging.ini')

    # we can override this on the command line
    # this is what we use for production engine settings
    if args:
        if args.logging_config_path:
            logging_config_path = args.logging_config_path
    
    # we can re-initialize later if we have to
    try:
        initialize_logging(logging_config_path) # this log file just gets some startup information
    except Exception as e:
        sys.exit(1)

    GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES = [_.strip() for _ in 
                                               CONFIG['gui']['whitelist_excluded_observable_types'].split(',')]

    for o_type in GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES:
        if o_type not in VALID_OBSERVABLE_TYPES:
            logging.error(f"invalid observable type {o_type} specified in [gui] whitelist_excluded_observable_types")

    # make this a faster lookup
    GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES = set(GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES)

    # load global SLA settings
    GLOBAL_SLA_SETTINGS = SLA(None, 
                              CONFIG['SLA'].getboolean('enabled'),
                              CONFIG['SLA'].getint('time_to_dispo'),
                              CONFIG['SLA'].getint('approaching_warn'),
                              None, None)

    EXCLUDED_SLA_ALERT_TYPES = [x.strip() for x in CONFIG['SLA']['excluded_alert_types'].split(',')]

    # load all the other SLA settings
    for section in [s for s in CONFIG.keys() if s.startswith('SLA_')]:
        logging.debug("loading {}".format(section))
        OTHER_SLA_SETTINGS.append(SLA(section[len('SLA_'):],
                                      CONFIG[section].getboolean('enabled'),
                                      CONFIG[section].getint('time_to_dispo'),
                                      CONFIG[section].getint('approaching_warn'),
                                      CONFIG[section]['property'],
                                      CONFIG[section]['value']))

    # what node is this?
    try:
        SAQ_NODE = CONFIG['global']['node']
        if SAQ_NODE == 'AUTO':
            SAQ_NODE = socket.getfqdn()
    except Exception as e:
        sys.stderr.write("unable to get hostname: {}\n".format(e))
        sys.exit(1)

    # what prefix do other systems use to communicate to the API server for this node?
    try:
        API_PREFIX = CONFIG['api']['prefix']
        if API_PREFIX == 'AUTO':
            API_PREFIX = socket.getfqdn()
        logging.debug("node {} has api prefix {}".format(SAQ_NODE, API_PREFIX))
    except Exception as e:
        sys.stderr.write("unable to get hostname: {}\n".format(e))
        sys.exit(1)

    # what type of instance is this?
    if 'instance_type' in CONFIG['global']:
        INSTANCE_TYPE = CONFIG['global']['instance_type']
        if INSTANCE_TYPE not in [ INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_QA, INSTANCE_TYPE_DEV ]:
            logging.warning("invalid instance type {}: defaulting to {}".format(INSTANCE_TYPE, INSTANCE_TYPE_PRODUCTION))
            INSTANCE_TYPE = INSTANCE_TYPE_PRODUCTION
    else:
        logging.warning("missing configuration instance_type in global section (defaulting to instance type {})".format(INSTANCE_TYPE_PRODUCTION))

    if FORCED_ALERTS: # lol
        logging.warning(" ****************************************************************** ")
        logging.warning(" ****************************************************************** ")
        logging.warning(" **** WARNING **** ALL ANALYSIS RESULTS IN ALERTS **** WARNING **** ")
        logging.warning(" ****************************************************************** ")
        logging.warning(" ****************************************************************** ")

    # warn if timezone is not UTC
    #if time.strftime("%z") != "+0000":
        #logging.warning("Timezone is not UTC. All ACE systems in a cluster should be in UTC.")

    # we can globally disable semaphores with this flag
    SEMAPHORES_ENABLED = CONFIG.getboolean('global', 'enable_semaphores')

    # some settings can be set to PROMPT
    for section in CONFIG.sections():
        for (name, value) in CONFIG.items(section):
            if value == 'PROMPT':
                CONFIG.set(section, name, getpass("Enter the value for {0}:{1}: ".format(section, name)))

    # make sure we've got the ca chain for SSL certs
    CA_CHAIN_PATH = os.path.join(SAQ_HOME, CONFIG['SSL']['ca_chain_path'])
    ace_api.set_default_ssl_ca_path(CA_CHAIN_PATH)

    # XXX this should probably move to the yara scanning module
    # set the location we'll be running yss out of
    YSS_BASE_DIR = os.path.join(SAQ_HOME, CONFIG['yara']['yss_base_dir'])
    if not os.path.exists(YSS_BASE_DIR):
        logging.critical("[yara][yss_base_dir] is set to {} but does not exist".format(YSS_BASE_DIR))

    YSS_SOCKET_DIR = os.path.join(YSS_BASE_DIR, CONFIG['yara']['yss_socket_dir'])

    # initialize the database connection
    initialize_database()

    # initialize fallback semaphores
    initialize_fallback_semaphores()

    # XXX get rid of this
    try:
        maliciousdir = CONFIG.get("global", "malicious")
    except:
        maliciousdir = "malicious"

    STATS_DIR = os.path.join(DATA_DIR, 'stats')
    MODULE_STATS_DIR = os.path.join(STATS_DIR, 'modules')

    # make sure some key directories exists
    for dir_path in [ 
        # anaysis data
        os.path.join(DATA_DIR, CONFIG['global']['node']),
        #os.path.join(SAQ_HOME, 'var', 'locks'), # XXX remove
        os.path.join(DATA_DIR, 'review', 'rfc822'),
        os.path.join(DATA_DIR, 'review', 'misc'),
        os.path.join(DATA_DIR, CONFIG['global']['error_reporting_dir']),
        STATS_DIR,
        MODULE_STATS_DIR,
        os.path.join(STATS_DIR, 'brocess'), # get rid of this
        os.path.join(STATS_DIR, 'metrics'),
        os.path.join(DATA_DIR, CONFIG['splunk_logging']['splunk_log_dir']),
        os.path.join(DATA_DIR, DATA_DIR, CONFIG['elk_logging']['elk_log_dir']),
        os.path.join(TEMP_DIR),
        os.path.join(SAQ_HOME, CONFIG['yara']['yss_base_dir'], 'logs'), ]: # XXX this should be in YSS
        #os.path.join(SAQ_HOME, maliciousdir) ]: # XXX remove
        try:
            if not os.path.isdir(dir_path):
                os.makedirs(dir_path)
        except Exception as e:
            logging.error("unable to create required directory {}: {}".format(dir_path, str(e)))
            sys.exit(1)

    # clear out any proxy environment variables if they exist
    for proxy_key in [ 'http_proxy', 'https_proxy', 'ftp_proxy' ]:
        if proxy_key in os.environ:
            logging.debug("removing proxy environment variable for {}".format(proxy_key))
            del os.environ[proxy_key]

    # set up the PROXY global dict (to be used with the requests library)
    for proxy_key in [ 'http', 'https' ]:
        if CONFIG['proxy']['host'] and CONFIG['proxy']['port'] and CONFIG['proxy']['transport']:
            if CONFIG['proxy']['user'] and CONFIG['proxy']['password']:
                PROXIES[proxy_key] = '{}://{}:{}@{}:{}'.format(CONFIG['proxy']['transport'], CONFIG['proxy']['user'], 
                CONFIG['proxy']['password'], CONFIG['proxy']['host'], CONFIG['proxy']['port'])
            else:
                PROXIES[proxy_key] = '{}://{}:{}'.format(CONFIG['proxy']['transport'], CONFIG['proxy']['host'], CONFIG['proxy']['port'])
            logging.debug("proxy for {} set to {}".format(proxy_key, PROXIES[proxy_key]))

    # load any additional proxies specified in the config sections proxy_*
    for section in CONFIG.keys():
        if section.startswith('proxy_'):
            proxy_name = section[len('proxy_'):]
            OTHER_PROXIES[proxy_name] = {}
            for proxy_key in [ 'http', 'https' ]:
                if CONFIG[section]['host'] and CONFIG[section]['port'] and CONFIG[section]['transport']:
                    if 'user' in CONFIG[section] and 'password' in CONFIG[section] \
                    and CONFIG[section]['user'] and CONFIG[section]['password']:
                        OTHER_PROXIES[proxy_name][proxy_key] = '{}://{}:{}@{}:{}'.format(
                        CONFIG[section]['transport'], CONFIG[section]['user'], CONFIG[section]['password'], 
                        CONFIG[section]['host'], CONFIG[section]['port'])
                    else:
                        OTHER_PROXIES[proxy_name][proxy_key] = '{}://{}:{}'.format(
                        CONFIG[section]['transport'], CONFIG[section]['host'], CONFIG[section]['port'])

    # load global constants
    import iptools
    
    MANAGED_NETWORKS = []
    for cidr in CONFIG['network_configuration']['managed_networks'].split(','):
        try:
            if cidr:
                MANAGED_NETWORKS.append(iptools.IpRange(cidr.strip()))
        except Exception as e:
            logging.error("invalid managed network {}: {}".format(cidr, str(e)))

    # are we running as a daemon?
    if args:
        DAEMON_MODE = args.daemon

    # initialize other systems
    initialize_remediation_system_manager()
    initialize_message_system()

    logging.debug("SAQ initialized")
