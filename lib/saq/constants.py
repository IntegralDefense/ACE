# vim: sw=4:ts=4:et

__all__ = [ 
    'INSTANCE_TYPE_PRODUCTION',
    'INSTANCE_TYPE_QA',
    'INSTANCE_TYPE_DEV',
    'F_UUID',
    'F_ID',
    'F_TOOL',
    'F_TOOL_INSTANCE',
    'F_TYPE',
    'F_DESCRIPTION',
    'F_EVENT_TIME',
    'F_DETAILS',
    'F_CIDR',
    'F_IPV4',
    'F_IPV4_CONVERSATION',
    'F_FQDN',
    'F_HTTP_REQUEST',
    'F_HOSTNAME',
    'F_ASSET',
    'F_USER',
    'F_URL',
    'F_PCAP',
    'F_FILE',
    'F_SUSPECT_FILE', # DEPRECATED
    'F_FILE_PATH',
    'F_FILE_NAME',
    'F_FILE_LOCATION',
    'F_EMAIL_ADDRESS',
    'F_EMAIL_CONVERSATION',
    'F_YARA',
    'F_YARA_RULE',
    'F_INDICATOR',
    'F_MD5',
    'F_SHA1',
    'F_SHA256',
    'F_SNORT_SIGNATURE',
    'F_MESSAGE_ID',
    'F_DISPOSITION',
    'F_PROCESS_GUID',
    'F_TEST',
    'event_time_format',
    'event_time_format_tz',
    'event_time_format_json_tz',
    'event_time_format_json',
    'OBSERVABLE_DESCRIPTIONS',
    'OBSERVABLE_NODE_COLORS',
    'VALID_OBSERVABLE_TYPES',
    'VALID_ALERT_DISPOSITIONS',
    'IGNORE_ALERT_DISPOSITIONS',
    'BENIGN_ALERT_DISPOSITIONS',
    'MAL_ALERT_DISPOSITIONS',
    'parse_ipv4_conversation',
    'create_ipv4_conversation',
    'parse_email_conversation',
    'create_email_conversation',
    'parse_file_location',
    'create_file_location',
    'DISPOSITION_FALSE_POSITIVE',
    'DISPOSITION_IGNORE',
    'DISPOSITION_UNKNOWN',
    'DISPOSITION_REVIEWED',
    'DISPOSITION_GRAYWARE',
    'DISPOSITION_POLICY_VIOLATION',
    'DISPOSITION_RECONNAISSANCE',
    'DISPOSITION_WEAPONIZATION',
    'DISPOSITION_DELIVERY',
    'DISPOSITION_EXPLOITATION',
    'DISPOSITION_INSTALLATION',
    'DISPOSITION_COMMAND_AND_CONTROL',
    'DISPOSITION_EXFIL',
    'DISPOSITION_DAMAGE',
    'DISPOSITION_CSS_MAPPING',
    'DIRECTIVE_ARCHIVE',
    'DIRECTIVE_COLLECT_FILE',
    'DIRECTIVE_CRAWL',
    'DIRECTIVE_FORCE_DOWNLOAD',
    'DIRECTIVE_EXTRACT_URLS',
    'DIRECTIVE_SANDBOX',
    'DIRECTIVE_ORIGINAL_EMAIL',
    'DIRECTIVE_ORIGINAL_SMTP',
    'DIRECTIVE_NO_SCAN',
    'DIRECTIVE_DELAY',
    'DIRECTIVE_EXCLUDE_ALL',
    'DIRECTIVE_WHITELISTED',
    'VALID_DIRECTIVES',
    'is_valid_directive',
    'TAG_LEVEL_FALSE_POSITIVE',
    'TAG_LEVEL_INFO',
    'TAG_LEVEL_WARNING',
    'TAG_LEVEL_ALERT',
    'TAG_LEVEL_CRITICAL',
    'TAG_LEVEL_HIDDEN',
    'EVENT_TAG_ADDED',
    'EVENT_OBSERVABLE_ADDED',
    'EVENT_DETAILS_UPDATED',
    'EVENT_DIRECTIVE_ADDED',
    'EVENT_ANALYSIS_ADDED',
    'EVENT_DETECTION_ADDED',
    'EVENT_RELATIONSHIP_ADDED',
    'EVENT_ANALYSIS_MARKED_COMPLETED',
    'EVENT_GLOBAL_TAG_ADDED',
    'EVENT_GLOBAL_OBSERVABLE_ADDED',
    'EVENT_GLOBAL_ANALYSIS_ADDED',
    'VALID_EVENTS',
    'ACTION_TAG_OBSERVABLE',
    'ACTION_UPLOAD_TO_CRITS',
    'ACTION_FILE_DOWNLOAD',
    'ACTION_FILE_DOWNLOAD_AS_ZIP',
    'ACTION_FILE_VIEW_AS_HEX',
    'ACTION_FILE_VIEW_AS_TEXT',
    'ACTION_FILE_UPLOAD_VT',
    'ACTION_FILE_UPLOAD_VX',
    'ACTION_FILE_VIEW_VT',
    'ACTION_FILE_VIEW_VX',
    'ACTION_COLLECT_FILE',
    'ACTION_CLEAR_CLOUDPHISH_ALERT',
    'ACTION_REMEDIATE_EMAIL',
    'METRIC_THREAD_COUNT',
    'R_DOWNLOADED_FROM',
    'R_EXTRACTED_FROM',
    'R_REDIRECTED_FROM',
    'VALID_RELATIONSHIP_TYPES',
    'TARGET_EMAIL_RECEIVED',
    'TARGET_EMAIL_XMAILER',
    'TARGET_EMAIL_BODY',
    'TARGET_EMAIL_MESSAGE_ID',
    'TARGET_EMAIL_RCPT_TO',
    'TARGET_VX_IPDOMAINSTREAMS',
    'VALID_TARGETS',
    'ANALYSIS_MODE_CORRELATION',
    'ANALYSIS_MODE_ANALYSIS',
    'ANALYSIS_MODE_EMAIL',
    'ANALYSIS_MODE_HTTP',
    'ANALYSIS_MODE_FILE',
    'ANALYSIS_MODE_CLI',
    'ANALYSIS_TYPE_MAILBOX',
    'ANALYSIS_TYPE_BRO_SMTP',
    'ANALYSIS_TYPE_BRO_HTTP',
    'ANALYSIS_TYPE_GENERIC',
]

# 
# instance types
#

INSTANCE_TYPE_PRODUCTION = 'PRODUCTION'
INSTANCE_TYPE_QA = 'QA'
INSTANCE_TYPE_DEV = 'DEV'

#
# required fields for every alert
#

F_UUID = 'uuid'
F_ID = 'id'
F_TOOL = 'tool'
F_TOOL_INSTANCE = 'tool_instance'
F_TYPE = 'type'
F_DESCRIPTION = 'description'
F_EVENT_TIME = 'event_time'
F_DETAILS = 'details'
F_DISPOSITION = 'disposition'
#F_COMMENTS = 'comments'

#
# observable types
#

#
# WARNING
# XXX NOTE
# when you add a new observable type you ALSO need to edit lib/saq/analysis.py
# and add a matching entry to the _OBSERVABLE_TYPE_MAPPING dictionary

F_CIDR = 'cidr'
F_IPV4 = 'ipv4'
F_IPV4_CONVERSATION = 'ipv4_conversation'
F_FQDN = 'fqdn'
F_HOSTNAME = 'hostname'
F_HTTP_REQUEST = 'http_request'
F_ASSET = 'asset'
F_USER = 'user'
F_URL = 'url'
F_PCAP = 'pcap'
F_FILE = 'file'
F_SUSPECT_FILE = 'suspect_file' # DEPRECATED
F_FILE_PATH = 'file_path'
F_FILE_NAME = 'file_name'
F_FILE_LOCATION = 'file_location'
F_EMAIL_ADDRESS = 'email_address'
F_EMAIL_CONVERSATION = 'email_conversation'
F_YARA = 'yara'
F_YARA_RULE = 'yara_rule'
F_INDICATOR = 'indicator'
F_MD5 = 'md5'
F_SHA1 = 'sha1'
F_SHA256 = 'sha256'
F_SNORT_SIGNATURE = 'snort_sig'
F_MESSAGE_ID = 'message_id'
F_PROCESS_GUID = 'process_guid'
F_TEST = 'test'

OBSERVABLE_DESCRIPTIONS = {
    F_CIDR: 'IPv4 range in CIDR notation',
    F_IPV4: 'IP address (version 4)',
    F_IPV4_CONVERSATION: 'two F_IPV4 that were communicating formatted as aaa.bbb.ccc.ddd_aaa.bbb.ccc.ddd',
    F_FQDN: 'fully qualified domain name',
    F_HOSTNAME: 'host or workstation name',
    F_HTTP_REQUEST: 'a single HTTP request',
    F_ASSET: 'a F_IPV4 identified to be a managed asset',
    F_USER: 'an NT user ID identified to have used a given asset in the given period of time',
    F_URL: 'a URL',
    F_PCAP: 'path to a pcap formatted file *** DEPRECATED (use F_FILE instead)',
    F_FILE: 'path to an attached file',
    F_SUSPECT_FILE: 'path to an attached file that might be malicious *** DEPRECATED (use directives instead)',
    F_FILE_PATH: 'a file path',
    F_FILE_NAME: 'a file name (no directory path)',
    F_FILE_LOCATION: 'the location of file with format hostname@full_path',
    F_EMAIL_ADDRESS: 'email address',
    F_EMAIL_CONVERSATION: 'a conversation between a source email address (MAIL FROM) and a destination email address (RCPT TO)',
    F_YARA: 'yara scan result *** DEPRECATED (use F_YARA_RULE instead)',
    F_YARA_RULE: 'yara rule name',
    F_INDICATOR: 'crits indicator object id',
    F_MD5: 'MD5 hash',
    F_SHA1: 'SHA1 hash',
    F_SHA256: 'SHA256 hash',
    F_SNORT_SIGNATURE: 'snort signature ID',
    F_MESSAGE_ID: 'email Message-ID',
    F_PROCESS_GUID: 'CarbonBlack global process identifier',
    F_TEST: 'unit testing observable',
}

# this is used in vis.js in the GUI
# see http://www.rapidtables.com/web/color/RGB_Color.htm
OBSERVABLE_NODE_COLORS = {
    F_CIDR: "#0000FF", # blue
    F_IPV4 : "#0000FF", # blue
    F_IPV4_CONVERSATION : "#0000FF", # blue
    F_FQDN : "#D2691E", # chocolate
    F_HOSTNAME : "#87CEFA", # light sky blue
    F_HTTP_REQUEST : "#87CEFA", # light sky blue
    F_ASSET : "#FDF5E6", # old lace
    F_USER : "#DDA0DD", # plum
    F_URL : "#F5F5DC", # beige
    F_PCAP : "#B0C4DE", # light steel blue
    F_FILE : "#9ACD32", # yellow green
    F_SUSPECT_FILE : "#9ACD32", # yellow green
    F_FILE_PATH : "#A9DC23", # ???
    F_FILE_NAME : "#A9DC23", # ???
    F_FILE_LOCATION : "#A9DC23", # ???
    F_EMAIL_ADDRESS : "#00CED1", # dark turquoise
    F_EMAIL_CONVERSATION : "#00CED1", # dark turquoise
    F_YARA : '#B22222', # firebrick 
    F_YARA_RULE : '#B22222', # firebrick 
    F_INDICATOR : "#F5F5F5", # white smoke
    F_MD5 : "#E6E6FA", # lavender
    F_SHA1 : "#E6E6FA", # lavender
    F_SHA256 : "#E6E6FA", # lavender
    F_MESSAGE_ID : "#E6E6FA", # lavender
    F_PROCESS_GUID : "#E6E6FA", # lavender
    F_TEST : "#E6E6FA", # lavender
}

VALID_OBSERVABLE_TYPES = sorted([
    F_CIDR,
    F_IPV4,
    F_IPV4_CONVERSATION,
    F_FQDN,
    F_HOSTNAME,
    F_HTTP_REQUEST,
    F_ASSET,
    F_USER,
    F_URL,
    F_PCAP,
    F_FILE,
    F_SUSPECT_FILE,
    F_FILE_PATH,
    F_FILE_NAME,
    F_FILE_LOCATION,
    F_EMAIL_ADDRESS,
    F_EMAIL_CONVERSATION,
    F_YARA,
    F_YARA_RULE,
    F_INDICATOR,
    F_MD5,
    F_SHA1,
    F_SHA256,
    F_SNORT_SIGNATURE,
    F_MESSAGE_ID,
    F_PROCESS_GUID,
    F_TEST,
])

# utility functions to work with F_IPV4_CONVERSATION types
def parse_ipv4_conversation(f_ipv4_c):
    return f_ipv4_c.split('_', 2)

def create_ipv4_conversation(src, dst):
    return '{0}_{1}'.format(src, dst)

# utility functions to work with F_EMAIL_CONVERSATION types
def parse_email_conversation(f_ipv4_c):
    result = f_ipv4_c.split('|', 2)
    
    # did parsing fail?
    if len(result) != 2:
        return f_ipv4_c, ''

    return result

def create_email_conversation(mail_from, rcpt_to):
    return '{0}|{1}'.format(mail_from, rcpt_to)

def parse_file_location(file_location):
    return file_location.split('@', 1)

def create_file_location(hostname, full_path):
    return '{}@{}'.format(hostname, full_path)

# the expected format of the event_time of an alert
event_time_format_tz = '%Y-%m-%d %H:%M:%S %z'
# the old time format before we started storing timezones
event_time_format = '%Y-%m-%d %H:%M:%S'
# the "ISO 8601" format that ACE uses to store datetime objects in JSON with a timezone
# NOTE this is the preferred format
event_time_format_json_tz = '%Y-%m-%dT%H:%M:%S.%f%z'
# the "ISO 8601" format that ACE uses to store datetime objects in JSON without a timezone
event_time_format_json = '%Y-%m-%dT%H:%M:%S.%f'

# alert dispositions
DISPOSITION_FALSE_POSITIVE = 'FALSE_POSITIVE'
DISPOSITION_IGNORE = 'IGNORE'
DISPOSITION_UNKNOWN = 'UNKNOWN'
DISPOSITION_REVIEWED = 'REVIEWED'
DISPOSITION_GRAYWARE = 'GRAYWARE'
DISPOSITION_POLICY_VIOLATION = 'POLICY_VIOLATION'
DISPOSITION_RECONNAISSANCE = 'RECONNAISSANCE'
DISPOSITION_WEAPONIZATION = 'WEAPONIZATION'
DISPOSITION_DELIVERY = 'DELIVERY'
DISPOSITION_EXPLOITATION = 'EXPLOITATION'
DISPOSITION_INSTALLATION = 'INSTALLATION'
DISPOSITION_COMMAND_AND_CONTROL = 'COMMAND_AND_CONTROL'
DISPOSITION_EXFIL = 'EXFIL'
DISPOSITION_DAMAGE = 'DAMAGE'

# disposition to label mapping
# each disposition has a specific CSS class assigned to it
DISPOSITION_CSS_MAPPING = {
    None: 'default', # when no disposition has been set yet
    DISPOSITION_FALSE_POSITIVE: 'success',
    DISPOSITION_IGNORE: 'default',
    DISPOSITION_UNKNOWN: 'info',
    DISPOSITION_REVIEWED: 'info',
    DISPOSITION_GRAYWARE: 'info',
    DISPOSITION_POLICY_VIOLATION: 'warning',
    DISPOSITION_RECONNAISSANCE: 'warning',
    DISPOSITION_WEAPONIZATION: 'danger',
    DISPOSITION_DELIVERY: 'danger',
    DISPOSITION_EXPLOITATION: 'danger',
    DISPOSITION_INSTALLATION: 'danger',
    DISPOSITION_COMMAND_AND_CONTROL: 'danger',
    DISPOSITION_EXFIL: 'danger',
    DISPOSITION_DAMAGE: 'danger',
}

VALID_ALERT_DISPOSITIONS = [
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_IGNORE,
    DISPOSITION_UNKNOWN,
    DISPOSITION_REVIEWED,
    DISPOSITION_GRAYWARE,
    DISPOSITION_POLICY_VIOLATION,
    DISPOSITION_RECONNAISSANCE,
    DISPOSITION_WEAPONIZATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_EXPLOITATION,
    DISPOSITION_INSTALLATION,
    DISPOSITION_COMMAND_AND_CONTROL,
    DISPOSITION_EXFIL,
    DISPOSITION_DAMAGE
]

IGNORE_ALERT_DISPOSITIONS = [
    DISPOSITION_IGNORE,
    DISPOSITION_UNKNOWN,
    DISPOSITION_REVIEWED
]

BENIGN_ALERT_DISPOSITIONS = [
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_GRAYWARE,
    DISPOSITION_POLICY_VIOLATION,
    DISPOSITION_RECONNAISSANCE
]

MAL_ALERT_DISPOSITIONS = [
    DISPOSITION_WEAPONIZATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_EXPLOITATION,
    DISPOSITION_INSTALLATION,
    DISPOSITION_COMMAND_AND_CONTROL,
    DISPOSITION_EXFIL,
    DISPOSITION_DAMAGE
]


# --- DIRECTIVES
# archive the file
DIRECTIVE_ARCHIVE = 'archive'
# collect the file from the remote endpoint
DIRECTIVE_COLLECT_FILE = 'collect_file'
# crawl the url
DIRECTIVE_CRAWL = 'crawl'
# download the content of the URL no matter what
DIRECTIVE_FORCE_DOWNLOAD = 'force_download'
# extract URLs from the given file
DIRECTIVE_EXTRACT_URLS = 'extract_urls'
# run the observable through a sandbox
DIRECTIVE_SANDBOX = 'sandbox'
# treat this file as the original email file
DIRECTIVE_ORIGINAL_EMAIL = 'original_email'
# treat this file as the original smtp stream
DIRECTIVE_ORIGINAL_SMTP = 'original_smtp'
# do not scan this file with yara
DIRECTIVE_NO_SCAN = 'no_scan'
# instructs various analysis modules that supprt this directive
# to delay the analysis (or to try again)
DIRECTIVE_DELAY = 'delay'
# instructs ACE to NOT analyze this observable at all
DIRECTIVE_EXCLUDE_ALL = 'exclude_all'
# indicates this observable was whitelisted, causing the entire analysis to also become whitelisted
DIRECTIVE_WHITELISTED = 'whitelisted'

VALID_DIRECTIVES = [
    DIRECTIVE_COLLECT_FILE,
    DIRECTIVE_CRAWL,
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_ORIGINAL_EMAIL,
    DIRECTIVE_ORIGINAL_SMTP,
    DIRECTIVE_SANDBOX,
    DIRECTIVE_FORCE_DOWNLOAD,
    DIRECTIVE_DELAY,
    DIRECTIVE_EXCLUDE_ALL,
    DIRECTIVE_NO_SCAN,
    DIRECTIVE_WHITELISTED,
]

def is_valid_directive(directive):
    return directive in VALID_DIRECTIVES

# --- TAGS
TAG_LEVEL_FALSE_POSITIVE = 'fp'
TAG_LEVEL_INFO = 'info'
TAG_LEVEL_WARNING = 'warning'
TAG_LEVEL_ALERT = 'alert'
TAG_LEVEL_CRITICAL = 'critical'
TAG_LEVEL_HIDDEN = 'hidden'

# --- EVENTS
# fired when we add a tag to something
EVENT_TAG_ADDED = 'tag_added'
# called when an Observable is added to the Analysis
EVENT_OBSERVABLE_ADDED = 'observable_added'
# called when the details of an Analysis have been updated
EVENT_DETAILS_UPDATED = 'details_updated'
# fired when we add a directive to an Observable
EVENT_DIRECTIVE_ADDED = 'directive_added'
# fired when we add an Analysis to an Observable
EVENT_ANALYSIS_ADDED = 'analysis_added'
# fired when we add a DetectionPoint ot an Analysis or Observable
EVENT_DETECTION_ADDED = 'detection_added'
# fired when an analysis is marked as completed manually
EVENT_ANALYSIS_MARKED_COMPLETED = 'analysis_marked_completed'
# fired when a relationship is added to an observable
EVENT_RELATIONSHIP_ADDED = 'relationship_added'

# these next two events are intended to be used with the RootAnalysis object
# fired when we add a tag to any taggable object
EVENT_GLOBAL_TAG_ADDED = 'global_tag_added'
# fired when we add an observable to any analysis object
EVENT_GLOBAL_OBSERVABLE_ADDED = 'global_observable_added'
# fired when we add an analysis to any observable object
EVENT_GLOBAL_ANALYSIS_ADDED = 'global_analysis_added'

# list of all valid events
VALID_EVENTS = [ 
    EVENT_ANALYSIS_MARKED_COMPLETED,
    EVENT_TAG_ADDED,
    EVENT_OBSERVABLE_ADDED,
    EVENT_ANALYSIS_ADDED,
    EVENT_DETECTION_ADDED,
    EVENT_DIRECTIVE_ADDED,
    EVENT_RELATIONSHIP_ADDED,
    EVENT_DETAILS_UPDATED,
    EVENT_GLOBAL_TAG_ADDED,
    EVENT_GLOBAL_OBSERVABLE_ADDED,
    EVENT_GLOBAL_ANALYSIS_ADDED ]

# available actions for observables
ACTION_TAG_OBSERVABLE = 'tag_observable'
ACTION_UPLOAD_TO_CRITS = 'upload_crits'
ACTION_FILE_DOWNLOAD = 'file_download'
ACTION_FILE_DOWNLOAD_AS_ZIP = 'file_download_as_zip'
ACTION_FILE_VIEW_AS_HEX = 'file_view_as_hex'
ACTION_FILE_VIEW_AS_TEXT = 'file_view_as_text'
ACTION_FILE_UPLOAD_VT = 'file_upload_vt'
ACTION_FILE_UPLOAD_VX = 'file_upload_vx'
ACTION_FILE_VIEW_VT = 'file_view_vt'
ACTION_FILE_VIEW_VX = 'file_view_vx'
ACTION_COLLECT_FILE = 'collect_file'
ACTION_CLEAR_CLOUDPHISH_ALERT = 'clear_cloudphish_alert'
ACTION_REMEDIATE_EMAIL = 'remediate_email'

# recorded metrics
METRIC_THREAD_COUNT = 'thread_count'

# relationships
R_DOWNLOADED_FROM = 'downloaded_from'
R_EXTRACTED_FROM = 'extracted_from'
R_REDIRECTED_FROM = 'redirected_from'

VALID_RELATIONSHIP_TYPES = [
    R_DOWNLOADED_FROM,
    R_EXTRACTED_FROM,
    R_REDIRECTED_FROM,
]

TARGET_EMAIL_RECEIVED = 'email.received'
TARGET_EMAIL_XMAILER = 'email.x_mailer'
TARGET_EMAIL_BODY = 'email.body'
TARGET_EMAIL_MESSAGE_ID = 'email.message_id'
TARGET_EMAIL_RCPT_TO = 'email.rcpt_to'
TARGET_VX_IPDOMAINSTREAMS = 'vx.ip_domain_streams'
VALID_TARGETS = [
    TARGET_EMAIL_RECEIVED,
    TARGET_EMAIL_XMAILER,
    TARGET_EMAIL_BODY,
    TARGET_EMAIL_MESSAGE_ID,
    TARGET_EMAIL_RCPT_TO,
    TARGET_VX_IPDOMAINSTREAMS,
]

# constants defined for keys to dicts (typically in json files)
KEY_DESCRIPTION = 'description'
KEY_DETAILS = 'details'

# analysis modes (more can be added)
ANALYSIS_MODE_CORRELATION = 'correlation'
ANALYSIS_MODE_CLI = 'cli'
ANALYSIS_MODE_ANALYSIS = 'analysis'
ANALYSIS_MODE_EMAIL = 'email'
ANALYSIS_MODE_HTTP = 'http'
ANALYSIS_MODE_FILE = 'file'

ANALYSIS_TYPE_GENERIC = 'generic'
ANALYSIS_TYPE_MAILBOX = 'mailbox'
ANALYSIS_TYPE_BRO_SMTP = 'bro - smtp'
ANALYSIS_TYPE_BRO_HTTP = 'bro - http'
