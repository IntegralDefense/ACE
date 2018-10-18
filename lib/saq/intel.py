# the list of valid indicator types

__all__ = [
    'I_ADJUST_TOKEN',
    'I_API_KEY',
    'I_AS_NUMBER',
    'I_AS_NAME',
    'I_BANK_ACCOUNT',
    'I_BITCOIN_ACCOUNT',
    'I_CERTIFICATE_FINGERPRINT',
    'I_CERTIFICATE_NAME',
    'I_CHECKSUM_CRC16',
    'I_CMD_LINE',
    'I_COMPANY_NAME',
    'I_COOKIE_NAME',
    'I_COUNTRY',
    'I_CRX',
    'I_DEBUG_PATH',
    'I_DEBUG_STRING',
    'I_DEST_PORT',
    'I_DEVICE_IO',
    'I_DOC_FROM_URL',
    'I_DOMAIN',
    'I_EMAIL_BOUNDARY',
    'I_EMAIL_ADDRESS',
    'I_EMAIL_FROM',
    'I_EMAIL_HEADER_FIELD',
    'I_EMAIL_HELO',
    'I_EMAIL_MESSAGE_ID',
    'I_EMAIL_ORIGINATING_IP',
    'I_EMAIL_REPLY_TO',
    'I_EMAIL_SENDER',
    'I_EMAIL_SUBJECT',
    'I_EMAIL_X_MAILER',
    'I_EMAIL_X_ORIGINATING_IP',
    'I_FILE_CREATED',
    'I_FILE_DELETED',
    'I_FILE_MOVED',
    'I_FILE_NAME',
    'I_FILE_OPENED',
    'I_FILE_PATH',
    'I_FILE_READ',
    'I_FILE_WRITTEN',
    'I_GET_PARAM',
    'I_HEX_STRING',
    'I_HTML_ID',
    'I_HTTP_REQUEST',
    'I_HTTP_RESP_CODE',
    'I_IMPHASH',
    'I_IPV4_ADDRESS',
    'I_IPV4_SUBNET',
    'I_IPV6_ADDRESS',
    'I_IPV6_SUBNET',
    'I_LATITUDE',
    'I_LAUNCH_AGENT',
    'I_LOCATION',
    'I_LONGITUDE',
    'I_MAC_ADDRESS',
    'I_MALWARE_NAME',
    'I_MD5',
    'I_MEMORY_ALLOC',
    'I_MEMORY_PROTECT',
    'I_MEMORY_READ',
    'I_MEMORY_WRITTEN',
    'I_MUTANT_CREATED',
    'I_MUTEX',
    'I_NAME_SERVER',
    'I_OTHER_FILE_OP',
    'I_PASSWORD',
    'I_PASSWORD_SALT',
    'I_PAYLOAD_DATA',
    'I_PAYLOAD_TYPE',
    'I_PIPE',
    'I_POST_DATA',
    'I_PROCESS_NAME',
    'I_PROTOCOL',
    'I_REFERER',
    'I_REFERER_OF_REFERER',
    'I_REGISTRAR',
    'I_REGISTRY_KEY',
    'I_REG_KEY_CREATED',
    'I_REG_KEY_DELETED',
    'I_REG_KEY_ENUMERATED',
    'I_REG_KEY_MONITORED',
    'I_REG_KEY_OPENED',
    'I_REG_KEY_VALUE_CREATED',
    'I_REG_KEY_VALUE_DELETED',
    'I_REG_KEY_VALUE_MODIFIED',
    'I_REG_KEY_VALUE_QUERIED',
    'I_SERVICE_NAME',
    'I_SHA1',
    'I_SHA256',
    'I_SMS_ORIGIN',
    'I_SOURCE_PORT',
    'I_SSDEEP',
    'I_TELEPHONE',
    'I_TIME_CREATED',
    'I_TIME_UPDATED',
    'I_TRACKING_ID',
    'I_TS_END',
    'I_TS_START',
    'I_URI',
    'I_URI_PATH',
    'I_USER_AGENT',
    'I_USER_ID',
    'I_VICTIM_IP',
    'I_VOLUME_QUERIED',
    'I_WEBSTORAGE_KEY',
    'I_WEB_PAYLOAD',
    'I_WHOIS_NAME',
    'I_WHOIS_ADDR1',
    'I_WHOIS_ADDR2',
    'I_WHOIS_REGISTRANT_EMAIL_ADDRESS',
    'I_WHOIS_TELEPHONE',
    'I_XPI',
    'valid_indicator_type',
]

I_ADJUST_TOKEN = 'adjust_token'
I_API_KEY = 'api_key'
I_AS_NUMBER = 'as_number'
I_AS_NAME = 'as_name'
I_BANK_ACCOUNT = 'bank_account'
I_BITCOIN_ACCOUNT = 'bitcoin_account'
I_CERTIFICATE_FINGERPRINT = 'certificate_fingerprint'
I_CERTIFICATE_NAME = 'certificate_name'
I_CHECKSUM_CRC16 = 'checksum_crc16'
I_CMD_LINE = 'cmd_line'
I_COMPANY_NAME = 'company_name'
I_COOKIE_NAME = 'cookie_name'
I_COUNTRY = 'country'
I_CRX = 'crx'
I_DEBUG_PATH = 'debug_path'
I_DEBUG_STRING = 'debug_string'
I_DEST_PORT = 'dest_port'
I_DEVICE_IO = 'device_io'
I_DOC_FROM_URL = 'doc_from_url'
I_DOMAIN = 'domain'
I_EMAIL_BOUNDARY = 'email_boundary'
I_EMAIL_ADDRESS = 'email_address'
I_EMAIL_FROM = 'email_from'
I_EMAIL_HEADER_FIELD = 'email_header_field'
I_EMAIL_HELO = 'email_helo'
I_EMAIL_MESSAGE_ID = 'email_message_id'
I_EMAIL_ORIGINATING_IP = 'email_originating_ip'
I_EMAIL_REPLY_TO = 'email_reply_to'
I_EMAIL_SENDER = 'email_sender'
I_EMAIL_SUBJECT = 'email_subject'
I_EMAIL_X_MAILER = 'email_x_mailer'
I_EMAIL_X_ORIGINATING_IP = 'email_x_originating_ip'
I_FILE_CREATED = 'file_created'
I_FILE_DELETED = 'file_deleted'
I_FILE_MOVED = 'file_moved'
I_FILE_NAME = 'file_name'
I_FILE_OPENED = 'file_opened'
I_FILE_PATH = 'file_path'
I_FILE_READ = 'file_read'
I_FILE_WRITTEN = 'file_written'
I_GET_PARAM = 'get_param'
I_HEX_STRING = 'hex_string'
I_HTML_ID = 'html_id'
I_HTTP_REQUEST = 'http_request'
I_HTTP_RESP_CODE = 'http_resp_code'
I_IMPHASH = 'imphash'
I_IPV4_ADDRESS = 'ipv4_address'
I_IPV4_SUBNET = 'ipv4_subnet'
I_IPV6_ADDRESS = 'ipv6_address'
I_IPV6_SUBNET = 'ipv6_subnet'
I_LATITUDE = 'latitude'
I_LAUNCH_AGENT = 'launch_agent'
I_LOCATION = 'location'
I_LONGITUDE = 'longitude'
I_MAC_ADDRESS = 'mac_address'
I_MALWARE_NAME = 'malware_name'
I_MD5 = 'md5'
I_MEMORY_ALLOC = 'memory_alloc'
I_MEMORY_PROTECT = 'memory_protect'
I_MEMORY_READ = 'memory_read'
I_MEMORY_WRITTEN = 'memory_written'
I_MUTANT_CREATED = 'mutant_created'
I_MUTEX = 'mutex'
I_NAME_SERVER = 'name_server'
I_OTHER_FILE_OP = 'other_file_op'
I_PASSWORD = 'password'
I_PASSWORD_SALT = 'password_salt'
I_PAYLOAD_DATA = 'payload_data'
I_PAYLOAD_TYPE = 'payload_type'
I_PIPE = 'pipe'
I_POST_DATA = 'post_data'
I_PROCESS_NAME = 'process_name'
I_PROTOCOL = 'protocol'
I_REFERER = 'referer'
I_REFERER_OF_REFERER = 'referer_of_referer'
I_REGISTRAR = 'registrar'
I_REGISTRY_KEY = 'registry_key'
I_REG_KEY_CREATED = 'reg_key_created'
I_REG_KEY_DELETED = 'reg_key_deleted'
I_REG_KEY_ENUMERATED = 'reg_key_enumerated'
I_REG_KEY_MONITORED = 'reg_key_monitored'
I_REG_KEY_OPENED = 'reg_key_opened'
I_REG_KEY_VALUE_CREATED = 'reg_key_value_created'
I_REG_KEY_VALUE_DELETED = 'reg_key_value_deleted'
I_REG_KEY_VALUE_MODIFIED = 'reg_key_value_modified'
I_REG_KEY_VALUE_QUERIED = 'reg_key_value_queried'
I_SERVICE_NAME = 'service_name'
I_SHA1 = 'sha1'
I_SHA256 = 'sha256'
I_SMS_ORIGIN = 'sms_origin'
I_SOURCE_PORT = 'source_port'
I_SSDEEP = 'ssdeep'
I_TELEPHONE = 'telephone'
I_TIME_CREATED = 'time_created'
I_TIME_UPDATED = 'time_updated'
I_TRACKING_ID = 'tracking_id'
I_TS_END = 'ts_end'
I_TS_START = 'ts_start'
I_URI = 'uri'
I_URI_PATH = 'uri_path'
I_USER_AGENT = 'user_agent'
I_USER_ID = 'user_id'
I_VICTIM_IP = 'victim_ip'
I_VOLUME_QUERIED = 'volume_queried'
I_WEBSTORAGE_KEY = 'webstorage_key'
I_WEB_PAYLOAD = 'web_payload'
I_WHOIS_NAME = 'whois_name'
I_WHOIS_ADDR1 = 'whois_addr1'
I_WHOIS_ADDR2 = 'whois_addr2'
I_WHOIS_REGISTRANT_EMAIL_ADDRESS = 'whois_registrant_email_address'
I_WHOIS_TELEPHONE = 'whois_telephone'
I_XPI = 'xpi'

all_indicator_types = [
    I_ADJUST_TOKEN,
    I_API_KEY,
    I_AS_NUMBER,
    I_AS_NAME,
    I_BANK_ACCOUNT,
    I_BITCOIN_ACCOUNT,
    I_CERTIFICATE_FINGERPRINT,
    I_CERTIFICATE_NAME,
    I_CHECKSUM_CRC16,
    I_CMD_LINE,
    I_COMPANY_NAME,
    I_COOKIE_NAME,
    I_COUNTRY,
    I_CRX,
    I_DEBUG_PATH,
    I_DEBUG_STRING,
    I_DEST_PORT,
    I_DEVICE_IO,
    I_DOC_FROM_URL,
    I_DOMAIN,
    I_EMAIL_BOUNDARY,
    I_EMAIL_ADDRESS,
    I_EMAIL_FROM,
    I_EMAIL_HEADER_FIELD,
    I_EMAIL_HELO,
    I_EMAIL_MESSAGE_ID,
    I_EMAIL_ORIGINATING_IP,
    I_EMAIL_REPLY_TO,
    I_EMAIL_SENDER,
    I_EMAIL_SUBJECT,
    I_EMAIL_X_MAILER,
    I_EMAIL_X_ORIGINATING_IP,
    I_FILE_CREATED,
    I_FILE_DELETED,
    I_FILE_MOVED,
    I_FILE_NAME,
    I_FILE_OPENED,
    I_FILE_PATH,
    I_FILE_READ,
    I_FILE_WRITTEN,
    I_GET_PARAM,
    I_HEX_STRING,
    I_HTML_ID,
    I_HTTP_REQUEST,
    I_HTTP_RESP_CODE,
    I_IMPHASH,
    I_IPV4_ADDRESS,
    I_IPV4_SUBNET,
    I_IPV6_ADDRESS,
    I_IPV6_SUBNET,
    I_LATITUDE,
    I_LAUNCH_AGENT,
    I_LOCATION,
    I_LONGITUDE,
    I_MAC_ADDRESS,
    I_MALWARE_NAME,
    I_MD5,
    I_MEMORY_ALLOC,
    I_MEMORY_PROTECT,
    I_MEMORY_READ,
    I_MEMORY_WRITTEN,
    I_MUTANT_CREATED,
    I_MUTEX,
    I_NAME_SERVER,
    I_OTHER_FILE_OP,
    I_PASSWORD,
    I_PASSWORD_SALT,
    I_PAYLOAD_DATA,
    I_PAYLOAD_TYPE,
    I_PIPE,
    I_POST_DATA,
    I_PROCESS_NAME,
    I_PROTOCOL,
    I_REFERER,
    I_REFERER_OF_REFERER,
    I_REGISTRAR,
    I_REGISTRY_KEY,
    I_REG_KEY_CREATED,
    I_REG_KEY_DELETED,
    I_REG_KEY_ENUMERATED,
    I_REG_KEY_MONITORED,
    I_REG_KEY_OPENED,
    I_REG_KEY_VALUE_CREATED,
    I_REG_KEY_VALUE_DELETED,
    I_REG_KEY_VALUE_MODIFIED,
    I_REG_KEY_VALUE_QUERIED,
    I_SERVICE_NAME,
    I_SHA1,
    I_SHA256,
    I_SMS_ORIGIN,
    I_SOURCE_PORT,
    I_SSDEEP,
    I_TELEPHONE,
    I_TIME_CREATED,
    I_TIME_UPDATED,
    I_TRACKING_ID,
    I_TS_END,
    I_TS_START,
    I_URI,
    I_URI_PATH,
    I_USER_AGENT,
    I_USER_ID,
    I_VICTIM_IP,
    I_VOLUME_QUERIED,
    I_WEBSTORAGE_KEY,
    I_WEB_PAYLOAD,
    I_WHOIS_NAME,
    I_WHOIS_ADDR1,
    I_WHOIS_ADDR2,
    I_WHOIS_REGISTRANT_EMAIL_ADDRESS,
    I_WHOIS_TELEPHONE,
    I_XPI,
]

def valid_indicator_type(indicator_type):
    return indicator_type in all_indicator_types
