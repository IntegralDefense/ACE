# vim: sw=4:ts=4:et:cc=120

import base64
import hashlib
import io
import ipaddress
import logging
import os.path
import pickle
import re
import unicodedata

from subprocess import Popen, PIPE

import saq
from saq.analysis import Observable, DetectionPoint
from saq.constants import *
from saq.email import normalize_email_address
from saq.error import report_exception
from saq.gui import *
from saq.intel import query_sip_indicator
from saq.util import is_subdomain

import iptools

__all__ = [
    'ObservableValueError',
    'CaselessObservable',
    'IPv4Observable',
    'IPv4ConversationObservable',
    'IPv4FullConversationObservable',
    'FQDNObservable',
    'HostnameObservable',
    'AssetObservable',
    'UserObservable',
    'URLObservable',
    'FileObservable',
    'FilePathObservable',
    'FileNameObservable',
    'FileLocationObservable',
    'EmailAddressObservable',
    'YaraRuleObservable',
    'IndicatorObservable',
    'MD5Observable',
    'SHA1Observable',
    'SHA256Observable',
    'EmailConversationObservable',
    'SnortSignatureObservable',
    'TestObservable',
    'create_observable' ]

# 
# custom Observable types
#

class ObservableValueError(ValueError):
    pass

class CaselessObservable(Observable):
    """An observable that doesn't care about the case of the value."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not isinstance(self.value, str):
            raise ObservableValueError("invalid type {}".format(type(self.value)))

    # see https://stackoverflow.com/a/29247821
    def normalize_caseless(self, value):
        if value is None:
            return None

        return unicodedata.normalize("NFKD", value.casefold())

    def _compare_value(self, other):
        return self.normalize_caseless(self.value) == self.normalize_caseless(other)

class IPv4Observable(Observable):

    def __init__(self, *args, **kwargs):
        super().__init__(F_IPV4, *args, **kwargs)

        # type check the value
        try:
            ipaddress.IPv4Address(self.value)
        except Exception as e:
            raise ObservableValueError("{} is not a valid ipv4 address".format(self.value))
    
    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
            result.extend(super().jinja_available_actions)

        return result

    def is_managed(self):
        """Returns True if this IP address is listed as part of a managed network, False otherwide."""
        # see [network_configuration]
        # these are initialized in the global initialization function
        for cidr in saq.MANAGED_NETWORKS:
            try:
                if self.value in cidr:
                    return True
            except:
                return False

        return False

    def matches(self, value):
        # is this CIDR notation?
        if '/' in value:
            try:
                return self.value in iptools.IpRange(value)
            except:
                pass

        # otherwise it has to match exactly
        return self.value == value

class IPv4ConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_IPV4_CONVERSATION, *args, **kwargs)
        self._source, self._dest = parse_ipv4_conversation(self.value)
        
    @property
    def source(self):
        return self._source

    @property
    def destination(self):
        return self._dest

class IPv4FullConversationObservable(Observable):
    
    def __init__(self, *args, **kwargs):
        super().__init__(F_IPV4_FULL_CONVERSATION, *args, **kwargs)
        self._source, self._source_port, self._dest, self._dest_port = parse_ipv4_full_conversation(self.value)

    @property
    def source(self):
        return self._source

    @property
    def source_port(self):
        return self._source_port

    @property
    def dest(self):
        return self._dest

    @property   
    def dest_port(self):
        return self._dest_port

class FQDNObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FQDN, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
            result.extend(super().jinja_available_actions)

        return result

    def is_managed(self):
        """Returns True if this FQDN is a managed DN."""
        for fqdn in saq.CONFIG['global']['local_domains'].split(','):
            if is_subdomain(self.value, fqdn):
                return True

        return False

class HostnameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_HOSTNAME, *args, **kwargs)

class AssetObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_ASSET, *args, **kwargs)

class UserObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_USER, *args, **kwargs)

class URLObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_URL, *args, **kwargs)

        self.value = self.value.strip() # remove any leading/trailing whitespace

        try:
            # sometimes URL extraction pulls out invalid URLs
            self.value.encode('ascii') # valid URLs are ASCII
        except UnicodeEncodeError as e:
            raise ObservableValueError("invalid URL {}: {}".format(self.value.encode('unicode_escape'), e))

    @property
    def sha256(self):
        """Returns the sha256 value of this URL suitable for cloudphish processing."""
        from lib.saq.cloudphish import hash_url

        if hasattr(self, '_sha256'):
            return self._sha256

        self._sha256 = hash_url(self.value)
        return self._sha256

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionClearCloudphishAlert(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class FileObservable(Observable):

    KEY_MD5_HASH = 'md5_hash'
    KEY_SHA1_HASH = 'sha1_hash'
    KEY_SHA256_HASH = 'sha256_hash'
    KEY_MIME_TYPE = 'mime_type'

    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE, *args, **kwargs)

        self._md5_hash = None
        self._sha1_hash = None
        self._sha256_hash = None

        self._mime_type = None

        self._scaled_width = None
        self._scaled_height = None

        # some directives are inherited by children
        self.add_event_listener(EVENT_RELATIONSHIP_ADDED, self.handle_relationship_added)

    #
    # in ACE the value of the F_FILE observable is the relative path to the content (inside the storage directory)
    # so when we want to look up the tag mapping we really want to look up the content
    # so we use the F_SHA256 value for this purpose instead
        
    @property
    def tag_mapping_type(self):
        return F_SHA256

    @property
    def tag_mapping_value(self):
        return self.sha256_hash

    @property
    def tag_mapping_md5_hex(self):
        if self.sha256_hash is None:
            return None

        md5_hasher = hashlib.md5()
        md5_hasher.update(self.sha256_hash.encode('utf8', errors='ignore'))
        return md5_hasher.hexdigest()

    @property
    def json(self):
        result = Observable.json.fget(self)
        result.update({
            FileObservable.KEY_MD5_HASH: self.md5_hash,
            FileObservable.KEY_SHA1_HASH: self.sha1_hash,
            FileObservable.KEY_SHA256_HASH: self.sha256_hash,
            FileObservable.KEY_MIME_TYPE: self._mime_type,
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        Observable.json.fset(self, value)

        if FileObservable.KEY_MD5_HASH in value:
            self._md5_hash = value[FileObservable.KEY_MD5_HASH]
        if FileObservable.KEY_SHA1_HASH in value:
            self._sha1_hash = value[FileObservable.KEY_SHA1_HASH]
        if FileObservable.KEY_SHA256_HASH in value:
            self._sha256_hash = value[FileObservable.KEY_SHA256_HASH]
        if FileObservable.KEY_MIME_TYPE in value:
            self._mime_type = value[FileObservable.KEY_MIME_TYPE]

    @property
    def md5_hash(self):
        self.compute_hashes()
        return self._md5_hash

    @property
    def sha1_hash(self):
        self.compute_hashes()
        return self._sha1_hash

    @property
    def sha256_hash(self):
        self.compute_hashes()
        return self._sha256_hash

    def compute_hashes(self):
        """Computes the md5, sha1 and sha256 hashes of the file and stores them as properties."""

        if self._md5_hash is not None and self._sha1_hash is not None and self._sha256_hash is not None:
            return True

        # sanity check
        # you need the root storage_dir to get the correct path
        if self.root is None:
            logging.error("compute_hashes was called before root was set for {}".format(self))
            return False

        if self.root.storage_dir is None:
            logging.error("compute_hashes was called before root.storage_dir was set for {}".format(self))
            return False
        
        md5_hasher = hashlib.md5()
        sha1_hasher = hashlib.sha1()
        sha256_hasher = hashlib.sha256()
    
        try:
            with open(self.path, 'rb') as fp:
                while True:
                    data = fp.read(io.DEFAULT_BUFFER_SIZE)
                    if data == b'':
                        break

                    md5_hasher.update(data)
                    sha1_hasher.update(data)
                    sha256_hasher.update(data)

        except Exception as e:
            # this will happen if a F_FILE observable refers to a file that no longer (or never did) exists
            logging.debug(f"unable to compute hashes of {self.value}: {e}")
            return False
        
        md5_hash = md5_hasher.hexdigest()
        sha1_hash = sha1_hasher.hexdigest()
        sha256_hash = sha256_hasher.hexdigest()
        logging.debug("file {} has md5 {} sha1 {} sha256 {}".format(self.path, md5_hash, sha1_hash, sha256_hash))

        self._md5_hash = md5_hash
        self._sha1_hash = sha1_hash
        self._sha256_hash = sha256_hash

        return True

    @property
    def jinja_template_path(self):
        return "analysis/file_observable.html"

    @property
    def mime_type(self):
        if self._mime_type:
            return self._mime_type

        p = Popen(['file', '-b', '--mime-type', '-L', self.path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

        if len(stderr) > 0:
            logging.warning("file command returned error output for {}".format(self.path))

        self._mime_type = stdout.decode(errors='ignore').strip()
        #logging.info("MARKER: {} mime type {}".format(self.path, self._mime_type))
        return self._mime_type

    @property
    def path(self):
        return os.path.join(saq.SAQ_RELATIVE_DIR, self.root.storage_dir, self.value)

    @property
    def ext(self):
        """Returns the file extension of this file in lower case, or None if it doesn't have one."""
        if '.' not in self.value:
            return None

        try:
            return os.path.basename(self.value).split('.')[-1].lower()
        except Exception as e:
            logging.error("unable to get file extension of {}: {}".format(self, e))
            return None

    @property
    def exists(self):
        try:
            #logging.info("checking stat of {}".format(self.path))
            return os.path.exists(self.path)
        except Exception as e:
            logging.warning("unable to stat path: {}".format(e))
            #report_exception()
            return False

    @property
    def size(self):
        try:
            return os.path.getsize(self.path)
        except Exception as e:
            logging.warning("unable to get size: {}".format(e))
            return 0

    @property
    def human_readable_size(self):
        from math import log2

        _suffixes = ['bytes', 'K', 'M', 'G', 'T', 'E', 'Z']

        # determine binary order in steps of size 10 
        # (coerce to int, // still returns a float)
        order = int(log2(self.size) / 10) if self.size else 0
        # format file size
        # (.4g results in rounded numbers for exact matches and max 3 decimals, 
        # should never resort to exponent values)
        return '{:.4g} {}'.format(self.size / (1 << (order * 10)), _suffixes[order])

    @property
    def jinja_available_actions(self):
        result = []
        if self.exists:
            result.append(ObservableActionDownloadFile())
            result.append(ObservableActionDownloadFileAsZip())
            result.append(ObservableActionSeparator())
            result.append(ObservableActionViewAsHex())
            result.append(ObservableActionViewAsText())
            result.append(ObservableActionSeparator())
            result.append(ObservableActionUploadToVt())
            result.append(ObservableActionUploadToVx())
            result.append(ObservableActionSeparator())
            result.append(ObservableActionViewInVt())
            result.append(ObservableActionViewInVx())
            result.append(ObservableActionSeparator())
        result.extend(super().jinja_available_actions)
        return result

    @property
    def is_image(self):
        """Returns True if the file command thinks this file is an image."""
        if self.mime_type is None:
            return False

        return self.mime_type.startswith('image')

    def compute_scaled_dimensions(self):
        from PIL import Image
        try:
            with Image.open(self.path) as image:
                width, height = image.size
        except Exception as e:
            logging.warning("unable to parse image {}: {}".format(self.path, e))
            return

        w_ratio = 1.0
        h_ratio = 1.0

        if width > 640:
            w_ratio = 640.0 / float(width)

        if height > 480:
            h_ratio = 480.0 / float(height)

        ratio = w_ratio if w_ratio > h_ratio else h_ratio
        self._scaled_width = int(width * ratio)
        self._scaled_height = int(height * ratio)
        #logging.info("MARKER: using ratio {} scaled width {} scaled height {}".format(ratio, self._scaled_width, self._scaled_height))

    @property
    def scaled_width(self):
        if not self.is_image:
            return None

        if self._scaled_width:
            return self._scaled_width

        self.compute_scaled_dimensions()
        return self._scaled_width

    @property
    def scaled_height(self):
        if not self.is_image:
            return None

        if self._scaled_height:
            return self._scaled_height

        self.compute_scaled_dimensions()
        return self._scaled_height

    def handle_relationship_added(self, source, event, target, relationship=None):
        pass
        #if relationship.target.has_directive(DIRECTIVE_EXTRACT_URLS):
            #logging.debug("{} inherited directive {} from {}".format(
                          #self, DIRECTIVE_EXTRACT_URLS, relationship.target))
            #self.add_directive(DIRECTIVE_EXTRACT_URLS)

class FilePathObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_PATH, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class FileNameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_NAME, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class FileLocationObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FILE_LOCATION, *args, **kwargs)
        self._hostname, self._full_path = parse_file_location(self.value)

    @property
    def hostname(self):
        return self._hostname

    @property
    def full_path(self):
        return self._full_path

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionCollectFile(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

    @property
    def jinja_template_path(self):
        return "analysis/file_location_observable.html"

class EmailAddressObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_ADDRESS, *args, **kwargs)

        # normalize email addresses
        normalized = normalize_email_address(self.value)
        if not normalized:
            logging.warning("unable to normalize email address {}".format(self.value))
        else:
            self.value = normalized

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class YaraRuleObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_YARA_RULE, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        return []

class IndicatorObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_INDICATOR, *args, **kwargs)
        self._sip_details = None

    @property
    def jinja_template_path(self):
        return "analysis/indicator_observable.html"

    @property
    def jinja_available_actions(self):
        result = []
    
        # SIP indicators start with sip:
        if self.is_sip_indicator:
            result.append(ObservableActionSetSIPIndicatorStatus_Informational())
            result.append(ObservableActionSetSIPIndicatorStatus_New())
            result.append(ObservableActionSetSIPIndicatorStatus_Analyzed())

        return result

    @property
    def is_sip_indicator(self):
        return self.value.startswith('sip:')

    @property
    def sip_details(self):
        if self._sip_details is not None:
            return self._sip_details

        if not self.is_sip_indicator:
            return None

        try:
            self._sip_details = query_sip_indicator(int(self.value[len('sip:'):]))
            return self._sip_details
        except Exception as e:
            logging.error(f"unable to obtain SIP indicator details for {self.value}: {e}")
            return None


    @property
    def sip_status(self):
        if not self.is_sip_indicator:
            return None

        if self.sip_details is None:
            return None

        return self.sip_details['status']

class MD5Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MD5, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class SHA1Observable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SHA1, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class SHA256Observable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SHA256, *args, **kwargs)

    @property
    def jinja_template_path(self):
        return "analysis/sha256_observable.html"

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionUploadToCrits(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class EmailConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_EMAIL_CONVERSATION, *args, **kwargs)
        self._mail_from, self._rcpt_to = parse_email_conversation(self.value)

    @property
    def mail_from(self):
        return self._mail_from

    @property
    def rcpt_to(self):
        return self._rcpt_to

    @property
    def jinja_template_path(self):
        return "analysis/email_conversation_observable.html"

class SnortSignatureObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_SNORT_SIGNATURE, *args, **kwargs)

class MessageIDObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MESSAGE_ID, *args, **kwargs)

    @property
    def jinja_available_actions(self):
        result = [ ObservableActionRemediateEmail(), ObservableActionSeparator() ]
        result.extend(super().jinja_available_actions)
        return result

class ProcessGUIDObservable(Observable): 
    def __init__(self, *args, **kwargs): 
        super().__init__(F_PROCESS_GUID, *args, **kwargs)

class TestObservable(Observable):
    def __init__(self, *args, **kwargs): 
        super().__init__(F_TEST, *args, **kwargs)

    # this allows us to use any object we want for the observable value
    # useful for passing around parameters for testing
    @property
    def value(self):
        return pickle.loads(base64.b64decode(self._value))

    @value.setter
    def value(self, v):
        self._value = base64.b64encode(pickle.dumps(v))

#
# technically we could store the class and module inside the observable
# and load it at runtime by reading that and doing it the same way we load analysis modules
# the problem is that sometimes you need to specify observables by textual type and value
# for example, when running from the command line, and when receiving new alerts over the wire
# thus we keep this mapping around
#

_OBSERVABLE_TYPE_MAPPING = {
    F_ASSET: AssetObservable,
    F_IPV4_CONVERSATION: IPv4ConversationObservable,
    F_IPV4_FULL_CONVERSATION: IPv4FullConversationObservable,
    F_PCAP: FileObservable,
    F_SNORT_SIGNATURE: SnortSignatureObservable,
    F_EMAIL_ADDRESS: EmailAddressObservable,
    F_EMAIL_CONVERSATION: EmailConversationObservable,
    F_FILE: FileObservable,
    F_FILE_LOCATION: FileLocationObservable,
    F_FILE_NAME: FileNameObservable,
    F_FILE_PATH: FilePathObservable,
    F_FQDN: FQDNObservable,
    F_HOSTNAME: HostnameObservable,
    F_INDICATOR: IndicatorObservable,
    F_IPV4: IPv4Observable,
    F_MD5: MD5Observable,
    F_SHA1: SHA1Observable,
    F_SHA256: SHA256Observable,
    F_SUSPECT_FILE: FileObservable,
    F_URL: URLObservable,
    F_USER: UserObservable,
    F_YARA_RULE: YaraRuleObservable,
    F_MESSAGE_ID: MessageIDObservable,
    F_PROCESS_GUID: ProcessGUIDObservable,
    F_TEST: TestObservable,
}

def create_observable(o_type, o_value, o_time=None):
    """Returns an Observable-based class instance for the given type, value and optionally time, 
       or None if value is invalid for the type of Observable."""
    try:
        o_class = _OBSERVABLE_TYPE_MAPPING[o_type]
    except KeyError:
        logging.error("invalid observable type {}".format(o_type))
        raise

    try:
        return o_class(o_value, time=o_time)
    except ObservableValueError as e:
        logging.debug("invalid value {} for observable type {}: {}".format(o_value.encode('unicode_escape'), o_type, e))
        return None
