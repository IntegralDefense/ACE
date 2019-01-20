# vim: sw=4:ts=4:et:cc=120
#
# various utility functions
#

import datetime
import logging
import os, os.path
import re

import saq
from saq.constants import *

import pytz

CIDR_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$')
CIDR_WITH_NETMASK_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$')
URL_REGEX_B = re.compile(rb'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))', re.I)
URL_REGEX_STR = re.compile(r'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))', re.I)

def create_directory(path):
    """Creates the given directory if it does not already exist.
       Returns True on success, False otherwise and logs the error message."""
    try:
        if not os.path.isdir(path):
            os.makedirs(path)

        return True
    except Exception as e:
        logging.error("unable to create directory {}: {}".format(path, e))
        return False

def is_ipv4(value):
    """Returns True if the given value is a dotted-quad IP address or CIDR notation."""
    return CIDR_REGEX.match(value) is not None

def add_netmask(value):
    """Returns a CIDR notation value for the given ipv4 or CIDR notation (adds the network if it's missing.)"""
    if CIDR_WITH_NETMASK_REGEX.match(value):
        return value

    # we assume it is a single host
    return '{}/32'.format(value)

def is_subdomain(src, dst):
    """Returns True if src is equal to or a subdomain of dst."""
    src = src.lower()
    src = src.split('.')
    src.reverse()
    
    dst = dst.lower()
    dst = dst.split('.')
    dst.reverse()

    for index in range(len(dst)):
        try:
            if src[index] != dst[index]:
                return False
        except IndexError:
            return False

    return True

def is_url(value):
    if isinstance(value, str):
        if URL_REGEX_STR.match(value):
            return True

        return False
    else:
        if URL_REGEX_B.match(value):
            return True

        return False

def iterate_fqdn_parts(fqdn, reverse=False):
    """For a.b.c.d iterates d, c.d, b.c.d, a.b.c.d."""
    parsed_fqdn = fqdn.split('.')
    parsed_fqdn.reverse()
    for i in range(1, len(parsed_fqdn) + 1):
        partial_fqdn = parsed_fqdn[:i]
        partial_fqdn.reverse()
        partial_fqdn = '.'.join(partial_fqdn)
        yield partial_fqdn

    raise StopIteration()

def human_readable_size(size):
    from math import log2

    _suffixes = ['bytes', 'K', 'M', 'G', 'T', 'E', 'Z']

    # determine binary order in steps of size 10 
    # (coerce to int, // still returns a float)
    order = int(log2(size) / 10) if size else 0
    # format file size
    # (.4g results in rounded numbers for exact matches and max 3 decimals, 
    # should never resort to exponent values)
    return '{:.4g} {}'.format(size / (1 << (order * 10)), _suffixes[order])

def create_timedelta(timespec):
    """Utility function to translate DD:HH:MM:SS into a timedelta object."""
    duration = timespec.split(':')
    seconds = int(duration[-1])
    minutes = 0
    hours = 0
    days = 0

    if len(duration) > 1:
        minutes = int(duration[-2])
    if len(duration) > 2:
        hours = int(duration[-3])
    if len(duration) > 3:
        days = int(duration[-4])

    return datetime.timedelta(days=days, seconds=seconds, minutes=minutes, hours=hours)

RE_ET_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}$')
RE_ET_OLD_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$')
RE_ET_JSON_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}[+-][0-9]{4}$')
RE_ET_OLD_JSON_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}$')
RE_ET_ISO_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}[+-][0-9]{2}:[0-9]{2}$')

def parse_event_time(event_time):
    """Return the datetime object for the given event_time."""
    # remove any leading or trailing whitespace
    event_time = event_time.strip()

    if RE_ET_FORMAT.match(event_time):
        return datetime.datetime.strptime(event_time, event_time_format_tz)
    elif RE_ET_OLD_FORMAT.match(event_time):
        return saq.LOCAL_TIMEZONE.localize(datetime.datetime.strptime(event_time, event_time_format))
    elif RE_ET_JSON_FORMAT.match(event_time):
        return datetime.datetime.strptime(event_time, event_time_format_json_tz)
    elif RE_ET_ISO_FORMAT.match(event_time):
        # we just need to remove the : in the timezone specifier
        # this has been fixed in python 3.7
        event_time = event_time[:event_time.rfind(':')] + event_time[event_time.rfind(':') + 1:]
        return datetime.datetime.strptime(event_time, event_time_format_json_tz)
    elif RE_ET_OLD_JSON_FORMAT.match(event_time):
        return saq.LOCAL_TIMEZONE.localize(datetime.datetime.strptime(event_time, event_time_format_json))
    else:
        raise ValueError("invalid date format {}".format(event_time))

UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
def storage_dir_from_uuid(uuid):
    """Returns the path (relative to SAQ_HOME) to the storage directory for the given uuid."""
    validate_uuid(uuid)
    return os.path.relpath(os.path.join(saq.DATA_DIR, saq.SAQ_NODE, uuid[0:3], uuid), start=saq.SAQ_HOME)

def validate_uuid(uuid):
    if not UUID_REGEX.match(uuid):
        raise ValueError("invalid UUID {}".format(uuid))

    return True

def local_time():
    """Returns datetime.datetime.now() in UTC time zone."""
    return saq.LOCAL_TIMEZONE.localize(datetime.datetime.now()).astimezone(pytz.UTC)

def abs_path(path):
    """Given a path, return SAQ_HOME/path if path is relative, or path if path is absolute."""
    if os.path.isabs(path):
        return path

    return os.path.join(saq.SAQ_HOME, path)
