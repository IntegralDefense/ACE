# vim: sw=4:ts=4:et:cc=120
#
# various utility functions
#

import datetime
import re

CIDR_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$')
URL_REGEX_B = re.compile(rb'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))', re.I)
URL_REGEX_STR = re.compile(r'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))', re.I)

def is_ipv4(value):
    """Returns True if the given value is a dotted-quad IP address or CIDR notation."""
    return CIDR_REGEX.match(value) is not None

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
