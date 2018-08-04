# vim: sw=4:ts=4:et

import datetime
import logging

from saq.constants import event_time_format

def validate_time_format(t):
    """Returns True if the given string matches the event time format, False otherwise."""
    try:
        datetime.datetime.strptime(t, event_time_format)
    except ValueError as e:
        logging.error("invalid event time format {0}: {1}".format(t, str(e)))
        return False

    return True
