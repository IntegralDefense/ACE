# vim: sw=4:ts=4:et

import requests
import logging
import os.path
import sys

from saq.analysis import Alert

def submit_alert(uri, key, alert):
    """Submit the given alert to the ACE server."""
    assert isinstance(alert, Alert)

