# vim: ts=4:sw=4:et:cc=120

#
# routines dealing with sending notification messages to Slack
#

import json
import logging

import saq
from saq.constants import *
from saq.messaging import MessageDispatchSystem

import requests

class SlackMessageDispatchSystem(MessageDispatchSystem):
    def dispatch(self, message, destination):
        # the destination is a lookup key in the config
        try:
            slack_url = self.config[f'destination_{destination}']
        except KeyError:
            logging.error(f"missing slack destination {destination}")
            return
        
        logging.info(f"submitting message {message.id} to {slack_url}")
        result = requests.post(slack_url, 
            proxies=saq.PROXIES,
            headers={'Content-Type': 'application/json'}, 
            json={'text': message.content})

        logging.info(f"got result {result.text} ({result.status_code}) for message {message.id}")
