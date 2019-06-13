# vim: sw=4:ts=4:et
#
# uses phishfry as the email remediation system
#

import os, os.path
import logging

from configparser import ConfigParser

import saq
from saq.database import Remediation

from saq.remediation import EmailRemediationSystem
from saq.remediation.constants import *

import EWS

class PhishfryRemediationSystem(EmailRemediationSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # set this property to true when doing unit testing
        self.testing_mode = False
        
        # load the Exchange Web Services accounts
        self.accounts = []
        config = ConfigParser()
        config.read(os.path.join(saq.SAQ_HOME, saq.CONFIG['phishfry']['config_path']))
        timezone = config["DEFAULT"].get("timezone", "UTC")
        for section in config.sections():
            server = config[section].get("server", "outlook.office365.com")
            version = config[section].get("version", "Exchange2016")
            user = config[section]["user"]
            password = config[section]["pass"]
            self.accounts.append(EWS.Account(user, password, server=server, version=version, 
                                             timezone=timezone, proxies=saq.PROXIES))
            logging.info(f"loaded phishfry EWS account user {user} server {server} version {version}")

    def enable_testing_mode(self):
        self.testing_mode = True

    def execute_request(self, remediation):
        logging.info(f"execution remediation {remediation}")
        message_id, recipient = remediation.key.split(':', 1)

        # TODO should we use our email address parsing utilities for this instead?
        if recipient.startswith('<'):
            recipient = recipient[1:]
        if recipient.endswith('>'):
            recipient = recipient[:-1]

        logging.debug("got message_id {message_id} recipient {recipient} from key {remediation.key}")

        found_recipient = False
        for account in self.accounts:
            if self.testing_mode:
                pf_result = {}
                pf_result[recipient] = EWS.remediation_result.RemediationResult(recipient, message_id, 'mailbox', remediation.action, success=True, message='removed')
            else:
                pf_result = account.Remediate(remediation.action, recipient, message_id)

            logging.info(f"got result {pf_result} for message-id {message_id} for {recipient}")

            # this returns a dict of the following structure
            # pf_result[email_address] = EWS.RemediationResult
            # with any number of email_address keys depending on what kind of mailbox it found
            # and how many forwards it found

            # use results from whichever account succesfully resolved the mailbox
            if pf_result[recipient].mailbox_type != "Unknown": # TODO remove hcc
                found_recipient = True
                messages = []
                for pf_recipient in pf_result.keys():
                    if pf_recipient == recipient:
                        continue

                    if pf_recipient in pf_result[recipient].forwards:
                        discovery_method = "forwarded to"
                    elif pf_recipient in pf_result[recipient].members:
                        discovery_method = "list membership"
                    elif pf_result[recipient].owner:
                        discovery_method = "owner"
                    else:
                        discovery_method = "UNKNOWN DISCOVERY METHOD"

                    messages.append('({}) success {} disc method {} recipient {} (message {})'.format(
                                    200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ] else 500,
                                    pf_result[pf_recipient].success,
                                    discovery_method,
                                    pf_recipient,
                                    pf_result[pf_recipient].message))
                
                message = pf_result[pf_recipient].message
                if message is None:
                    message = ''
                if messages:
                    message += '\n' + '\n'.join(messages)

                saq.db.execute(Remediation.__table__.update().values(
                    result=message,
                    successful=pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ],
                    status=REMEDIATION_STATUS_COMPLETED).where(
                    Remediation.id==remediation.id))
                saq.db.commit()

                # we found the recipient in this EWS acount so we don't need to keep looking in any others ones
                break

        # did we find it?
        if not found_recipient:
            saq.db.execute(Remediation.__table__.update().values(
                result="cannot find mailbox",
                success=False,
                status=REMEDIATION_STATUS_COMPLETED).where(
                id=remediation.id))
            saq.db.commit()
            logging.warning(f"could not find message-id {message_id} sent to {recipient}")

        logging.info("completed remediation request {remediation}")
