# vim: sw=4:ts=4:et

#
# remediation routines

import datetime
import importlib
import json
import logging
import os, os.path
import queue
import queue
import re
import smtplib
import threading
import time
import uuid

from configparser import ConfigParser

import saq
from saq.database import Alert, get_db_connection, Remediation
from saq.constants import *
from .constants import *
from saq.error import report_exception
from saq.messaging import send_message
from saq.util import *

import requests

from sqlalchemy import asc, func, and_, or_

KEY_ENV_MAIL_FROM = 'env_mail_from'
KEY_ENV_RCPT_TO = 'env_rcpt_to'
KEY_MAIL_FROM = 'from'
KEY_DECODED_MAIL_FROM = 'decoded_mail_from'
KEY_MAIL_TO = 'to'
KEY_SUBJECT = 'subject'
KEY_DECODED_SUBJECT = 'decoded_subject'
KEY_MESSAGE_ID = 'message_id'

# TODO these should be defined in the phishfry library
ACTION_REMEDIATE = 'remove'
ACTION_RESTORE = 'restore'

# when remediation is attempting, this system can optionally send a message with the result
MESSAGE_TYPE_REMEDIATION_SUCCESS = 'remediation_success'
MESSAGE_TYPE_REMEDIATION_FAILURE = 'remediation_failure'

def _remediate_email_o365_EWS(emails):
    """Remediates the given emails specified by a list of tuples of (message-id, recipient email address)."""
    assert emails
    assert all([len(e) == 2 for e in emails])

    result = [] # tuple(message_id, recipient, result_code, result_text)
    
    # get the hostname and port for our EWS proxy system
    # this system receives requests for remediation and restorations and submits them to EWS on our behalf
    ews_host = saq.CONFIG['remediation']['ews_host']
    ews_port = saq.CONFIG['remediation'].getint('ews_port')

    # the format of each request is a POST to
    # https://host:port/delete
    # with JSON as the POST data content
    
    # note that we make a separate request for each one
    url = 'https://{}:{}/delete'.format(saq.CONFIG['remediation']['ews_host'], saq.CONFIG['remediation']['ews_port'])
    session = requests.Session()
    data = { 'recipient': None, 'message_id': None }
    headers = { 'Content-Type': 'application/json' }
    
    for message_id, recipient in emails:
        try:

            if recipient is None:
                continue

            if recipient.startswith('<'):
                recipient = recipient[1:]
            if recipient.endswith('>'):
                recipient = recipient[:-1]

            data['recipient'] = recipient
            data['message_id'] = message_id
            json_data = json.dumps(data)

            logging.info("remediating message_id {} to {}".format(message_id, recipient))
            r = session.post(url, headers=headers, data=json_data, verify=False)
            logging.info("got result {} text {} for message_id {} to {}".format(r.status_code, r.text, message_id, recipient))
            result.append((message_id, recipient, r.status_code, r.text))
        except Exception as e:
            error_message = 'unable to remediate message_id {} to {}: {}'.format(message_id, recipient, str(e))
            logging.error(error_message)
            report_exception()
            result.append((message_id, recipient, 'N/A', str(e)))

    return result

def _unremediate_email_o365_EWS(emails):
    """Remediates the given emails specified by a list of tuples of (message-id, recipient email address)."""
    assert emails
    assert all([len(e) == 2 for e in emails])

    result = [] # tuple(message_id, recipient, result_code, result_text)
    
    # get the hostname and port for our EWS proxy system
    # this system receives requests for remediation and restorations and submits them to EWS on our behalf
    ews_host = saq.CONFIG['remediation']['ews_host']
    ews_port = saq.CONFIG['remediation'].getint('ews_port')

    # the format of each request is a POST to
    # https://host:port/delete
    # with JSON as the POST data content
    
    # note that we make a separate request for each one
    url = 'https://{}:{}/restore'.format(saq.CONFIG['remediation']['ews_host'], saq.CONFIG['remediation']['ews_port'])
    session = requests.Session()
    data = { 'recipient': None, 'message_id': None }
    headers = { 'Content-Type': 'application/json' }
    
    for message_id, recipient in emails:

        try:
            if recipient.startswith('<'):
                recipient = recipient[1:]
            if recipient.endswith('>'):
                recipient = recipient[:-1]

            data['recipient'] = recipient
            data['message_id'] = message_id
            json_data = json.dumps(data)

            logging.info("restoring message_id {} to {}".format(message_id, recipient))
            r = session.post(url, headers=headers, data=json_data, verify=False)
            logging.info("got result {} text {} for message_id {} to {}".format(r.status_code, r.text, message_id, recipient))
            result.append((message_id, recipient, r.status_code, r.text))
        except Exception as e:
            error_message = 'unable to restore message_id {} to {}: {}'.format(message_id, recipient, str(e))
            logging.error(error_message)
            report_exception()
            result.append((message_id, recipient, 'N/A', str(e)))

    return result

def load_phishfry_accounts():
    """Loads phishfry accounts from a configuration file and returns the list of EWS.Account objects."""
    import EWS
    accounts = []
    config = ConfigParser()
    config.read(os.path.join(saq.SAQ_HOME, "etc", "phishfry.ini"))
    timezone = config["DEFAULT"].get("timezone", "UTC")
    for section in config.sections():
        server = config[section].get("server", "outlook.office365.com")
        version = config[section].get("version", "Exchange2016")
        user = config[section]["user"]
        password = config[section]["pass"]
        accounts.append(EWS.Account(user, password, server=server, version=version, timezone=timezone, proxies=saq.PROXIES))

    return accounts

def get_restoration_targets(message_ids):
    """Given a list of message-ids, return a list of tuples of (message_id, recipient)
       suitable for the unremediate_emails command. The values are discovered by 
       querying the remediation table in the database."""

    from saq.database import get_db_connection

    if not message_ids:
        return []

    result = [] # if ( message-id, recipient )

    logging.info("searching for restoration targets for {} message-ids".format(len(message_ids)))
    
    with get_db_connection() as db:
        c = db.cursor()

        for message_id in message_ids:
            # TODO create an email_remediation table that has the indexing for message_id, recipient, etc...
            c.execute("SELECT DISTINCT(`key`) FROM `remediation` WHERE `type` = 'email' AND `action` = 'remove' AND `key` LIKE %s",
                     (f'{message_id}%',))

            for row in c:
                message_id, recipient = row[0].split(':', 1)
                result.append((message_id, recipient))

    return result

def get_remediation_targets(message_ids):
    """Given a list of message-ids, return a list of tuples of (message_id, recipient) 
       suitable for the remediate_emails command."""

    from saq.email import get_email_archive_sections, search_archive

    if not message_ids:
        return []

    result = [] # of ( message-id, recipient )

    logging.info("searching for remediation targets for {} message-ids".format(len(message_ids)))

    # first search email archives for all delivered emails that had this message-id
    for source in get_email_archive_sections():
        search_result = search_archive(source, message_ids, excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(','))
        for archive_id in search_result:
            result.append((search_result[archive_id].message_id, search_result[archive_id].recipient))
            #message_id = search_result[archive_id].message_id
            #recipient = search_result[archive_id].recipient
            #sender = result[archive_id].sender
            #subject = result[archive_id].subject
            #if message_id not in targets:
                #targets[message_id] = { "recipients": {}, "sender": sender, "subject": subject }
            #targets[message_id]["recipients"][recipient] = { "removed": 0, "history": [] }

    #with get_db_connection() as db:
        #c = db.cursor()

        # get remediation history of each target
        #c.execute("""SELECT remediation.key, action, insert_date, username, result, successful, removed
                     #FROM email_remediation
                     #JOIN remediation ON email_remediation.key = remediation.key
                     #JOIN users ON remediation.user_id = users.id
                     #WHERE message_id IN ( {} )
                     #ORDER BY insert_date ASC""".format(','.join(['%s' for _ in message_ids])), tuple(message_ids))
        #for row in c:
            #key, action, insert_date, user, result, successful, removed = row
            #message_id, recipient = key.split(':')
            #if recipient not in targets[message_id]['recipients']:
                ###targets[message_id]['recipients'][recipient] = { "removed": 0, "history": [] }
            #targets[message_id]['recipients'][recipient]["removed"] = removed targets[message_id]['recipients'][recipient]["history"].append({"action":action, "insert_date":insert_date, "user":user, "result":result, "successful":successful})
#
    logging.info("found {} remediation targets for {} message-ids".format(len(result), len(message_ids)))
    return result

def _execute_phishfry_remediation(action, emails):

    result = [] # tuple(message_id, recipient, result_code, result_text)

    for message_id, recipient in emails:
        found_recipient = False
        for account in load_phishfry_accounts():
            #if recipient.startswith('<'):
                #recipient = recipient[1:]
            #if recipient.endswith('>'):
                #recipient = recipient[:-1]

            logging.info(f"attempting to {action} message-id {message_id} for {recipient}")
            if not saq.UNIT_TESTING:
                pf_result = account.Remediate(action, recipient, message_id)
            else:
                # for unit testing we want to fake the results of the remediation attempt
                # fake the results of the remediation attempt
                pf_result = None # TODO

            logging.info(f"got {action} result {pf_result} for message-id {message_id} for {recipient}")

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

                    messages.append('({}) {} {} ({})'.format(
                                    200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ] else 500,
                                    discovery_method,
                                    pf_recipient,
                                    pf_result[pf_recipient].message))
                
                message = pf_result[pf_recipient].message
                if messages:
                    message += '\n' + '\n'.join(messages)

                result.append((pf_result[recipient].message_id,
                               recipient,
                               200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ] else 500,
                               message))

                # we found the recipient in this acount so we don't need to keep looking
                break

        # did we find it?
        if not found_recipient:
            logging.warning(f"could not find message-id {message_id} sent to {recipient}")
            result.append((message_id,
                           recipient,
                           500,
                           "cannot find email"))

    return result

def _remediate_email_phishfry(*args, **kwargs):
    return _execute_phishfry_remediation(ACTION_REMEDIATE, *args, **kwargs)

def _unremediate_email_phishfry(*args, **kwargs):
    return _execute_phishfry_remediation(ACTION_RESTORE, *args, **kwargs)

def _process_email_remediation_results(action, user_id, comment, results):
    with get_db_connection() as db:
        c = db.cursor()
        for result in results:
            message_id, recipient, result_code, result_text = result
            result_text = '({}) {}'.format(result_code, result_text)
            result_success = str(result_code) == '200'
            c.execute("""INSERT INTO remediation ( `type`, `action`, `user_id`, `key`, 
                                                   `result`, `comment`, `successful`, `status` ) 
                         VALUES ( 'email', %s, %s, %s, %s, %s, %s, %s )""", (
                      action,
                      user_id,
                      f'{message_id}:{recipient}',
                      result_text,
                      comment,
                      result_success,
                      REMEDIATION_STATUS_COMPLETED))

        db.commit()
    
def remediate_emails(*args, user_id=None, comment=None, **kwargs):
    assert user_id

    #if use_phishfry:
        #results = _execute_phishfry_remediation(ACTION_REMEDIATE, *args, **kwargs)
    #else:
        #results = _remediate_email_o365_EWS(*args, **kwargs)

    results = _remediate_email_o365_EWS(*args, **kwargs)
    _process_email_remediation_results(ACTION_REMEDIATE, user_id, comment, results)
    return results

def unremediate_emails(*args, user_id=None, comment=None, **kwargs):
    assert user_id

    #if use_phishfry:
        #results = _execute_phishfry_remediation(ACTION_RESTORE, *args, **kwargs)
    #else:

    results = _unremediate_email_o365_EWS(*args, **kwargs)
    _process_email_remediation_results(ACTION_RESTORE, user_id, comment, results)
    return results

def execute_remediation(remediation):
    from saq.database import Remediation

    message_id, recipient = remediation.key.split(':', 2)
    results = remediate_emails((message_id, recipient), user_id=remediation.user_id, comment=remediation.comment)
    for result in results:
        message_id, recipient, result_code, result_text = result
        result_text = '({}) {}'.format(result_code, result_text)
        result_success = str(result_code) == '200'
        saq.db.execute(Remediation.__table__.update().values(
            result=text_text, successful=result_success).where(
            Remediation.id == remediation.id))
        saq.db.commit()

def _insert_email_remediation_object(action, message_id, recipient, user_id, company_id, comment=None):
    from saq.database import Remediation
    remediation = Remediation(
        type=REMEDIATION_TYPE_EMAIL,
        action=action,
        user_id=user_id,
        key=f'{message_id}:{recipient}',
        comment=comment,
        company_id=company_id)

    saq.db.add(remediation)
    saq.db.commit()
    logging.info(f"user {user_id} added remediation request for message_id {message_id} recipient {recipient}")
    return True

def request_email_remediation(*args, **kwargs):
    return _insert_email_remediation_object(REMEDIATION_ACTION_REMOVE, *args, **kwargs)

def request_email_restoration(*args, **kwargs):
    return _insert_email_remediation_object(REMEDIATION_ACTION_RESTORE, *args, **kwargs)

def remediate_phish(alerts):
    """Attempts to remediate the given Alert objects.  Returns a tuple of (success_count, total)"""
    # make sure we can load all of the alerts
    for alert in alerts:
        if not alert.load():
            raise RuntimeError("unable to load alert {}".format(str(alert)))

        # hard coded type
        # XXX would like to map types to remediation functions to call in aggregate
        if alert.alert_type != 'brotex - smtp - v2' and alert.alert_type != 'mailbox':
            raise RuntimeError("alert {} is not a support alert type of phishing remediation".format(str(alert)))

    emails = [] # list of dicts returned by _create_remediation_email
    brotex_alert_count = 0 # keep track of how many brotex alerts we're remediating

    #
    # Office365 EWS Proxy Remediation
    #

    from saq.modules.email import EmailAnalysis, KEY_MESSAGE_ID, KEY_ENV_RCPT_TO, KEY_TO
    targets = [] # of tuple(message_id, recipient)
    results = {} # key = alert.uuid, value = str

    for alert in alerts:
        email_file = None
        for o in alert.observables:
            if o.type == F_FILE and (o.has_directive(DIRECTIVE_ORIGINAL_EMAIL) or o.value.endswith('email.rfc822')):
                email_file = o
                break

        if email_file is None:
            logging.warning("expected a single file observable in the alert for email remediation, "
                            "but got {}".format(len(email_file)))
            results[alert.uuid] = 'unexpected F_FILE type observables in main alert'
            continue

        # then get the EmailAnalysis for this email
        analysis = email_file.get_analysis(EmailAnalysis)
        if not analysis:
            loggging.warning("cannot get EmailAnalysis for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find email analysis'
            continue

        message_id = None
        env_rcpt_to = None
        mail_to = None
        recipient = None

        if KEY_MESSAGE_ID in analysis.email:
            message_id = analysis.email[KEY_MESSAGE_ID]

        if KEY_ENV_RCPT_TO in analysis.email:
            env_rcpt_to = analysis.email[KEY_ENV_RCPT_TO]
        # if we didn't find it there then look in the main alert
        # XXX I really don't how all this information is all over the place
        elif 'envelope rcpt to' in alert.details:
            env_rcpt_to = alert.details['envelope rcpt to']
            if isinstance(env_rcpt_to, str):
                env_rcpt_to = [env_rcpt_to]

        if KEY_TO in analysis.email:
            mail_to = analysis.email[KEY_TO]

        if not message_id:
            logging.error("cannot find Message-ID for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find Message-ID'
            continue

        if env_rcpt_to:
            recipient = env_rcpt_to[0] # there should only be one
            logging.debug("using env_rcpt_to value {} as recipient for {} in {}".format(recipient, email_file, alert))
        elif mail_to:
            recipient = mail_to[0] # XXX I need to look at all of them and pull out the one that matches a domain we own
            logging.debug("using mail_to value {} as recipient for {} in {}".format(recipient, email_file, alert))

        if not recipient:
            logging.error("cannot determine recipient for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot determine recipient'
            continue

        targets.append((message_id, recipient))

    result = _remediate_email_o365_EWS(targets)
    success_count = 0
    messages = [] # of str
    for message_id, recipient, result_code, result_text in result:
        if result_code == 200:
            success_count += 1

            # on 1/9/2017 we changed the format of the output
            # the result_text is now a JSON array [ {"address": EMAIL_ADDRESS, "code": CODE, "message": MESSAGE }, ... ]
            decoded_result_text = json.loads(result_text)
            for entry in decoded_result_text:
                messages.append('message-id {} to {} error code {} message {}'.format(
                                message_id, entry['address'], entry['code'], entry['message']))
        else:
            messages.append('message-id {} to {} error code {} message {}'.format(message_id, recipient, result_code, result_text))

    messages.insert(0, 'remediated {} out of {} emails from office365'.format(success_count, len(alerts)))
    return messages

def unremediate_phish(alerts):
    # make sure we can load all of the alerts
    for alert in alerts:
        if not alert.load():
            raise RuntimeError("unable to load alert {}".format(str(alert)))

        # hard coded type
        # XXX would like to map types to remediation functions to call in aggregate
        if alert.alert_type != 'brotex - smtp - v2' and alert.alert_type != 'mailbox':
            raise RuntimeError("alert {} is not a support alert type of phishing remediation".format(str(alert)))

    #
    # Office365 EWS Proxy Remediation
    #

    from saq.modules.email import EmailAnalysis, KEY_MESSAGE_ID, KEY_ENV_RCPT_TO, KEY_TO
    targets = [] # of tuple(message_id, recipient)
    results = {} # key = alert.uuid, value = str

    for alert in alerts:
        # the two types of alerts that support this will have a single F_FILE observable in the Alert itself
        email_file = [o for o in alert.observables if o.type == F_FILE]
        if len(email_file) != 1:
            logging.warning("expected a single file observable in the alert for email remediation, "
                            "but got {}".format(len(email_file)))
            results[alert.uuid] = 'unexpected F_FILE type observables in main alert'
            continue

        email_file = email_file[0]
        # then get the EmailAnalysis for this email
        analysis = email_file.get_analysis(EmailAnalysis)
        if not analysis:
            loggging.warning("cannot get EmailAnalysis for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find email analysis'
            continue

        message_id = None
        env_rcpt_to = None
        mail_to = None
        recipient = None

        if KEY_MESSAGE_ID in analysis.email:
            message_id = analysis.email[KEY_MESSAGE_ID]

        if KEY_ENV_RCPT_TO in analysis.email:
            env_rcpt_to = analysis.email[KEY_ENV_RCPT_TO]
        # if we didn't find it there then look in the main alert
        # XXX I really don't how all this information is all over the place
        elif 'envelope rcpt to' in alert.details:
            env_rcpt_to = alert.details['envelope rcpt to']
            if isinstance(env_rcpt_to, str):
                env_rcpt_to = [env_rcpt_to]

        if KEY_TO in analysis.email:
            mail_to = analysis.email[KEY_TO]

        if not message_id:
            logging.error("cannot find Message-ID for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find Message-ID'
            continue

        if env_rcpt_to:
            recipient = env_rcpt_to[0] # there should only be one
            logging.debug("using env_rcpt_to value {} as recipient for {} in {}".format(recipient, email_file, alert))
        elif mail_to:
            recipient = mail_to[0]
            logging.debug("using mail_to value {} as recipient for {} in {}".format(recipient, email_file, alert))

        if not recipient:
            logging.error("cannot determine recipient for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot determine recipient'
            continue

        targets.append((message_id, recipient))

    result = _unremediate_email_o365_EWS(targets)
    success_count = 0
    messages = [] # of str
    for message_id, recipient, result_code, result_text in result:
        if result_code == 200:
            success_count += 1

        messages.append('message-id {} to {} error code {} message {}'.format(message_id, recipient, result_code, result_text))

    messages.insert(0, 'restored {} out of {} emails from office365'.format(success_count, len(alerts)))
    return messages

#
# the global remediation system
# this is created using the initialize_remediation_system_manager() function
# 

REMEDIATION_SYSTEM_MANAGER = None

def request_remediation(remediation_type, *args, **kwargs):
    if REMEDIATION_SYSTEM_MANAGER is None:
        logging.error("request_remediation called before initialize_remediation_system_manager is called")
        return None

    return REMEDIATION_SYSTEM_MANAGER.request_remediation(remediation_type, *args, **kwargs)

def request_restoration(remediation_type, *args, **kwargs):
    if REMEDIATION_SYSTEM_MANAGER is None:
        logging.error("request_restoration called before initialize_remediation_system_manager is called")
        return None

    return REMEDIATION_SYSTEM_MANAGER.request_restoration(remediation_type, *args, **kwargs)

class RemediationSystemManager(object):
    def __init__(self):
        # the list of remediation systems this is managing
        self.systems = {} # key = remediation_type, value = RemediationSystem
        self.load_remediation_systems()

    def start(self, *args, **kwargs):
        for type, system in self.systems.items():
            system.start(*args, **kwargs)

    def stop(self, *args, **kwargs):
        for type, system in self.systems.items():
            system.stop(*args, **kwargs)

    def wait(self, *args, **kwargs):
        for type, system in self.systems.items():
            system.wait(*args, **kwargs)

    def request_remediation(self, remediation_type, *args, **kwargs):
        try:
            return self.systems[remediation_type].request_remediation(*args, **kwargs)
        except KeyError as e:
            logging.error(f"requested unknown remediation type {remediation_type}")
            raise e

    def request_restoration(self, remediation_type, *args, **kwargs):
        try:
            return self.systems[remediation_type].request_restoration(*args, **kwargs)
        except KeyError as e:
            logging.error(f"requested unknown remediation type {remediation_type}")
            raise e

    def load_remediation_systems(self):
        for section_name in saq.CONFIG.keys():
            if not section_name.startswith('remediation_system_'):
                continue

            name = section_name[len('remediation_system_'):]

            if not saq.CONFIG[section_name].getboolean('enabled'):
                logging.debug(f"remediation system {name} is disabled")
                continue

            module_name = saq.CONFIG[section_name]['module']
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error(f"unable to import module {module_name}: {e}")
                report_exception()
                continue

            class_name = saq.CONFIG[section_name]['class']
            try:
                _class = getattr(_module, class_name)
            except AttributeError as e:
                logging.error(f"class {class_name} does not exist in module {module_name} in remediation system {name}")
                report_exception()
                continue

            try:
                logging.debug(f"loading remediation system {name}")
                remediation_system = _class(batch_size=saq.CONFIG[section_name].getint('batch_size', fallback=None),
                                            message_on_success=saq.CONFIG[section_name].getboolean('message_on_success', fallback=False),
                                            message_on_error=saq.CONFIG[section_name].getboolean('message_on_error', fallback=False))

                if remediation_system.remediation_type in self.systems:
                    logging.error(f"multiple remediations systems are defined for the type {remediation_system.remediation_type}")
                    continue

                self.systems[remediation_system.remediation_type] = remediation_system
                logging.debug(f"loaded remediation system {name} supporting remediation type {remediation_system.remediation_type}")

            except Exception as e:
                logging.error(f"unable to load remediation system {name}: {e}")
                report_exception()
                continue

class RemediationSystem(object):
    def __init__(self, batch_size=10, message_on_success=None, message_on_error=None):

        # the queue that contains the current Remediation object to work on
        self.queue = None

        # the thread the reads the work to be done and adds it to the queue
        self.manager_thread = None

        # the list of worker threads that perform the work added to the queue
        self.worker_threads = []

        # control event to shut the remediation system down (gracefully)
        self.control_event = None

        # the UUID used to lock remediation items for ownership
        self.lock = None

        # the total number of remediation items this system will lock at once
        self.batch_size = batch_size

        # defines message targets 
        self.message_on_success = message_on_success
        self.message_on_error = message_on_error

    @property
    def remediation_type(self):
        """The type of remediations this system provides."""
        raise NotImplementedError()

    def execute_request(self, remediation):
        raise NotImplementedError()

    def request_remediation(self, *args, **kwargs):
        return self._insert(*args, action=REMEDIATION_ACTION_REMOVE, type=self.remediation_type, **kwargs)

    def request_restoration(self, *args, **kwargs):
        return self._insert(*args, action=REMEDIATION_ACTION_RESTORE, type=self.remediation_type, **kwargs)

    def execute_remediation(self, *args, **kwargs):
        from saq.database import Remediation

        # create a locked remediation entry so any currently running remediation systems don't grab it
        remediation_id = self.request_remediation(*args, 
                                                  lock=str(uuid.uuid4()), 
                                                  lock_time=datetime.datetime.now(), 
                                                  **kwargs)
        self.execute_request(saq.db.query(Remediation).filter(Remediation.id == remediation_id).one())
        return saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()

    def execute_restoration(self, *args, **kwargs):
        from saq.databased import Remediation

        # create a locked remediation entry so any currently running remediation systems don't grab it
        remediation_id = self.request_restoration(*args, 
                                                  lock=str(uuid.uuid4()), 
                                                  lock_time=datetime.datetime.now(), 
                                                  **kwargs)
        self.execute_request(saq.db.query(Remediation).filter(Remediation.id == remediation_id).one())
        return saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()

    def _insert(self, type, action, user_id, key, company_id, 
                comment=None, lock=None, lock_time=None, status=REMEDIATION_STATUS_NEW):

        from saq.database import Remediation

        remediation = Remediation(
            type=type,
            action=action,
            user_id=user_id,
            key=key,
            comment=comment,
            company_id=company_id,
            lock=lock,
            lock_time=lock_time,
            status=status)

        saq.db.add(remediation)
        saq.db.commit()
        logging.info(f"added remediation request {remediation}")
        return remediation.id

    #
    # automation routines

    def start(self):
        # grab the lock uuid used last time, or, create a new one
        lock_uuid_path = os.path.join(saq.DATA_DIR, 'var', 'remediation.uuid')
        if os.path.exists(lock_uuid_path):
            try:
                with open(lock_uuid_path) as fp:
                    self.lock = fp.read()
                    validate_uuid(self.lock)
            except Exception as e:
                logging.warning(f"unable to read {lock_uuid_path} - recreating")
                self.lock = None

        if self.lock is None:
            with open(lock_uuid_path, 'w') as fp:
                self.lock = str(uuid.uuid4())
                fp.write(self.lock)

        from saq.database import Remediation

        # reset any outstanding work set to this uuid
        # this would be stuff left over from the last time it shut down
        saq.db.execute(Remediation.__table__.update().values(
            status=REMEDIATION_STATUS_NEW,
            lock=None,
            lock_time=None).where(and_(
            Remediation.lock == self.lock,
            or_(
                Remediation.status == REMEDIATION_STATUS_NEW, 
                Remediation.status == REMEDIATION_STATUS_IN_PROGRESS))))

        saq.db.commit()
        
        self.queue = queue.Queue(maxsize=1)
        self.control_event = threading.Event()

        # start the workers first so they can start reading the the queue
        for index in range(saq.CONFIG['engine'].getint('max_concurrent_remediation_count')):
            worker_thread = threading.Thread(target=self.worker_loop, name=f"Remediation Worker #{index}")
            worker_thread.start()
            self.worker_threads.append(worker_thread)

        self.manager_thread = threading.Thread(target=self.manager_loop, name="Remediation Manager")
        self.manager_thread.start()

    def stop(self, wait=True):
        self.control_event.set()
        if wait:
            self.wait()

    def wait(self):
        for t in self.worker_threads:
            logging.debug(f"waiting for {t} to stop...")
            t.join()

        logging.debug("waiting for {self.manager_thread} to stop...")
        self.manager_thread.join()

    def manager_loop(self):
        logging.debug("remediation manager loop started")
        while not self.control_event.is_set():
            try:
                sleep_time = self.manager_execute()
            except Exception as e:
                sleep_time = 10 # we'll wait a bit longer if something is broken
                logging.error(f"uncaught exception {e}")
                report_exception()
            finally:
                # since we are doing SQL operations we need to make sure these
                # are closed after each iteration
                saq.db.close()

            self.control_event.wait(sleep_time)

        logging.debug("remediation manager loop exiting")

    def manager_execute(self):
        from saq.database import Remediation

        # start putting whatever is available
        locked_workload = saq.db.query(Remediation).filter(and_(
            Remediation.lock == self.lock,
            Remediation.status == REMEDIATION_STATUS_NEW)).order_by(
            asc(Remediation.id)).all() # there will only be self.batch_size so the all() call should be OK

        saq.db.expunge_all()
        saq.db.commit()

        for remediation in locked_workload:
            try:
                # mark the work item as currently be processed
                saq.db.execute(Remediation.__table__.update().values(status=REMEDIATION_STATUS_IN_PROGRESS).where(Remediation.id == remediation.id))
                saq.db.commit()
            except Exception as e:
                logging.error(f"unable to set status of remediation item {remediation.id} to {REMEDIATION_STATUS_IN_PROGRESS}: {e}")
                saq.db.rollback()
                continue

            # this loop will not exit until we are shutting down or the item is grabbed for processing
            while not self.control_event.is_set():
                try:
                    self.queue.put(remediation, block=True, timeout=1)
                    break
                except queue.Full:
                    continue

        # lock more work to do
        # get a list of the first N items that are lockable
        # typically this would be part of a subquery but we're using MySQL
        target_ids = saq.db.query(Remediation.id).filter(and_(
            Remediation.type == self.remediation_type,
            Remediation.company_id == saq.COMPANY_ID,
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW))\
            .order_by(asc(Remediation.id))\
            .limit(self.batch_size)\
            .all()

        if not target_ids:
            return 3 # if we didn't get anything then we wait 3 seconds to try again

        # gather the ids into a list
        target_ids = [_[0] for _ in target_ids]
        
        result = saq.db.execute(Remediation.__table__.update().values(
            lock=self.lock,
            lock_time=func.now()).where(and_(
            Remediation.id.in_(target_ids),
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW)))

        saq.db.commit()

        if result.rowcount == 0:
            # execute again but wait a few seconds
            return 3 # do we need to make this configurable?

        # execute again (don't wait)
        return 0

    def worker_loop(self):
        logging.debug("remediation worker started")
        while not self.control_event.is_set():
            try:
                sleep_time = self.worker_execute()
            except Exception as e:
                sleep_time = 30
                logging.error(f"uncaught exception {e}")
                report_exception()
            finally:
                saq.db.close()

            self.control_event.wait(sleep_time)

        logging.debug("remediation worker exited")

    def worker_execute(self):
        # get the next remediation request from the queue
        try:
            remediation = self.queue.get(block=True, timeout=2)
        except queue.Empty:
            return 0 # the get on the queue is what blocks

        # execute this remediation
        try:
            remediation_result = self.execute_request(remediation)
            if remediation_result is None:
                raise RuntimeError("forgot to return remediation object in execute_request")

            alert_references = []
            for alert_uuid in remediation_result.alert_uuids:
                alert_references.append("referencing alert: {}analysis?direct={}".format(saq.CONFIG['gui']['base_uri'], alert_uuid))

            if alert_references:
                alert_references = '\n' + '\n'.join(alert_references)
            else:
                alert_references = ""

            if remediation_result.successful and self.message_on_success:
                try:
                    send_message(f"remediation for {remediation_result.key} completed: {remediation_result.result}{alert_references}", MESSAGE_TYPE_REMEDIATION_SUCCESS)
                except Exception as e:
                    logging.error(f"unable to send completed message: {e}")

            elif not remediation_result.successful and self.message_on_error:
                try:
                    send_message(f"<!channel> :rotating_light: remediation for {remediation_result.key} failed:\n{remediation_result.result}{alert_references}", MESSAGE_TYPE_REMEDIATION_SUCCESS)
                except Exception as e:
                    logging.error(f"unable to send completed message: {e}")

            saq.db.execute(Remediation.__table__.update().values(
                status = REMEDIATION_STATUS_COMPLETED,
                successful = remediation_result.successful,
                result = remediation_result.result).where(
                Remediation.id == remediation_result.id))
            saq.db.commit()
    
        except Exception as e:
            logging.error(f"unable to execute remediation item {remediation.id}: {e}")
            report_exception()
            
            try:
                saq.db.execute(Remediation.__table__.update().values(
                    status=REMEDIATION_STATUS_COMPLETED,
                    successful=False,
                    result=str(e))\
                .where(Remediation.id == remediation.id))
                saq.db.commit()

                if self.message_on_error:
                    send_message(f"<!channel> :rotating_light: attempt to execute remediation {remediation.key} failed:\n{e}{alert_references}", MESSAGE_TYPE_REMEDIATION_FAILURE)
                    
            except Exception as e:
                logging.error(f"unable to record error for remediation item {remediation.id}: {e}")
                report_exception()

            return

class EmailRemediationSystem(RemediationSystem):
    @property
    def remediation_type(self):
        return REMEDIATION_TYPE_EMAIL

    def request_remediation(self, message_id, recipient, *args, **kwargs):
        return RemediationSystem.request_remediation(
            self,
            *args, 
            key=f'{message_id}:{recipient}', 
            **kwargs)

    def request_restoration(self, message_id, recipient, *args, **kwargs):
        return RemediationSystem.request_restoration(
            self,
            *args, 
            key=f'{message_id}:{recipient}', 
            **kwargs)

class LogOnlyRemdiationSystem(EmailRemediationSystem):
    """Dummy class that simply logs the request and marks it as completed."""
    def execute_request(self, remediation):
        logging.info(f"execution remediation {remediation}")
        message_id, recipient = remediation.key.split(':', 1)

        if 'fail' in message_id:
            raise 

        remediation.status = REMEDIATION_STATUS_COMPLETED
        remediation.successful = True
        remediation.result = 'executed by LogOnlyRemediationSystem'

        logging.info(f"completed remediation request {remediation}")
        return remediation

def initialize_remediation_system_manager(*args, **kwargs):
    global REMEDIATION_SYSTEM_MANAGER

    from saq.messaging import initialize_message_system
    initialize_message_system()

    REMEDIATION_SYSTEM_MANAGER = RemediationSystemManager(*args, **kwargs)
    return REMEDIATION_SYSTEM_MANAGER

def start_remediation_system_manager(*args, **kwargs):
    if REMEDIATION_SYSTEM_MANAGER is None:
        logging.error("called start_remediation_system_manager before initialize_remediation_system_manager")
        return None

    REMEDIATION_SYSTEM_MANAGER.start(*args, **kwargs)

def stop_remediation_system_manager(*args, **kwargs):
    if REMEDIATION_SYSTEM_MANAGER is None:
        logging.error("called stop_remediation_system_manager before initialize_remediation_system_manager")
        return None

    REMEDIATION_SYSTEM_MANAGER.stop(*args, **kwargs)

def wait_remediation_system_manager(*args, **kwargs):
    if REMEDIATION_SYSTEM_MANAGER is None:
        logging.error("called wait_remediation_system_manager before initialize_remediation_system_manager")
        return None

    REMEDIATION_SYSTEM_MANAGER.wait(*args, **kwargs)
