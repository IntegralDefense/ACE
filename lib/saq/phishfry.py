from configparser import ConfigParser
import EWS
import os
import saq
from saq import SAQ_HOME
import saq.constants
from saq.database import get_db_connection
from saq.email import search_archive, get_email_archive_sections

def get_config_var(config, section, key, default=None):
    if section in config and key in config[section] and config[section][key]:
        return config[section][key]
    elif default is not None:
        return default
    raise Exception("Missing required config variable config[{}][{}]".format(section, key))

def remediate_message_ids(action, message_ids):
    assert action in [ 'restore', 'delete' ];
    result_targets = {}
    
    # get info about each target
    targets = {}
    for source in get_email_archive_sections():
        result = search_archive(source, message_ids, excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(','))
        for archive_id in result:
            message_id = result[archive_id].message_id
            if message_id not in targets:
                targets[message_id] = { "recipients": {}, "sender": "Unknown", "subject": "Unknown" }
            targets[message_id]["recipients"][result[archive_id].recipient] = { "remediated": 0, "error": "", "success": True }
            targets[message_id]["sender"] = result[archive_id].sender
            targets[message_id]["subject"] = result[archive_id].subject

    with get_db_connection() as db:
        c = db.cursor()

        # get remediation status of each target
        message_ids_format = ",".join(['%s' for _ in message_ids])
        c.execute("""SELECT message_id, recipient, remediated, error FROM email_remediation
                     WHERE message_id IN ( {} )""".format(message_ids_format), tuple(message_ids))
        for row in c:
            message_id, recipient, remediated, error = row
            message_id = message_id
            targets[message_id]["recipients"][recipient] = { "remediated": remediated, "error": error, "success": True }

        # load ews accounts from phishfry.ini
        accounts = []
        config = ConfigParser()
        config.read(os.path.join(SAQ_HOME, "etc", "phishfry.ini"))
        timezone = get_config_var(config, "DEFAULT", "timezone", default="UTC")
        for section in config.sections():
            server = get_config_var(config, section, "server", default="outlook.office365.com")
            version = get_config_var(config, section, "version", default="Exchange2016")
            user = get_config_var(config, section, "user")
            password = get_config_var(config, section, "pass")
            accounts.append(EWS.Account(user, password, server=server, version=version, timezone=timezone))

        # warn if no EWS accounts are configured
        if len(accounts) == 0:
            raise Exception("No configured EWS remediation accounts")

        # desired status and error message
        desired_status = 1 if action == "delete" else 0
        desired_error = "Remediated" if action == "delete" else "Restored"

        for message_id in targets:
            for recipient in targets[message_id]["recipients"]:
                # skip deleting targets that are already the way we want them
                remediated = targets[message_id]["recipients"][recipient]["remediated"]
                if (action == "delete" and remediated) or (action == "restored" and not remediated):
                    if message_id not in result_targets:
                        result_targets[message_id] = { "recipients": {}, "sender": targets[message_id]["sender"], "subject": targets[message_id]["subject"] }
                    result_targets[message_id]["recipients"][address] = { "remediated": desired_status, "error": desired_error, "success": True }
                    continue

                results = {}
                for account in accounts:
                    # execute the remediation action
                    results = account.Remediate(action, recipient, message_id)

                    # use results from whichever account succesfully resolved the mailbox
                    if results[recipient].mailbox_type != "Unknown":
                        break

                # update remediation history
                for address in results:
                    status = desired_status
                    error = desired_error
                    if not results[address].success:
                        status = remediated if address in targets[message_id]["recipients"] else 0
                        error = results[address].message if status != desired_status else desired_error
                    success = status == desired_status
                    if message_id not in result_targets:
                        result_targets[message_id] = { "recipients": {}, "sender": targets[message_id]["sender"], "subject": targets[message_id]["subject"] }
                    result_targets[message_id]["recipients"][address] = { "remediated": status, "error": error, "success": success }
                    c.execute("""INSERT INTO email_remediation ( `message_id`, `recipient`, `remediated`, `error` )
                                 VALUES ( %s, %s, %s, %s )
                                 ON DUPLICATE KEY UPDATE `remediated` = %s, `error` = %s""", (
                              message_id, address, status, error, status, error))

        # commit changes to remediation history
        db.commit()
    
    return result_targets
