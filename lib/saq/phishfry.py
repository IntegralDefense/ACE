from configparser import ConfigParser
import EWS
from flask_login import current_user
import os
import saq
from saq import SAQ_HOME
import saq.constants
from saq.database import get_db_connection
from saq.email import get_remediation_targets

def get_config_var(config, section, key, default=None):
    if section in config and key in config[section] and config[section][key]:
        return config[section][key]
    elif default is not None:
        return default
    raise Exception("Missing required config variable config[{}][{}]".format(section, key))

def remediate_targets(action, targets):
    assert action in [ 'restore', 'remove' ];
    result_targets = {}

    with get_db_connection() as db:
        c = db.cursor()

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
            accounts.append(EWS.Account(user, password, server=server, version=version, timezone=timezone, proxies=saq.PROXIES))

        # warn if no EWS accounts are configured
        if len(accounts) == 0:
            raise Exception("No configured EWS remediation accounts")

        for message_id in targets:
            for recipient in targets[message_id]["recipients"]:
                # skip targets that were already handle via spidering
                if message_id in result_targets and recipient in result_targets[message_id]['recipients']:
                    continue

                # skip targets that are already the way we want them
                removed = targets[message_id]['recipients'][recipient]['removed']
                if (action == 'remove' and removed) or (action == 'restore' and not removed):
                    if message_id not in result_targets:
                        result_targets[message_id] = { "recipients": {}, "sender": targets[message_id]["sender"], "subject": targets[message_id]["subject"] }
                    result_targets[message_id]["recipients"][recipient] = { "action": action, "result": "already {}d".format(action), "success": True }
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
                    if message_id not in result_targets:
                        result_targets[message_id] = { "recipients": {}, "sender": targets[message_id]["sender"], "subject": targets[message_id]["subject"] }
                    result_targets[message_id]["recipients"][address] = { "action": action, "result": results[address].message, "success": results[address].success }

                    new_removed = 0
                    if address in targets[message_id]['recipients']:
                        new_removed = targets[message_id]['recipients'][address]['removed']
                    if results[address].success:
                        new_removed = 1 if action == 'remove' else 0
                                        
                    c.execute("""INSERT INTO remediation ( `type`, `action`, `user_id`, `key`, `result`, `successful` ) 
                                 VALUES ( 'email', %s, %s, %s, %s, %s )""", (
                                action,
                                current_user.id,
                                message_id + ':' + address,
                                results[address].message,
                                results[address].success))

                    c.execute("""INSERT INTO email_remediation ( `message_id`, `key`, `removed` )
                                 VALUES ( %s, %s, %s ) ON DUPLICATE KEY UPDATE `removed`=%s""", (
                                message_id,
                                message_id + ":" + address,
                                new_removed,
                                new_removed))

        # commit changes to remediation history
        db.commit()
    
    return result_targets
