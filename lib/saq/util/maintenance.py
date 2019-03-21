# vim: sw=4:ts=4:et
import datetime
import os.path
import logging
import shutil

import saq

def cleanup_alerts(fp_days_old=None, ignore_days_old=None, dry_run=False):
    """Cleans up the alerts stored in the ACE system. 
       Alerts dispositioned as FALSE_POSITIVE are archived (see :method:`saq.database.Alert.archive`)
       Alerts dispositioned as IGNORE as deleted.
       This is intended to be called from an external maintenance script.

       :param int fp_days_old: By default the age of the alerts to be considered for cleanup
       is stored in the configuration file. Setting this overrides these settings.
       :param int ignore_days_old: By default the age of the alerts to be considered for cleanup
       is stored in the configuration file. Setting this overrides these settings.
       :param bool dry_run: Setting this to True will simply print the number of alerts would
       be archived and deleted. Defaults to False.
    """

    import gc
    import weakref

    from saq.constants import DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE
    from saq.database import Alert, DatabaseSession, retry_sql_on_deadlock

    from sqlalchemy.sql.expression import select, delete

    ignore_days = saq.CONFIG['global'].getint('ignore_days')
    fp_days = saq.CONFIG['global'].getint('fp_days')

    if fp_days_old:
        fp_days = fp_days_old

    if ignore_days_old:
        ignore_days = ignore_days_old

    # delete alerts dispositioned as IGNORE and older than N days
    dry_run_count = 0
    for storage_dir, alert_id in saq.db.execute(select([Alert.storage_dir, Alert.id])
        .where(Alert.location == saq.CONFIG['global']['node'])
        .where(Alert.disposition == DISPOSITION_IGNORE)
        .where(Alert.disposition_time < datetime.datetime.now() - datetime.timedelta(days=ignore_days))):

        if dry_run:
            dry_run_count += 1
            continue

        # delete the files backing the alert
        try:
            target_path = os.path.join(saq.SAQ_HOME, storage_dir)
            logging.info(f"deleting files {target_path}")
            shutil.rmtree(target_path)
        except Exception as e:
            logging.error(f"unable to delete alert storage directory {storage_dir}: {e}")

        # delete the alert from the database
        logging.info(f"deleting database entry {alert_id}")
        retry_sql_on_deadlock(delete(Alert).where(Alert.id == alert_id), commit=True)

    if dry_run:
        logging.info(f"{dry_run_count} ignored alerts would be deleted")

    # archive alerts dispositioned as False Positive older than N days
    dry_run_count = 0
    for alert in saq.db.query(Alert).filter(
        Alert.location == saq.CONFIG['global']['node'],
        Alert.archived == False,
        Alert.disposition == DISPOSITION_FALSE_POSITIVE,
        Alert.disposition_time < datetime.datetime.now() - datetime.timedelta(days=fp_days)):
    
        if dry_run:
            dry_run_count += 1
            continue

        logging.info(f"resetting false positive {alert}")

        try:
            alert.load()
        except Exception as e:
            logging.error(f"unable to load {alert}: {e}")
            continue

        alert.archive()
        alert.sync()
        
    if dry_run:
        logging.info(f"{dry_run_count} fp alerts would be archived")
