# vim: sw=4:ts=4:et
# utility functions to report errors

import logging
import os
import os.path
import shutil
import smtplib
import sys
import traceback

from datetime import datetime
from email.mime.text import MIMEText
from subprocess import Popen, PIPE

import saq

def report_exception():
    import saq.engine

    _, reported_exception, _ = sys.exc_info()

    # spit it out to stdout first
    if saq.DUMP_TRACEBACKS:
        traceback.print_exc()

    try:
        output_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['global']['error_reporting_dir'])
        #if not os.path.exists(output_dir):
            #try:
                #os.makedirs(output_dir)
            #except Exception as e:
                #logging.error("unable to create directory {}: {}".format(output_dir, str(e)))
                #return

        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        with open(error_report_path, 'w') as fp:
            if saq.engine.CURRENT_ENGINE:
                fp.write("CURRENT ENGINE: {}\n".format(saq.engine.CURRENT_ENGINE))
                fp.write("CURRENT ANALYSIS TARGET: {}\n".format(saq.engine.CURRENT_ENGINE.root))

            fp.write("EXCEPTION\n")
            fp.write(str(reported_exception))
            fp.write("\n\nSTACK TRACE\n")
            fp.write(traceback.format_exc())

        return error_report_path

        #if saq.engine.CURRENT_ENGINE and saq.engine.CURRENT_ENGINE.root:
            #if os.path.isdir(saq.engine.CURRENT_ENGINE.root.storage_dir):
                #analysis_dir = '{}.ace'.format(error_report_path)
                #try:
                    #shutil.copytree(saq.engine.CURRENT_ENGINE.root.storage_dir, analysis_dir)
                    #logging.warning("copied analysis from {} to {} for review".format(saq.engine.CURRENT_ENGINE.root.storage_dir, analysis_dir))
                #except Exception as e:
                    #logging.error("unable to copy from {} to {}: {}".format(saq.engine.CURRENT_ENGINE.root.storage_dir, analysis_dir, e))

        # do we send an email?
        #email_addresses = [x.strip() for x in saq.CONFIG['global']['error_reporting_email'].split(',') if x.strip() != '']
        #if len(email_addresses) > 0:
            #try:
                #email_message = 'From: {0}\r\nTo: {1}\r\nSubject: {2}\r\n\r\n{3}'.format(
                    #saq.CONFIG['smtp']['mail_from'],
                    #', '.join(email_addresses), 
                    #'ACE Exception Reported',
                    #str(reported_exception) + '\n\n' + traceback.format_exc())
                #server = smtplib.SMTP(saq.CONFIG['smtp']['server'])
                #server.sendmail(saq.CONFIG['smtp']['mail_from'], email_addresses, email_message)
                #server.quit()
            #except Exception as e:
                #logging.error("unable to send email: {0}".format(str(e)))

    except Exception as e:
        logging.error("uncaught exception we reporting an exception: {}".format(e))

# we don't want to spam conditions so we keep track of when was the last time we sent an alert about a given condition
condition_history = dict() # key = condition (str), value = datetime.timestamp()
# NOTE this is global but not shared by processes
# NOTE we're not clearing these out - probably not going to be a lot of them

def report_condition(condition, details):
    """Reports a condition to an administrator so it can be brought to their attention."""
    assert isinstance(condition, str) 
    assert condition
    assert isinstance(details, str)
    assert details

    # have we already reported this condition in the past N minutes?
    delay = saq.CONFIG['global'].getint('condition_reporting_delay')

    # is condition reporting disabled?
    if not delay:
        return

    delay *= 60 # convert to seconds
    delay = 3

    last_attempt = None
    try:
        last_attempt = datetime.fromtimestamp(condition_history[condition])
    except KeyError:
        pass

    if last_attempt and (datetime.now() - last_attempt).total_seconds() < delay:
        logging.warning("already sent email for condition {}".format(condition))
        return

    try:
        logging.info("sending email for condition {}".format(condition))
        email_message = MIMEText(details)
        email_message['From'] = saq.CONFIG['smtp']['mail_from']
        email_message['To'] = saq.CONFIG['global']['error_reporting_email']
        email_message['Subject'] = 'ACE Condition Reported: {}'.format(condition)
        p = Popen(['/usr/sbin/sendmail', '-t', '-oi'], stdin=PIPE)
        p.communicate(email_message.as_string().encode(errors='ignore'))

        # remember the last time we reported this condition
        condition_history[condition] = datetime.now().timestamp()
        
    except Exception as e:
        logging.error("unable to send email: {}".format(str(e)))
        

