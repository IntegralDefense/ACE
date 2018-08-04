import datetime
import logging
import os
import os.path
import shutil
import socket
import uuid

from urllib.parse import urlparse

import saq

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.email import normalize_email_address
from saq.engine import MySQLCollectionEngine, SSLNetworkServer, submit_sql_work_item
from saq.error import report_exception
from saq.modules.email import BrotexSMTPPackageAnalyzer, BrotexSMTPStreamArchiveAction
from saq.modules.http import BrotexHTTPPackageAnalyzer

alert_type_smtp = 'brotex - {} - v2'.format('smtp')
alert_type_http = 'brotex - {} - v2'.format('http')

class BrotexStreamEngine(SSLNetworkServer, MySQLCollectionEngine):
    """Processes brotex stream files from the pulse sensors."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # if set to True then we don't delete the work directories
        self.keep_work_dir = False

    @property
    def name(self):
        return 'brotex_stream'

    def handle_network_item(self, stream_archive_path):
        # add it to the local workload for processing
        self.add_sql_work_item(stream_archive_path)

    def process(self, stream_archive_path):
        logging.info("processing {}".format(stream_archive_path))

        # format of file name is connection_id.stream_type.tar
        stream_archive_file = os.path.basename(stream_archive_path)

        connection_id, stream_type, _ = stream_archive_file.split('.')
        if connection_id is None:
            logging.error("unable to determine connection_id from {}".format(stream_archive_file))
        if stream_type is None:
            logging.error("unable to determine stream type from {}".format(stream_archive_file))

        # we use a temporary directory while we process the file
        storage_dir = os.path.relpath(os.path.join(self.work_dir, connection_id), start=saq.SAQ_HOME)
        logging.debug("using storage_dir {} for {}".format(storage_dir, stream_archive_file))

        # XXX there seems to be an occasional issue where tar fails on the client side
        # need to investigate and fix that side of it
        # but this works for now
        _count = 0
        _new_storage_dir = storage_dir
        while os.path.exists(_new_storage_dir):
            _new_storage_dir = '{}.{}'.format(storage_dir, _count)
            _count += 1

        storage_dir = _new_storage_dir

        try:
            root = RootAnalysis(storage_dir=storage_dir,
                                tool='ACE - Brotex',
                                tool_instance=socket.gethostname(),
                                alert_type='brotex - {} - v2'.format(stream_type),
                                desc='Brotex {} Stream Detection - {}'.format(stream_type.upper(), connection_id),
                                event_time=datetime.datetime.now())
            root.initialize_storage()

            dest_path = os.path.join(storage_dir, stream_archive_file)
            shutil.copy(stream_archive_path, dest_path)

            file_observable = root.add_observable(F_FILE, os.path.relpath(dest_path, start=root.storage_dir))
            if file_observable:
                file_observable.add_directive(DIRECTIVE_ARCHIVE)
                file_observable.limited_analysis = [ BrotexSMTPPackageAnalyzer.__name__, 
                                                     BrotexHTTPPackageAnalyzer.__name__,
                                                     BrotexSMTPStreamArchiveAction.__name__ ]

            # now analyze the file
            try:
                self.analyze(root)
            except Exception as e:
                logging.error("analysis failed for {}: {}".format(dest_path, e))
                report_exception()

        except Exception as e:
            logging.error("unable to process {}: {}".format(stream_archive_file, e))
            report_exception()

        finally:
            try:
                # delete original stream file
                os.remove(stream_archive_path)
            except Exception as e:
                logging.error("unable to delete file {0}: {1}".format(stream_archive_path, str(e)))
                report_exception()

            # delete the work directory
            if os.path.isdir(root.storage_dir):
                try:
                    shutil.rmtree(root.storage_dir)
                except Exception as e:
                    logging.error("unable to delete {}: {}".format(root.storage_dir, e))
                    report_exception()

    def post_analysis(self, root):
        # what we do here depends on the type of the stream
        if root.alert_type == alert_type_smtp:
            self.post_smtp_analysis(root)
        elif root.alert_type == alert_type_http:
            self.post_http_analysis(root)
        else:
            logging.error("unknown alert type {}".format(root.alert_type))

    def post_http_analysis(self, root):

        from saq.modules.http import BrotexHTTPPackageAnalysis, \
                                     KEY_TIME, \
                                     KEY_SRC_IP, \
                                     KEY_SRC_PORT, \
                                     KEY_DEST_IP, \
                                     KEY_DEST_PORT, \
                                     KEY_METHOD, \
                                     KEY_HOST, \
                                     KEY_URI, \
                                     KEY_REFERRER, \
                                     KEY_USER_AGENT, \
                                     KEY_STATUS_CODE, \
                                     KEY_FILES

        # get the paths to the http scanning system
        #http_scanner_dir = saq.CONFIG['engine_http_scanner']['collection_dir']
        http_scanner_dir = self.collection_dir

        analysis = None
        for a in root.all_analysis:
            if isinstance(a, BrotexHTTPPackageAnalysis) and a.requests:
                analysis = a
                break

        # this can happen if the request was whitelisted
        if analysis:
            for request in analysis.requests:
                subroot = RootAnalysis()
                subroot.company_name = root.company_name
                subroot.tool = root.tool
                subroot.tool_instance = root.tool_instance
                subroot.alert_type = root.alert_type
                subroot.description = "Brotex HTTP Stream Detection - "
                if request[KEY_HOST]:
                    subroot.description += " {} ".format(request[KEY_HOST])

                if request[KEY_DEST_IP]:
                    subroot.description += " ({}) ".format(request[KEY_DEST_IP])

                if request[KEY_URI]:
                    # don't want to show all the fragments and query params
                    try:
                        parts = urlparse(request[KEY_URI])
                        subroot.description += parts.path
                    except Exception as e:
                        logging.warning("unable to parse {}: {}".format(request[KEY_URI], e))
                        subroot.description += request[KEY_URI]

                subroot.event_time = root.event_time
                subroot.details = request
                subroot.uuid = str(uuid.uuid4())

                # we use a temporary directory while we process the file
                subroot.storage_dir = os.path.join(
                    http_scanner_dir,
                    subroot.uuid[0:3],
                    subroot.uuid)

                subroot.initialize_storage()

                if request[KEY_SRC_IP]:
                    subroot.add_observable(F_IPV4, request[KEY_SRC_IP])

                if request[KEY_DEST_IP]:
                    subroot.add_observable(F_IPV4, request[KEY_DEST_IP])

                if request[KEY_SRC_IP] and request[KEY_DEST_IP]:
                    subroot.add_observable(F_IPV4_CONVERSATION, create_ipv4_conversation(request[KEY_SRC_IP], 
                                                                                       request[KEY_DEST_IP]))

                if request[KEY_HOST]:
                    subroot.add_observable(F_FQDN, request[KEY_HOST])

                if request[KEY_URI]:
                    subroot.add_observable(F_URL, request[KEY_URI])

                if request[KEY_REFERRER]:
                    subroot.add_observable(F_URL, request[KEY_REFERRER])

                for file_path in request[KEY_FILES]:
                    src_path = os.path.join(root.storage_dir, file_path)
                    dest_path = os.path.join(subroot.storage_dir, os.path.basename(file_path))
                    try:
                        shutil.copy(src_path, dest_path)
                    except Exception as e:
                        logging.error("unable to copy {} to {}: {}".format(src_path, dest_path, e))
                        report_exception()
                        
                    subroot.add_observable(F_FILE, os.path.basename(file_path)) # already relative

                try:
                    subroot.save()
                except Exception as e:
                    logging.error("unable to save {}: {}".format(alert, e))
                    report_exception()
                    continue

                # submit the path to the database of the email scanner for analysis
                try:
                    submit_sql_work_item('HTTP', subroot.storage_dir) # XXX hard coded constant
                except:
                    # failure is already logged inside the call
                    continue

    def post_smtp_analysis(self, root):
        from saq.modules.email import EmailAnalysis, SMTPStreamAnalysis, \
                                      BrotexSMTPPackageAnalysis, \
                                      KEY_ENVELOPES_MAIL_FROM, KEY_ENVELOPES_RCPT_TO

        # get the paths to the email scanning system
        #email_scanner_dir = saq.CONFIG['engine_email_scanner']['collection_dir']
        email_scanner_dir = self.collection_dir

        # create a new analysis root for each email analysis we found
        for analysis in root.all_analysis:
            if not isinstance(analysis, EmailAnalysis) or not analysis.email:
                continue

            env_mail_from = None
            env_rcpt_to = None
            connection_id = None

            # the observable for this EmailAnalysis will be a file
            email_file = analysis.observable
            if email_file.type != F_FILE:
                logging.warning("the observable for {} should be F_FILE but it is {}".format(analysis, email_file.type))
            else:
                # this will be either an rfc822 file generated by the SMTPStreamAnalysis module 
                # (which will have the envelope information)
                # OR it is a "broken stream" file, which does not
                stream_analysis = [a for a in root.all_analysis if isinstance(a, SMTPStreamAnalysis) and email_file in a.observables]
                if len(stream_analysis) > 1:
                    logging.error("there should not be more than one of these")
                elif len(stream_analysis) == 1:
                    stream_analysis = stream_analysis[0]
                    logging.debug("detected stream analysis for {}".format(email_file))
                    # get the MAIL FROM and RCPT TO from this
                    if not analysis.env_mail_from:
                        if email_file.value in stream_analysis.envelopes:
                            analysis.env_mail_from = stream_analysis.envelopes[email_file.value][KEY_ENVELOPES_MAIL_FROM]
                    if not analysis.env_rcpt_to:
                        if email_file.value in stream_analysis.envelopes:
                            analysis.env_rcpt_to = stream_analysis.envelopes[email_file.value][KEY_ENVELOPES_RCPT_TO]

                    # get the original brotex package file that the stream came from
                    stream_package = stream_analysis.observable
                    # get the BrotexSMTPPackageAnalysis for this stream package so we can get the connection id
                    package_analysis = [a for a in root.all_analysis if isinstance(a, BrotexSMTPPackageAnalysis) and stream_package in a.observables]
                    if len(package_analysis) > 1:
                        logging.error("there should not be more than one of these!")
                    elif len(package_analysis) == 1:
                        package_analysis = package_analysis[0]
                        connection_id = package_analysis.connection_id

                # if we could not find the stream, we will want to find the brotex smtp package so we can have the connection id
                package_analysis = [a for a in root.all_analysis if isinstance(a, BrotexSMTPPackageAnalysis) and email_file in a.observables]
                if len(package_analysis) > 1:
                    logging.error("there should not be more than one of these!")
                elif len(package_analysis) == 1:
                    package_analysis = package_analysis[0]
                    connection_id = package_analysis.connection_id
                

            subroot = RootAnalysis()
            subroot.company_name = root.company_name
            subroot.tool = root.tool
            subroot.tool_instance = root.tool_instance
            subroot.alert_type = root.alert_type
            subroot.description = 'Brotex SMTP Stream Detection - '

            if analysis.decoded_subject:
                subroot.description += '{} '.format(analysis.decoded_subject)
            elif analysis.subject:
                subroot.description += '{} '.format(analysis.subject)
            else:
                subroot.description += '(no subject) '
                if analysis.env_mail_from:
                    subroot.description += 'From {} '.format(normalize_email_address(analysis.env_mail_from))
                elif analysis.mail_from:
                    subroot.description += 'From {} '.format(normalize_email_address(analysis.mail_from))
                if analysis.env_rcpt_to:
                    if len(analysis.env_rcpt_to) == 1:
                        subroot.description += 'To {} '.format(analysis.env_rcpt_to[0])
                    else:
                        subroot.description += 'To ({} recipients) '.format(len(analysis.env_rcpt_to))
                elif analysis.mail_to:
                    if isinstance(analysis.mail_to, list): # XXX I think this *has* to be a list
                        if len(analysis.mail_to) == 1:
                            subroot.description += 'To {} '.format(analysis.mail_to[0])
                        else:
                            subroot.description += 'To ({} recipients) '.format(len(analysis.mail_to))
                    else:
                        subroot.description += 'To {} '.format(analysis.mail_to)

            subroot.event_time = root.event_time
            subroot.details = analysis.details
            subroot.details['connection_id'] = connection_id
            subroot.uuid = str(uuid.uuid4())

            # we use a temporary directory while we process the file
            subroot.storage_dir = os.path.join(
                email_scanner_dir,
                subroot.uuid[0:3],
                subroot.uuid)

            subroot.initialize_storage()

            # copy the original file
            src_path = os.path.join(root.storage_dir, analysis.observable.value)
            dest_path = os.path.join(subroot.storage_dir, analysis.observable.value)

            subroot.add_observable(F_FILE, os.path.relpath(dest_path, start=subroot.storage_dir))

            # so the EmailAnalysis that will trigger on the RFC822 file (or whatever you have)
            # will *not* have the envelope headers
            # so we do that here in the main alert
            env_mail_from = None
            if analysis.env_mail_from:
                # this is to handle this: <hydraulicinstitute-djstyl1jhjthyuktt1y@cmail2.com> SIZE=80280
                # XXX assuming there can be no spaces in an email address
                env_mail_from = analysis.env_mail_from.split(' ', 1)
                env_mail_from = env_mail_from[0]
                
                # is this not the empty indicator?
                if env_mail_from != '<>':
                    env_mail_from = normalize_email_address(env_mail_from)
                    subroot.add_observable(F_EMAIL_ADDRESS, env_mail_from)

            if analysis.env_rcpt_to:
                for address in analysis.env_rcpt_to:
                    address = normalize_email_address(address)
                    if address:
                        subroot.add_observable(F_EMAIL_ADDRESS, address)
                        if env_mail_from:
                            subroot.add_observable(F_EMAIL_CONVERSATION, create_email_conversation(env_mail_from, address))

            try:
                subroot.save()
            except Exception as e:
                logging.error("unable to save {}: {}".format(alert, e))
                report_exception()
                continue

            # TODO also add the stream and update any envelopment headers and stuff
        
            try:
                logging.debug("copying {} to {}".format(src_path, dest_path))
                shutil.copy(src_path, dest_path)
            except Exception as e:
                logging.error("unable to copy {} to {}: {}".format(src_path, dest_path, e))
                report_exception()
                continue

            # submit the path to the database of the email scanner for analysis
            try:
                submit_sql_work_item('EMAIL', subroot.storage_dir)
            except Exception as e:
                logging.error("unable to add work item: {}".format(e))
                report_exception()
                continue

            # END FOR LOOP

    def root_analysis_completed(self, root):
        if root.delayed:
            return

        if not self.keep_work_dir:
            root.delete()
