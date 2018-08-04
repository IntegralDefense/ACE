# vim: sw=4:ts=4:et

import glob
import json
import logging
import mmap
import os.path
import re

import saq
from saq.analysis import Analysis, Observable, ProfilePoint, ProfilePointAnalyzer, search_down, _JSONEncoder
from saq.constants import *
from saq.modules import AnalysisModule
from saq.modules.util import *
from saq.error import report_exception
from saq.email import normalize_email_address
from saq.pscript import compile_pscript

import yara

class ReWithoutReplyTo(ProfilePointAnalyzer):
    
    @property
    def description(self):
        return """Email subject has Re: without an "in-reply-to" header."""

    def analyze(self, root):
        
        email = get_email(root)
        if email is None:
            return

        if email.subject and email.subject.lower().startswith('re:'):
            for key, value in email.headers:
                if key.lower() == 'in-reply-to':
                    return False

            return ProfilePoint(self.description)

        return

class EmailAttachmentAnalyzer(ProfilePointAnalyzer):
    
    def analyze(self, root):

        result = []

        email = get_email(root)
        if email is None:
            return []

        if email.attachments:
            result.append(ProfilePoint("The email contains an attachment.", "email contains attachment {}".format(email.attachments[0].value)))

            #if len(email.attachments) == 1:
                #result.append(ProfilePoint("The email contains a single attachment.", "email contains attachment {}".format(email.attachments[0].value)))

            compressed_attachments = []
            if email.attachments:
                for attachment in email.attachments:
                    file_name = os.path.basename(attachment.value).lower()
                    for ext in COMPRESSION_FILE_EXTENSIONS:
                        if file_name.endswith(ext.lower()):
                            compressed_attachments.append(file_name)

            if compressed_attachments:
                result.append(ProfilePoint("The email contains compressed attachments.", "email contains compressed attachment(s) {}".format(', '.join(compressed_attachments))))

            if len(compressed_attachments) == 1:
                result.append(ProfilePoint("The email only contains a compressed file attachment type.", "email contains compressed attachment {}".format(compressed_attachments[0])))

        return result

class EmailContainsSingleValidURL(ProfilePointAnalyzer):
    
    @property
    def description(self):
        return """The email only has one valid URL in it."""

    def analyze(self, root):
        
        from saq.modules.file_analysis import URLExtractionAnalysis

        email = get_email(root)
        if email is None:
            return

        if email.body is None:
            return

        extraction_analysis = email.body.get_analysis(URLExtractionAnalysis)
        if extraction_analysis is None:
            return

        if extraction_analysis.details is None:
            return

        if len(set(extraction_analysis.details)) == 1:
            return ProfilePoint(self.description, "{} has the single url {}".format(email, extraction_analysis.details[0]))

        return

class ReplyToReturnPathDifferentFrom(ProfilePointAnalyzer):
    
    @property
    def description(self):
        return """The reply-to-/return-path address is different than the from address."""

    def analyze(self, root):

        email = get_email(root) 
        if email is None:
            return

        in_reply_to = None
        return_path = None
        mail_from = None
        if email.headers:
            for key, value in email.headers:
                if key.lower() == 'reply-to':
                    in_reply_to = normalize_email_address(value)
                elif key.lower() == 'return-path':
                    return_path = normalize_email_address(value)
                elif key.lower() == 'from':
                    mail_from = normalize_email_address(value)

        if not mail_from:
            return 

        result = []

        if return_path is not None and mail_from != return_path:
            result.append(ProfilePoint(self.description, "mail from {} does not match return path {}".format(mail_from, return_path)))

        if in_reply_to is not None and mail_from != in_reply_to:
            result.append(ProfilePoint(self.description, "mail from {} does not match reply to {}".format(mail_from, in_reply_to)))
                
        return result

class RcptToDifferentThanMailTo(ProfilePointAnalyzer):
    
    @property
    def description(self):
        return """The recipient address is different than the to address."""

    def analyze(self, root):

        email = get_email(root) 
        if not email:
            return

        if email.env_rcpt_to and email.mail_to:
            env_rcpt_to = normalize_email_address(email.env_rcpt_to)
            mail_to = normalize_email_address(email.mail_to)
            if normalize_email_address(email.env_rcpt_to) != normalize_email_address(email.mail_to):
                return ProfilePoint(self.description, "recipient {} does not match mail to {}".format(env_rcpt_to, mail_to))

        return

class ProfilePointYaraAnalyzer(ProfilePointAnalyzer):
    """Scans various targets with yara rules to create profile points."""

    def analyze(self, root):
        # the list of profile points to return
        profile_points = []

        # load the yara rules
        source = []
        for path in glob.glob(os.path.join(saq.SAQ_HOME, 'etc', 'pp', 'yara_rules', '*.yar')):
            logging.debug("loading yara rule {}".format(path))
            with open(path, 'r') as fp:
                source.append(fp.read())

        try:
            yara_context = yara.compile(source='\n'.join(source))
        except Exception as e:
            logging.error("unable to compile yara rules: {}".format(e))
            return

        def _scan(data, verify_target_func):
            nonlocal profile_points

            matches = yara_context.match(data=data)

            for match in matches:
                # sanity checking the yara rule, target and profile_point meta needs to exist
                if 'target' not in match.meta:
                    logging.error("yara rule {} missing target meta directive".format(match.rule))
                    continue

                if 'profile_point' not in match.meta:
                    logging.error("yara rule {} missing profile_point meta directive".format(match.rule))
                    continue

                if not verify_target_func(match):
                    continue

                profile_points.append(ProfilePoint(match.meta['profile_point'], str(match)))

        for obj in root.all:
            if isinstance(obj, Analysis):
                # scan the details of the analysis
                if obj.details is not None:
                    def _verify_analysis_target(match):
                        if not match.meta['target'].startswith('analysis:'):
                            return False

                        analysis_match = match.meta['target'][len('analysis:'):]
                        return analysis_match in data.summary

                    logging.debug("scanning analysis object {}".format(obj))
                    _scan(json.dumps(obj.details, indent=2, sort_keys=True, cls=_JSONEncoder), _verify_analysis_target)

                # scan all the profile point targets for this analysis
                for target in obj.targets:
                    if target.data is None:
                        continue

                    logging.info("scanning {}".format(target))
                    def _verify_pp_target(match):
                        return match.meta['target'] == target.name
    
                    _scan(target.data, _verify_pp_target)

                # if we don't do this we'll end up loading the entire analysis into memory
                obj.discard_details()

            elif isinstance(obj, Observable):
                def _verify_observable_target(match):
                    if not match.meta['target'].startswith('observable:'):
                        return False

                    observable_match = match.meta['target'][len('observable:'):]
                    return observable_match == obj.type

                _scan(obj.value, _verify_observable_target)

        
        return profile_points

class PScriptAnalyzer(ProfilePointAnalyzer):
    """Executes pscript code against the RootAnalysis objects to resolve Profile Points."""

    def __init__(self, *args, **kwargs):
        # load the scripts
        self.pscripts = []
        for pscript_path in glob.glob(os.path.join(saq.SAQ_HOME, 'etc', 'pp', 'pscript', '*.p')):
            logging.info("loading pscript {}".format(pscript_path))
            try:
                with open(pscript_path, 'r') as fp:
                    line_number = 1
                    for line in fp.readlines():
                        try:
                            p = compile_pscript(line)
                        except Exception as e:
                            logging.error("unable to load line #{} of {}: {}".format(line_number, pscript_path, e))
                            report_exception()
                            continue
                        finally:
                            line_number += 1

                        logging.info("loaded pscript {}".format(p))
                        self.pscripts.append(p)

            except Exception as e:
                logging.error("unable to load pscript {}: {}".format(pscript_path, e))
                report_exception()
    
    def analyze(self, root):
        profile_points = []
        for p in self.pscripts:
            try:
                if p(root):
                    profile_points.append(ProfilePoint(p.description, p.expression.matched_target.value if p.expression.matched_target else None))
            except Exception as e:
                logging.error("profile point analysis failed: {}".format(e))
                report_exception()

        return profile_points
