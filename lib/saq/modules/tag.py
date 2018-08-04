# vim: ts=4:sw=4:et

import csv
import fnmatch
import json
import logging
import os.path
import re
import smtplib
import ipaddress

import saq

from saq.analysis import Analysis, Observable, recurse_down, TaggableObject
from saq.database import Alert
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule, TagAnalysisModule
from saq.util import is_subdomain

class TagAnalysis(Analysis):
    """Base class for all tag analysis.  We don't display this as analysis in the GUI."""
    def initialize_details(self):
        pass

    @property
    def jinja_should_render(self):
        return False

class SiteTagAnalysis(TagAnalysis):
    """Tags observables defined in etc/tags.csv"""
    pass

class _tag_mapping(object):

    MATCH_TYPE_DEFAULT = 'default'
    MATCH_TYPE_GLOB = 'glob'
    MATCH_TYPE_REGEX= 'regex'
    MATCH_TYPE_CIDR = 'cidr'
    MATCH_TYPE_SUBDOMAIN = 'subdomain'

    def __init__(self, match_type, ignore_case, value, tags):
        assert match_type in [ _tag_mapping.MATCH_TYPE_DEFAULT,
                               _tag_mapping.MATCH_TYPE_GLOB,
                               _tag_mapping.MATCH_TYPE_REGEX,
                               _tag_mapping.MATCH_TYPE_SUBDOMAIN,
                               _tag_mapping.MATCH_TYPE_CIDR ]
        assert isinstance(ignore_case, bool)
        assert value is not None
        assert isinstance(tags, list)
        assert all([isinstance(t, str) for t in tags])

        self.match_type = match_type
        self.ignore_case = ignore_case
        self.value = value
        self.tags = tags

        # if we have a regex go ahead and compile it
        if self.match_type == _tag_mapping.MATCH_TYPE_REGEX:
            self.compiled_regex = re.compile(self.value, flags=re.I if ignore_case else 0)

        # if we have a cidr go ahead and create the object used to match it
        if self.match_type == _tag_mapping.MATCH_TYPE_CIDR:
            self.compiled_cidr = ipaddress.ip_network(value)

    def __str__(self):
        return 'tag_mapping({} --> {})'.format(self.value, ','.join(self.tags))

    def matches(self, value):
        if self.match_type == _tag_mapping.MATCH_TYPE_DEFAULT:
            return self._matches_default(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_GLOB:
            return self._matches_glob(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_REGEX:
            return self._matches_regex(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_CIDR:
            return self._matches_cidr(value)
        elif self.match_type == _tag_mapping.MATCH_TYPE_SUBDOMAIN:
            return self._matches_subdomain(value)
        else:
            raise RuntimeError("invalid match type: {}".format(self.match_type))

    def _matches_default(self, value):
        if self.ignore_case:
            return self.value.lower() == value.lower()

        return self.value == value

    def _matches_glob(self, value):
        if self.ignore_case:
            return fnmatch.fnmatch(value, self.value)

        return fnmatch.fnmatchcase(value, self.value)

    def _matches_regex(self, value):
        return self.compiled_regex.search(value) is not None

    def _matches_cidr(self, value):
        try:
            return ipaddress.ip_address(value) in self.compiled_cidr
        except ValueError as e:
            logging.debug("{} did not parse out to be an ip/cidr: {}".format(value, e))
            return False

    def _matches_subdomain(self, value):
        # is value equal to or a subdomain of self.value?
        return is_subdomain(value, self.value)

class SiteTagAnalyzer(TagAnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('csv_file')
        self.verify_path_exists(self.csv_file)

    @property
    def csv_file(self):
        path = self.config['csv_file']
        if os.path.isabs(path):
            return path

        return os.path.join(saq.SAQ_HOME, path)

    @property
    def generated_analysis_type(self):
        return SiteTagAnalysis

    @property
    def valid_observable_types(self):
        return None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_mapping = {} # key = type, value = [_tag_mapping]
        self.watch_file(self.csv_file, self.load_csv_file)

    def load_csv_file(self):
        # load the configuration
        with open(self.csv_file, 'r') as fp:
            for row in csv.reader(fp):
                try:
                    o_types, match_type, ignore_case, value, tags = row
                except Exception as e:
                    logging.error("invalid tag specification: {}: {}".format(','.join(row), e))
                    continue

                o_types = o_types.split('|')
                ignore_case = bool(ignore_case)
                tags = tags.split('|')

                mapper = _tag_mapping(match_type, ignore_case, value, tags)
                #logging.debug("created mapping {}".format(mapper))

                for o_type in o_types:
                    if o_type not in self.tag_mapping:
                        self.tag_mapping[o_type] = []

                    self.tag_mapping[o_type].append(mapper)

    def execute_analysis(self, observable):

        if observable.type not in self.tag_mapping:
            return False

        analysis = self.create_analysis(observable)

        for mapper in self.tag_mapping[observable.type]:
            if mapper.matches(observable.value):
                logging.debug("{} matches {}".format(observable, mapper))
                for tag in mapper.tags:
                    observable.add_tag(tag)

        return True

# DEPRECATED
class IPv4TagAnalysis(TagAnalysis):
    pass

# DEPRECATED
class UserTagAnalysis(TagAnalysis):
    pass

class EmailNotificationAnalysis(TagAnalysis):
    pass

class EmailNotification(AnalysisModule):
    """Alerts with specific tags will cause emails to be generated."""
    @property
    def generated_analysis_type(self):
        return EmailNotificationAnalysis

    @property
    def valid_analysis_target_type(self):
        return None

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, alert):
        if not isinstance(alert, Alert):
            return

        for option in saq.CONFIG.options(self.config_section):
            if option.startswith('tag_distro_'):
                tag_list, email_list = saq.CONFIG[self.config_section][option].split(':')
                tags = tag_list.split(',')
                emails = email_list.split(',')

                # does this alert have these tags?
                expected_tags = tags[:]
                for tag in self.root.tags:
                    try:
                        expected_tags.remove(tag.name)
                    except:
                        pass

                if len(expected_tags) == 0:

                    # have we already sent out an email for this tag combination?
                    email_submission_marker = os.path.join(alert.storage_dir, 'email_submission_{0}'.format(option))
                    if os.path.exists(email_submission_marker):
                        continue

                    try:
                        # send out the email
                        logging.info("sending email notification for {0}".format(alert))
                        email_message = "From: {0}\r\nTo: {1}\r\nSubject: {2}\r\n\r\n{3}".format(
                            saq.CONFIG[self.config_section]['smtp_mail_from'],
                            email_list,
                            "{0}: {1}".format(saq.CONFIG[self.config_section]['smtp_subject_prefix'], alert.description),
                            alert.to_email_message)
                
                        server = smtplib.SMTP(saq.CONFIG[self.config_section]['smtp_server'])
                        server.sendmail(saq.CONFIG[self.config_section]['smtp_mail_from'], emails, email_message)
                        server.quit()

                        # we create this file as a marker to indicate we've already sent an alert for this 
                        with open(email_submission_marker, 'w'):
                            pass

                    except Exception as e:
                        logging.error("unable to send email for {0}: {1}".format(alert, str(e)))

class CorrelatedTagDefinition(object):
    def __init__(self, text, tags):
        self.text = text
        self.tags = tags
        self.reset()

    def reset(self):
        # for each tag we keep track of what objects have that tag
        # key = tag_name, value = [ objects ]
        self.tag_matches = {}
        for tag in self.tags:
            self.tag_matches[tag] = [] # can be more than one

    def match(self, target):
        assert isinstance(target, TaggableObject)
        result = False
        for tag in self.tags:
            if target.has_tag(tag):
                self.tag_matches[tag].append(target)
                result = True

        return result

    def matches(self):
        for tag in self.tags:
            if len(self.tag_matches[tag]) == 0:
                return False

        # at this point we know we've got matches for all the tags we're looking for
        # now look to see if all the matches have a common ancestor somewhere
        def _callback(obj):
            nonlocal _ancestors
            # we don't look at the root since everything shares that as a common point
            if not ( obj is obj.root ):
                _ancestors.append(obj)

        all_ancestors = []
        for tag in self.tags:
            for obj in self.tag_matches[tag]:
                _ancestors = []
                recurse_down(obj, _callback)
                all_ancestors.append(set(_ancestors))

        # at this point we have a list of all the ancestors of all the objects
        # we need at least one common object in all of them
        for index in range(len(all_ancestors) - 1):
            if index == 0:
                result = all_ancestors[index] & all_ancestors[index + 1]
            else:
                result = result & all_ancestors[index + 1]

        return len(result) > 0

class CorrelatedTagAnalysis(Analysis):
    pass

class CorrelatedTagAnalyzer(AnalysisModule):
    """Does this combination of tagging exist on objects with a common ancestry?"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.definitions = []
        
        for config_item in self.config.keys():
            if config_item.startswith('definition_') and config_item.endswith('_rule'):
                config_rule = config_item
                config_text = config_item.replace('_rule', '_text')
                if config_text not in self.config:
                    logging.error("missing text description for config rule {}".format(config_item))
                    continue

                self.definitions.append(CorrelatedTagDefinition(self.config[config_text], 
                                         [x.strip() for x in self.config[config_rule].split(',')]))
                logging.info("loaded definition for {}".format(config_rule))

    @property
    def generated_analysis_type(self):
        return CorrelatedTagAnalysis

    @property
    def valid_analysis_target_type(self):
        return None # any

    @property
    def valid_observable_types(self):
        return None # any

    def execute_analysis(self, target):
        pass

    def execute_final_analysis(self, target):

        for _def in self.definitions:
            _def.reset()

        # does this target have a tag we're looking for?
        if not _def.match(target):
            return

        for _def in self.definitions:
            _def.reset()
        
        for obj in self.root.all:
            for _def in self.definitions:
                _def.match(obj)

        for _def in self.definitions:
            if _def.matches():
                already_detected = False
                message = "Correlated Tag Match: {}".format(_def.text)
                for detection_point in target.detections:
                    if detection_point.description == message:
                        already_detected = True
                        break

                if not already_detected:
                    target.add_detection_point("Correlated Tag Match: {}".format(_def.text))
