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

#
# NOTE - understanding how this logic works
# (A) --> (C) --> (alert)
# (B) --> (C)
# (B) --> (D) --> (alert)
# where (A) has tag t1 and (B) has tag t2

# (A) has t1 so tag_map[A] = (t1) and tag_map[C] = (t1)
# (B) has t2 so tag_map[B] = (t2) and tag_map[C] = (t1, t2)
# (t1, t2) matches the definition so C gets the detection point

class CorrelatedTagDefinition(object):
    def __init__(self, text, tags):
        # the textual description of the alert
        self.text = text
        # the list of tags we expect to see in the children of a target object
        self.tags = set(tags)

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
                logging.debug("loaded definition for {}".format(config_rule))

    def execute_post_analysis(self):
        for d in self.definitions:
            tag_map = {} # key = object_id, value = [tags]
            def callback(obj):
                if obj is self.root:
                    return

                if id(obj) not in tag_map:
                    tag_map[id(obj)] = set()

                tag_map[id(obj)].add(t)
                if tag_map[id(obj)] == d.tags:
                    o.add_detection_point("Correlated Tag Match: {}".format(d.text))

            for t in d.tags:
                for o in self.root.all:
                    # exclude looking at the RootAnalysis object itself
                    if o is self.root:
                        continue

                    # if this object has the tag we're looking for...
                    if o.has_tag(t):
                        # then "apply" the tag all the way down to (but not including) the root
                        recurse_down(o, callback)
