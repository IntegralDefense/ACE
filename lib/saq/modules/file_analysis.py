import base64
import csv
import datetime
import fnmatch
import gc
import hashlib
import html
import io
import json
import logging
import mmap
import os
import os.path
import re
import shutil
import socket
import stat
import sys
import tempfile
import time

from lxml import etree
from urllib.parse import urlparse, urljoin

#from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired

from urlfinderlib import find_urls

import saq
import yara_scanner

from saq.analysis import Analysis, Observable, RootAnalysis
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.process_server import Popen, PIPE, DEVNULL, TimeoutExpired
from saq.util import is_url, URL_REGEX_B, URL_REGEX_STR

from bs4 import BeautifulSoup
from iptools import IpRangeList

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
warnings.filterwarnings("ignore", category=RuntimeWarning, module='bs4')

rfc1918 = IpRangeList('10.0.0.0/8', '172.168.0.0/12', '192.168.0.0/16', '127.0.0.1')

# known file extensions for microsoft office files
# see https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions
# 2/19/2018 - removed MSO file ext (relying on OLE format instead)
# 6/29/2018 - https://docs.google.com/spreadsheets/d/1LXneVF8VxmOgkt2W_NG5Kl3lzWW45prE7gxtuPcO-4o/edit#gid=1950593040
KNOWN_OFFICE_EXTENSIONS = [ '.{}'.format(ext) for ext in [ 
    # Microsoft Word
    'doc',
    'docb',
    'dochtml',
    'docm',
    'docx',
    'docxml',
    'dot',
    'dothtml',
    'dotm',
    'dotx',
    'odt',
    'rtf',
    'wbk',
    'wiz',
    # Microsoft Excel
    'csv',
    'dqy',
    'iqy',
    'odc',
    'ods',
    'slk',
    'xla',
    'xlam',
    'xlk',
    'xll',
    'xlm',
    'xls',
    'xlsb',
    'xlshtml',
    'xlsm',
    'xlsx',
    'xlt',
    'xlthtml',
    'xltm',
    'xltx',
    'xlw',
    # Microsoft Powerpoint
    'odp',
    'pot',
    'pothtml',
    'potm',
    'potx',
    'ppa',
    'ppam',
    'pps',
    'ppsm',
    'ppsx',
    'ppt',
    'ppthtml',
    'pptm',
    'pptx',
    'pptxml',
    'pwz',
    'sldm',
    'sldx',
    'thmx',
]]

    #'mso',
    #'ppt', 'pot', 'pps', 'pptx', 'pptm', 'potx', 'potm', 'ppam', 'ppsx', 'ppsm', 'sldx', 'sldm', 'rtf', 'pub' ]]

# same thing for macros extracted from office documents
KNOWN_MACRO_EXTENSIONS = [ '.bas', '.frm', '.cls' ]

def is_office_ext(path):
    """Returns True if the given path has a file extension that would be opened by microsoft office."""
    root, ext = os.path.splitext(path)
    return ext in KNOWN_OFFICE_EXTENSIONS

def is_office_file(_file):
    """Returns True if we think this is probably an Office file of some kind."""
    assert isinstance(_file, Observable) and _file.type == F_FILE
    result = is_office_ext(os.path.basename(_file.value))
    file_type_analysis = _file.get_analysis(FileTypeAnalysis)
    if not file_type_analysis:
        return result

    result |= 'microsoft powerpoint' in file_type_analysis.file_type.lower()
    result |= 'microsoft excel' in file_type_analysis.file_type.lower()
    result |= 'microsoft word' in file_type_analysis.file_type.lower()
    result |= 'microsoft ooxml' in file_type_analysis.file_type.lower()
    return result

def is_macro_ext(path):
    root, ext = os.path.splitext(path)
    return ext in KNOWN_MACRO_EXTENSIONS

def is_ole_file(path):
    with open(path, 'rb') as fp:
        return fp.read(8) == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

def is_rtf_file(path):
    with open(path, 'rb') as fp:
        data = fp.read(4)
        return data[:3] == b'\\rt' or data == b'{\\rt'


def is_pdf_file(path):
    with open(path, 'rb') as fp:
        return b'%PDF-' in fp.read(1024)

def is_pe_file(path):
    with open(path, 'rb') as fp:
        return fp.read(2) == b'MZ'

def is_zip_file(path):
    with open(path, 'rb') as fp:
        return fp.read(2) == b'PK'

def is_empty_macro(path):
    """Returns True if the given macro file only has empty lines and/or Attribute settings."""
    with open(path, 'rb') as fp:
        for line in fp:
            # if the line is empty keep moving
            if line.strip() == b'':
                continue

            # or if it starts with one of these lines
            if line.startswith(b'Attribute VB_'):
                continue

            # otherwise it's something else, so return False
            return False

    return True

def _safe_filename(s):

    def _safe_char(c):
        # we want . for file ext and / for dir path, but ...
        if c.isalnum() or c == '/' or c == '.':
            return c
        else:
            return "_"

    # make sure we don't allow parent dir
    return ("".join(_safe_char(c) for c in s).rstrip("_")).replace('..', '_') # turn parent dir into bemused face
        
"""File Analysis Routines"""

def get_local_file_path(root, _file):
    """Return the local (full) file path for a given F_FILE type indicator from the given analysis."""
    assert isinstance(root, RootAnalysis)
    assert isinstance(_file, Observable)
    assert _file.type == F_FILE

    # I removed the SAQ_HOME from the front of this so that we can analyze stuff in other directories
    # with the command line tools.
    # This requires that the services (engine, gui, etc...) all run from the SAQ_HOME directory as CWD.
    return os.path.join(root.storage_dir, _file.value)


class FileHashAnalysis(Analysis):
    """What are the hash values of this file?"""

    def initialize_details(self):
        self.details = {
            'md5': None,
            'sha1': None,
            'sha256': None, }

    @property
    def md5(self):
        if self.details is None:
            return None

        return self.details['md5']

    @md5.setter
    def md5(self, value):
        self.details['md5'] = value

    @property
    def sha1(self):
        if self.details is None:
            return None

        return self.details['sha1']

    @sha1.setter
    def sha1(self, value):
        self.details['sha1'] = value

    @property
    def sha256(self):
        if self.details is None:
            return None

        return self.details['sha256']

    @sha256.setter
    def sha256(self, value):
        self.details['sha256'] = value

    def generate_summary(self):
        if self.sha256 is not None:
            return "File Hash Analysis {0}".format(self.sha256)
        return None

class FileHashAnalyzer(AnalysisModule):
    """Perform hash analysis on F_FILE indicator types for files attached to the alert."""

    @property
    def generated_analysis_type(self):
        return FileHashAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
    
    def execute_analysis(self, _file):

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return False

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # some files we skip hashing, specifically the files that we generate
        for section in self.config.keys():
            if section.startswith('ignore_pattern_'):
                ignore_pattern = self.config[section]
                if fnmatch.fnmatch(local_file_path, ignore_pattern):
                    logging.debug("skipping file hash analysis on {} for ignore pattern {}".format(
                        local_file_path, ignore_pattern))
                    return False

            if section.startswith('ignore_mime_type_'):
                ignore_pattern = self.config[section]
                if fnmatch.fnmatch(file_type_analysis.mime_type, ignore_pattern):
                    logging.debug("skipping file hash analysis on {} for ignore mime type {}".format(
                                  local_file_path, ignore_pattern))
                    return False

        # the FileObservable actually defines it's own compute_hashes function that does all the work
        if not _file.compute_hashes():
            logging.error("file hash analysis failed for {}".format(_file))
            return False

        logging.debug("analyzing file {}".format(local_file_path))

        result = self.create_analysis(_file)

        o_md5 = result.add_observable(F_MD5, _file.md5_hash)
        o_sha1 = result.add_observable(F_SHA1, _file.sha1_hash)
        o_sha256 = result.add_observable(F_SHA256, _file.sha256_hash)

        result.md5 = _file.md5_hash
        result.sha1 = _file.sha1_hash
        result.sha256 = _file.sha256_hash

        if o_md5: o_md5.add_link(_file)
        if o_sha1: o_sha1.add_link(_file)
        if o_sha256: o_sha256.add_link(_file)

        return True

# NEVER IMPLEMENTED
class MalwareZooAnalysis(Analysis):
    def initialize_details(self):
        pass

class MalwareZooAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MalwareZooAnalysis

    @property
    def valid_observable_types(self):
        return F_MD5, F_SHA1, F_SHA256

    def execute_analysis(self, _hash):
        pass

class SsdeepAnalysis(Analysis):
    """Does this file match any other files by fuzzy hash?"""

    def initialize_details(self):
        self.details = {
            'matches': [], # [] of { 'file': blah, 'score': int }
        }

    def generate_summary(self):
        if len(self.details['matches']) > 0:
            return "Ssdeep Analysis ({0} matches {1}% highest match)".format(
                len(self.details['matches']), max([x['score'] for x in self.details['matches']]))
        return None

class SsdeepAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('ssdeep_hashes')
        self.verify_path_exists(self.config['ssdeep_hashes'])
        self.verify_config_exists('maximum_size')
        self.verify_config_exists('ssdeep_match_threshold')
        self.verify_program_exists('ssdeep')

    @property
    def ssdeep_hashes(self):
        return self.config['ssdeep_hashes']

    @property
    def maximum_size(self):
        return self.config.getint('maximum_size')

    @property
    def ssdeep_match_threshold(self):
        return self.config.getint('ssdeep_match_threshold')

    @property
    def generated_analysis_type(self):
        return SsdeepAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # don't bother for files that are really small
        file_size = os.path.getsize(local_file_path)
        if file_size < 1024:
            logging.debug("{} too small for ssdeep analysis".format(local_file_path))
            return False

        # and bail if the file is too big
        if file_size > self.maximum_size:
            logging.debug("{} too large ({}) for ssdeep analysis".format(local_file_path, file_size))
            return False

        logging.debug("analyzing file {}".format(local_file_path))
        p = Popen(['ssdeep', '-m', self.ssdeep_hashes, local_file_path], 
            stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (stdout, stderr) = p.communicate()

        if len(stderr) > 0:
            logging.debug("ssdeep returned errors for {}".format(local_file_path))
            return False

        analysis = None

        for line in stdout.split('\n'):
            # example output:
            # /opt/mwzoo/data/pos/frameworkpos/1/a5dc57aea5f397c2313e127a6e01aa00 matches all_the_hashes.ssdeep:/opt/mwzoo/data/pos/frameworkpos/1/a5dc57aea5f397c2313e127a6e01aa00.sample (100)
            if line == '':
                continue

            m = re.match(r'^.+? matches [^:]+:(.+) \(([0-9]{1,3})\)$', line)
            if not m:
                logging.error("unexpected ssdeep output: {}".format(line))
                continue

            matched_file = m.group(1)
            ssdeep_score = 0

            try:
                ssdeep_score = int(m.group(2))
            except Exception as e:
                logging.error("unable to parse {} as integer".format(ssdeep_score))

            if ssdeep_score >= self.ssdeep_match_threshold:
                _file.add_tag('ssdeep')
                _file.add_directive(DIRECTIVE_SANDBOX)
                if not analysis:
                    analysis = self.create_analysis(_file)

                analysis.details['matches'].append({'file': matched_file, 'score': int(ssdeep_score)})

        return analysis is not None

class ArchiveAnalysis(Analysis):
    """Is this an archive file?  What files are in this archive?"""

    def initialize_details(self):
        self.details = {
            'file_count': None,
        }

    @property
    def file_count(self):
        return self.details_property('file_count')

    @file_count.setter
    def file_count(self, value):
        self.details['file_count'] = value

    def upgrade(self):
        if 'file_count' not in self.details:
            logging.debug("upgrading {0}".format(self))
            self.details['file_count'] = len([x for x in self.observables if x.type == F_FILE])

    def generate_summary(self):
        if self.details['file_count'] is not None and self.details['file_count'] > 0:
            files_available = self.details['file_count']
            files_extracted = len([x for x in self.observables if x.type == F_FILE])
            return "Archive Analysis ({0} files available {1} extracted)".format(
                files_available, files_extracted)

        return None

# 2018-02-19 12:15:48          319534300    299585795  155 files, 47 folders
Z7_SUMMARY_REGEX = re.compile(rb'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d+\s+\d+\s+(\d+)\s+files.*?')

# listed: 1 files, totaling 711.168 bytes (compressed 326.520)
UNACE_SUMMARY_REGEX = re.compile(rb'^listed: (\d+) files,.*')

class ArchiveAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('max_file_count')
        self.verify_config_exists('timeout')
        self.verify_program_exists('7z')
        self.verify_program_exists('unrar')
        self.verify_program_exists('unace')
        self.verify_program_exists('unzip')

    @property
    def max_file_count(self):
        return self.config.getint('max_file_count')

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def excluded_mime_types(self):
        if 'excluded_mime_types' in self.config:
            return map(lambda x: x.strip(), self.config['excluded_mime_types'].split(','))
        return []

    @property
    def generated_analysis_type(self):
        return ArchiveAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None or file_type_analysis.details is None:
            return False

        # there are some we exclude
        for excluded_mime_type in self.excluded_mime_types:
            if file_type_analysis.mime_type.lower().startswith(excluded_mime_type.lower()):
                logging.debug("skipping excluded mime type {} on archive file {}".format(excluded_mime_type, _file.value))
                return False

            # we also do not extract OLE compound documents (we have other modules that do a better job)
            if is_ole_file(local_file_path):
                logging.debug("skipping archive extraction of OLE file {}".format(_file.value))
                return False

        # special logic for rar files
        is_rar_file = 'RAR archive data' in file_type_analysis.file_type
        is_rar_file |= file_type_analysis.mime_type == 'application/x-rar'

        # and special logic for some types of zip files
        is_zip_file = 'Microsoft Excel 2007+' in file_type_analysis.file_type
        is_zip_file |= file_type_analysis.mime_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        # special logic for microsoft office files
        is_office_document = is_office_file(_file)
        #is_office_document = is_office_ext(os.path.basename(local_file_path))
        #is_office_document |= 'microsoft powerpoint' in file_type_analysis.file_type.lower()
        #is_office_document |= 'microsoft excel' in file_type_analysis.file_type.lower()
        #is_office_document |= 'microsoft word' in file_type_analysis.file_type.lower()
        #is_office_document |= 'microsoft ooxml' in file_type_analysis.file_type.lower()

        # notice that we pass in a password of "infected" here even if we're not prompted for one
        # infosec commonly use that as the password, and if it's not right then it just fails because
        # we don't know it anyways

        # special logic for ACE files
        is_ace_file = 'ACE archive data' in file_type_analysis.file_type
        is_ace_file |= _file.value.lower().endswith('.ace')

        count = 0

        if is_rar_file:
            logging.debug("using unrar to extract files from {}".format(local_file_path))
            p = Popen(['unrar', 'la', local_file_path], stdout=PIPE, stderr=PIPE)
            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired as e:
                logging.error("timed out tryign to extract files from {} with unrar".format(local_file_path))
                return False

            if b'is not RAR archive' in stdout:
                return False

            start_flag = False
            for line in stdout.split(b'\n'):
                if not start_flag:
                    if line.startswith(b'-----------'):
                        start_flag = True
                        continue

                    continue

                if line.startswith(b'-----------'):
                    break

                count += 1

        elif is_zip_file:
            logging.debug("using unzip to extract files from {}".format(local_file_path))
            p = Popen(['unzip', '-l', '-P', 'infected', local_file_path], stdout=PIPE, stderr=PIPE)
            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired as e:
                logging.error("timed out trying to list files from {} with unzip".format(local_file_path))
                return False

            if b'End-of-central-directory signature not found.' in stdout:
                return False

            start_flag = False
            for line in stdout.split(b'\n'):
                if not start_flag:
                    if line.startswith(b'---------'):
                        start_flag = True
                        continue

                    continue

                if line.startswith(b'---------'):
                    break

                if b'ppt/slides/_rels' in line:
                    is_office_document = True

                if b'word/document.xml' in line:
                    is_office_document = True

                if b'xl/embeddings/oleObject' in line:
                    is_office_document = True

                if b'xl/worksheets/sheet' in line:
                    is_office_document = True

                count += 1

            # 01/17/2017 - docx sample 42f587b277f02445b526e3887893c2c5 file command does not indicate docx
            # we can use presence of ole file as indicator
            # NOTE the uses of regex wildcard match for file separator, sometimes windows sometimes unix
            ole_object_regex = re.compile(b'word.embeddings.oleObject1\\.bin', re.M)
            is_office_document |= (ole_object_regex.search(stdout) is not None)
                
        elif is_ace_file:
            p = Popen(['unace', 'l', local_file_path], stdout=PIPE, stderr=PIPE)

            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired as e:
                logging.error("timed out trying to extract files from {} with 7z".format(local_file_path))
                return False

            for line in stdout.split(b'\n'):
                m = UNACE_SUMMARY_REGEX.match(line)
                if m:
                    count = int(m.group(1))
                    break

        else:
            logging.debug("using 7z to extract files from {}".format(local_file_path))
            p = Popen(['7z', '-y', '-pinfected', 'l', local_file_path], stdout=PIPE, stderr=PIPE)
            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired as e:
                logging.error("timed out trying to extract files from {} with 7z".format(local_file_path))
                return False

            if b'Error: Can not open file as archive' in stdout:
                return False

            for line in stdout.split(b'\n'):
                m = Z7_SUMMARY_REGEX.match(line)
                if m:
                    count = int(m.group(1))

                #if line.startswith(b'Testing'):
                    #count += 1

                if b'ppt/slides/_rels' in line:
                    is_office_document = True

                if b'word/document.xml' in line:
                    is_office_document = True

                if b'xl/embeddings/oleObject' in line:
                    is_office_document = True

                if b'xl/worksheets/sheet' in line:
                    is_office_document = True

            # 01/17/2017 - docx sample 42f587b277f02445b526e3887893c2c5 file command does not indicate docx
            # we can use presence of ole file as indicator
            # NOTE the uses of regex wildcard match for file separator, sometimes windows sometimes unix
            ole_object_regex = re.compile(b'word.embeddings.oleObject1\\.bin', re.M)
            is_office_document |= (ole_object_regex.search(stdout) is not None)

        if not is_office_document:
            if self.max_file_count != 0 and count > self.max_file_count:
                logging.debug("skipping archive analysis of {}: file count {} exceeds configured maximum {} in max_file_count setting".format(
                    local_file_path, count, self.max_file_count))
                return False

        if count == 0:
            return False

        # we need a place to store these things
        extracted_path = '{}.extracted'.format(local_file_path).replace('*', '_') # XXX need a normalize function
        if not os.path.isdir(extracted_path):
            try:
                os.makedirs(extracted_path)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(extracted_path, e))
                return False

        logging.debug("extracting {} files from archive {} into {}".format(count, local_file_path, extracted_path))

        analysis = self.create_analysis(_file)
        analysis.file_count = count

        params = []
        kwargs = { 'stdout': PIPE, 'stderr': PIPE }

        if is_rar_file:
            params = ['unrar', 'e', '-y', '-o+', local_file_path, extracted_path]
        elif is_zip_file:
            # avoid the numerious XML documents in excel files
            params = ['unzip', local_file_path, '-x', 'xl/activeX/*', 
                                                '-x', 'xl/activeX/_rels/*', 
                      '-d', extracted_path]
        elif is_ace_file:
            # for some reason, unace doesn't let you use a full path
            params = ['unace', 'x', '-y', '-o', os.path.relpath(local_file_path, start=extracted_path)]
            kwargs['cwd'] = extracted_path
        else:
            params = ['7z', '-y', '-pinfected', '-o{}'.format(extracted_path), 'x', local_file_path]

        if params:
            p = Popen(params, **kwargs)

            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired as e:
                (stdout, stderr) = p.communicate()

        #logging.debug("extracted into {}".format(extracted_path))

        # rather than parse the output we just go find all the files we've created in that directory
        for root, dirs, files in os.walk(extracted_path):
            for file_name in files:
                extracted_file = os.path.join(root, file_name)
                logging.debug("extracted_file = {}".format(extracted_file))

                file_observable = analysis.add_observable(F_FILE, 
                    os.path.relpath(extracted_file, start=self.root.storage_dir))

                if not file_observable:
                    continue

                # add a relationship back to the original file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)

                # if we extracted an office document then we want everything to point back to that document
                # so that we sandbox the right thing
                if is_office_document:
                    file_observable.redirection = _file

                # https://github.com/IntegralDefense/ACE/issues/12 - also fixed for xps
                if file_observable.ext in [ 'xps', 'rels' ]:
                    file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)

                # a single file inside of a zip file is always suspect
                if analysis.file_count == 1:
                    logging.debug("archive file {} has one file inside (always suspect)".format(_file.value))
                    analysis.add_tag('single_file_zip')

                    # and then we want to sandbox it
                    file_observable.add_directive(DIRECTIVE_SANDBOX)

                    # but an executable or script file (js, vbs, etc...) is an alert
                    for extracted_file in analysis.observables:
                        for ext in [ '.exe', '.scr', '.cpl', '.jar' ]:
                            if extracted_file.value.lower().endswith(ext):
                                analysis.add_tag('exe_in_zip')
                        for ext in [ '.vbe', '.vbs', '.jse', '.js', '.bat', '.wsh', '.ps1' ]:
                            if extracted_file.value.lower().endswith(ext):
                                analysis.add_tag('script_in_zip')
                        for ext in [ '.lnk' ]:
                            if extracted_file.value.lower().endswith(ext):
                                analysis.add_tag('lnk_in_zip')

        try:
            for root, dirs, files in os.walk(extracted_path):
                for _dir in dirs:
                    full_path = os.path.join(root, _dir)
                    try:
                        os.chmod(full_path, 0o775)
                    except Exception as e:
                        logging.error("unable to adjust permissions on dir {}: {}".format(full_path, e))

                for _file in files:
                    full_path = os.path.join(root, _file)
                    try:
                        os.chmod(full_path, 0o664)
                    except Exception as e:
                        logging.error("unable to adjust permissions on file {}: {}".format(full_path, e))

        except Exception as e:
            logging.error("some error was reported when trying to recursively chmod {}: {}".format(extracted_path, e))
            report_exception()

        return True

# DEPRECATED
class OLEVBA_Analysis_v1_0(Analysis):
    """Does this office document have macros?"""

    KEY_FILE_TYPE = 'ole_vba_file_type'
    KEY_ANALYSIS = 'ole_vba_analysis'
    KEY_SUMMARY = 'ole_vba_summary'

    def initialize_details(self):
        pass

    @property
    def olevba_file_type(self):
        return self.details[OLEVBA_Analysis_v1_0.KEY_FILE_TYPE]

    @olevba_file_type.setter
    def olevba_file_type(self, value):
        self.details[OLEVBA_Analysis_v1_0.KEY_FILE_TYPE] = value

    @property
    def olevba_analysis(self):
        return self.details[OLEVBA_Analysis_v1_0.KEY_ANALYSIS]

    @olevba_analysis.setter
    def olevba_analysis(self, value):
        self.details[OLEVBA_Analysis_v1_0.KEY_ANALYSIS] = value

    @property
    def olevba_summary(self):
        return self.details[OLEVBA_Analysis_v1_0.KEY_SUMMARY]

    @olevba_summary.setter
    def olevba_summary(self, value):
        self.details[OLEVBA_Analysis_v1_0.KEY_SUMMARY] = value

    def generate_summary(self):
        if self.olevba_file_type is None:
            return None

        return 'OLEVBA Analysis ({0} macro files) ({1})'.format(
            len(self.olevba_analysis.keys()),
            ' '.join(['{0}:{1}'.format(x, self.olevba_summary[x]) for x in self.olevba_summary.keys()]))

# DEPRECATED
class OLEVBA_Analyzer_v1_0(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return OLEVBA_Analysis_v1_0

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        pass

class OLEVBA_Analysis_v1_1(Analysis):
    """Does this office document have macros?"""

    KEY_TYPE = 'type'
    KEY_MACROS = 'macros'
    KEY_PATH = 'path'
    KEY_FILENAME = 'filename'
    KEY_STREAM_PATH = 'stream_path'
    KEY_VBA_FILENAME = 'vba_filename'
    KEY_ANALSIS = 'analysis'
    KEY_OLEVBA_SUMMARY = 'olevba_summary'

    def initialize_details(self):
        self.details = { } # free from from result of command

    @property
    def type(self):
        if not self.details:
            return None

        return self.details[OLEVBA_Analysis_v1_1.KEY_TYPE]

    @property
    def macros(self):
        if not self.details:
            return None

        if not OLEVBA_Analysis_v1_1.KEY_MACROS in self.details:
            return []

        return self.details[OLEVBA_Analysis_v1_1.KEY_MACROS]

    @property
    def olevba_summary(self):
        if not self.details:
            return None

        if not OLEVBA_Analysis_v1_1.KEY_OLEVBA_SUMMARY in self.details:
            return None

        return self.details[OLEVBA_Analysis_v1_1.KEY_OLEVBA_SUMMARY]

    def generate_summary(self):
        if not self.details:
            return None

        if not self.type:
            return None

        result = 'OLEVBA Analysis - ({} macro files) ({})'.format(len(self.macros), self.type)
        if self.olevba_summary:
            result += ' ' + ' '.join(['{}:{}'.format(x, self.olevba_summary[x]) for x in self.olevba_summary.keys()])

        return result

class OLEVBA_Analyzer_v1_1(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we use a temporary directory to extract things
        # this moves inside the storage directory if things work out
        # otherwise we need to delete it
        # so we keep track of the ones we create in this list
        # and then make sure they get cleaned up after analysis
        self.output_dirs = []

    def verify_environment(self):
        self.verify_config_exists('olevba_wrapper_path')
        self.verify_path_exists(self.config['olevba_wrapper_path'])
        #self.verify_config_exists('threshold_autoexec')
        #self.verify_config_exists('threshold_suspicious')
        self.verify_config_exists('timeout')

    @property
    def olevba_wrapper_path(self):
        return self.config['olevba_wrapper_path']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def generated_analysis_type(self):
        return OLEVBA_Analysis_v1_1

    @property
    def valid_observable_types(self):
        return F_FILE

    def _cleanup_tmpdirs(self):
        for output_dir in self.output_dirs:
            try:
                if os.path.isdir(output_dir):
                    logging.debug("removing temporary directory {}".format(output_dir))
                    shutil.rmtree(output_dir)
            except Exception as e:
                logging.error("unable to cleanup output directory {} : {}".format(output_dir, e))
                report_exception()

        # lol don't forget to do this
        self.output_dirs.clear()

    def cleanup(self):
        self._cleanup_tmpdirs()

    def execute_analysis(self, _file):
        try:
            return self._execute_analysis(_file)
        finally:
            self._cleanup_tmpdirs()

    def _execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            return False

        # so right now olevba is written in python2 :-(
        # and the output from his command line tool is difficult to parse
        # so we wrote our own

        output_dir = None
        p = None

        try:

            # we create a temporary directory to hold the output data
            output_dir = tempfile.mkdtemp(suffix='.ole', dir=saq.TEMP_DIR)
            # keep track of these so we can remove them later
            self.output_dirs.append(output_dir)
            
            olevba_wrapper_path = self.olevba_wrapper_path
            if not os.path.isabs(olevba_wrapper_path):
                olevba_wrapper_path = os.path.join(saq.SAQ_HOME, olevba_wrapper_path)
                
            p = Popen(['python2.7', olevba_wrapper_path, '-d', output_dir, local_file_path], stdout=PIPE, stderr=PIPE)
            _stdout, _stderr = p.communicate(timeout=self.timeout)

        except Exception as e:
            logging.error("olevba execution error on {}: {}".format(local_file_path, e))

            # if the file ends with a microsoft office extension then we tag it
            if is_office_ext(local_file_path):
                _file.add_tag('olevba_failed')
                _file.add_directive(DIRECTIVE_SANDBOX)

            try:
                #p.kill()
                _stdout, _stderr = p.communicate()
            except Exception as e:
                logging.error("unable to finished process {}: {}".format(p, e))

            return False

        # if the process returned with error code 2 then the parsing failed, which means it wasn't an office document format
        if p.returncode == 2:
            logging.debug("{} reported not a valid office document: {}".format(olevba_wrapper_path, local_file_path))
            return False

        if _stderr:
            _stderr = _stderr.decode(errors='ignore')
            logging.error('{} reported errors for {}: {}'.format(olevba_wrapper_path, local_file_path, _stderr))

        try:
            json_data = _stdout.decode(errors='replace').strip()
        except Exception as e:
            logging.error("unable to decode output of {} for {} as utf-8: {}".format(
                          olevba_wrapper_path, local_file_path, e))
            report_exception()
            return False

        if json_data == '':
            logging.debug("{} returned nothing for {}".format(olevba_wrapper_path, local_file_path))
            return False

        analysis = self.create_analysis(_file)

        try:
            analysis.details = json.loads(json_data)
        except Exception as e:
            logging.error("unable to parse output of {} as json: {}".format(local_file_path, e))
            report_exception()

            # remove me later... XXX
            import uuid
            _uuid = str(uuid.uuid4())
            _path = os.path.join(saq.DATA_DIR, 'review', 'misc', _uuid)
            with open(_path, 'w') as fp:
                fp.write(json_data)

            return False

        # move the temporary storage directory into the local storage directory
        try:
            target_dir = '{}.olevba'.format(local_file_path)
            shutil.move(output_dir, target_dir)
            # since the directory was created with mkdtemp, it has strict permissions
            os.chmod(target_dir, 0o0755)
        except Exception as e:
            logging.error("unable to move {} to {}: {}".format(output_dir, target_dir, e))
            report_exception()
            return False

        # did we get any macro files out?
        if analysis.macros:
            for macro_dict in analysis.macros:
                if 'path' not in macro_dict:
                    continue

                # the paths of these files are absolute paths to the temporary directory
                # but they've moved to the target_dir
                macro_relative_path = os.path.relpath(macro_dict['path'], start=output_dir)
                macro_full_path = os.path.join(target_dir, macro_relative_path)

                # is the macro file empty?
                if is_empty_macro(macro_full_path):
                    logging.debug("macro file {} appears to be empty".format(macro_relative_path))
                    continue

                file_observable = analysis.add_observable(F_FILE, os.path.relpath(macro_full_path, self.root.storage_dir))
                if file_observable:
                    file_observable.redirection = _file
                    file_observable.add_tag('macro')
                    file_observable.add_directive(DIRECTIVE_SANDBOX)
                    file_observable.add_relationship(R_EXTRACTED_FROM, _file)

        # do we have summary information?
        if not analysis.olevba_summary:
            return True

        # do the counts exceed the thresholds?
        threshold_exceeded = True
        for option in self.config.keys():
            if option.startswith("threshold_"):
                _, kw_type = option.split('_', 1)

                if kw_type not in analysis.olevba_summary:
                    logging.debug("threshold keyword {} not seen in {}".format(kw_type, local_file_path))
                    threshold_exceeded = False
                    break

                if analysis.olevba_summary[kw_type] < self.config.getint(option):
                    logging.debug("count for {} ({}) does not meet threshold {} for {}".format(
                                  kw_type, analysis.olevba_summary[kw_type], self.config.getint(option), local_file_path))
                    threshold_exceeded = False
                    break

                logging.debug("count for {} ({}) meets threshold {} for {}".format(
                    kw_type, analysis.olevba_summary[kw_type], self.config.getint(option), local_file_path))

        # all thresholds passed (otherwise we would have returned by now)
        if threshold_exceeded:
            _file.add_tag('olevba') # tag it for alerting
            _file.add_directive(DIRECTIVE_SANDBOX)

        return True

KEY_TYPE = 'type'
KEY_MACROS = 'macros'
KEY_PATH = 'path'
#KEY_FILENAME = 'filename'
#KEY_STREAM_PATH = 'stream_path'
#KEY_VBA_FILENAME = 'vba_filename'
#KEY_ANALSIS = 'analysis'
#KEY_OLEVBA_SUMMARY = 'olevba_summary'
#KEY_ALL_MACRO_CODE = 'all_macro_code'
KEY_KEYWORD_SUMMARY = 'keyword_summary'

class OLEVBA_Analysis_v1_2(Analysis):
    """Does this office document have macros?"""

    def initialize_details(self):
        self.details = {
            KEY_TYPE: None,
            KEY_MACROS: [],
            #KEY_ALL_MACRO_CODE: None,
            KEY_KEYWORD_SUMMARY: {},
        } 

    @property
    def type(self):
        return self.details_property(KEY_TYPE)

    @type.setter
    def type(self, value):
        self.details[KEY_TYPE] = value

    @property
    def macros(self):
        return self.details_property(KEY_MACROS)

    @macros.setter
    def macros(self, value):
        self.details[KEY_MACROS] = value

    #@property
    #def all_macro_code(self):
        #return self.details_property(KEY_ALL_MACRO_CODE)

    #@all_macro_code.setter
    #def all_macro_code(self, value):
        #self.details[KEY_ALL_MACRO_CODE] = value

    @property
    def keyword_summary(self):
        return self.details_property(KEY_KEYWORD_SUMMARY)

    @keyword_summary.setter
    def keyword_summary(self, value):
        self.details[KEY_KEYWORD_SUMMARY] = value

    def generate_summary(self):
        if not self.type or not self.macros:
            return None

        result = 'OLEVBA Analysis - ({} macro files) ({})'.format(len(self.macros), self.type)
        if self.macros:
            result += ' | '
            result += ', '.join(['{}={}'.format(x, self.keyword_summary[x]) for x in self.keyword_summary.keys()])

        return result

class OLEVBA_Analyzer_v1_2(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return OLEVBA_Analysis_v1_2

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            return False

        # ignore rtf files
        if is_rtf_file(local_file_path):
            return False

        # ignore MSI files
        if local_file_path.lower().endswith('.msi'):
            return False

        # ignore files we're not interested in
        if not ( is_office_ext(local_file_path) or is_ole_file(local_file_path) or is_zip_file(local_file_path) ):
            return False

        # ignore large files
        if _file.size > 1024 * 1024 * 4: # 4MB
            return False

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis:
            return False

        # sometimes we end up with HTML files with office extensions (mostly from downloaded from the Internet)
        if 'html' in file_type_analysis.mime_type:
            return False

        # ignore plain text files
        if file_type_analysis.mime_type == 'text/plain':
            return False

        analysis = self.create_analysis(_file)

        from oletools.olevba3 import VBA_Parser, VBA_Scanner, filter_vba
        parser = None

        try:
            parser = VBA_Parser(local_file_path, relaxed=True)
            analysis.type = parser.type

            current_macro_index = None
            output_dir = None

            for file_name, stream_path, vba_filename, vba_code in parser.extract_macros():
                if current_macro_index is None:
                    current_macro_index = 0
                    output_dir = '{}.olevba'.format(local_file_path)
                    if not os.path.isdir(output_dir):
                        os.mkdir(output_dir)

                output_path = os.path.join(output_dir, 'macro_{}.bas'.format(current_macro_index))

                if isinstance(vba_code, bytes):
                    vba_code = vba_code.decode('utf8', errors='ignore')

                vba_code = filter_vba(vba_code)
                if not vba_code.strip():
                    continue

                with open(output_path, 'w') as fp:
                    fp.write(vba_code)

                file_observable = analysis.add_observable(F_FILE, os.path.relpath(output_path, self.root.storage_dir))
                if file_observable:
                    file_observable.redirection = _file
                    file_observable.add_tag('macro')
                    file_observable.add_directive(DIRECTIVE_SANDBOX)
                    analysis.macros.append({'file_name': file_name,
                                            'stream_path': stream_path,
                                            'vba_filename': vba_filename,
                                            'vba_code': vba_code,
                                            'local_path': file_observable.value})

                    # this analysis module will analyze it's own output so we need to not do that
                    file_observable.exclude_analysis(self)

                current_macro_index += 1

            if analysis.macros:
                all_macro_code = '\r\n\r\n'.join([x['vba_code'] for x in analysis.macros])
                scanner = VBA_Scanner(all_macro_code)
                analysis.scan_results = scanner.scan(False, False) # setting this to True takes too long to use in prod
                analysis.keyword_summary = {}
                for _type, keyword, description in analysis.scan_results:
                    if _type not in analysis.keyword_summary:
                        analysis.keyword_summary[_type.lower()] = 0

                    analysis.keyword_summary[_type.lower()] += 1

                # do the counts exceed the thresholds?
                threshold_exceeded = True
                for option in self.config.keys():
                    if option.startswith("threshold_"):
                        _, kw_type = option.split('_', 1)

                        if kw_type not in analysis.keyword_summary:
                            logging.debug("threshold keyword {} not seen in {}".format(kw_type, local_file_path))
                            threshold_exceeded = False
                            break

                        if analysis.keyword_summary[kw_type] < self.config.getint(option):
                            logging.debug("count for {} ({}) does not meet threshold {} for {}".format(
                                          kw_type, analysis.keyword_summary[kw_type], self.config.getint(option), local_file_path))
                            threshold_exceeded = False
                            break

                        logging.debug("count for {} ({}) meets threshold {} for {}".format(
                            kw_type, analysis.keyword_summary[kw_type], self.config.getint(option), local_file_path))

                # all thresholds passed (otherwise we would have returned by now)
                if threshold_exceeded:
                    _file.add_tag('olevba') # tag it for alerting
                    _file.add_directive(DIRECTIVE_SANDBOX)
                
        except Exception as e:
            logging.warning("olevba execution error on {}: {}".format(local_file_path, e))
            #report_exception()

            # if the file ends with a microsoft office extension then we tag it
            if is_office_ext(local_file_path):
                _file.add_tag('olevba_failed')
                _file.add_directive(DIRECTIVE_SANDBOX)

            return True

        finally:
            if parser:
                try:
                    parser.close()
                except Exception as e:
                    logging.error("unable to close olevba parser: {}".format(e))
                    report_exception()

        return True

class _XMLPlainTextDumper(object):
    def __init__(self, output_path):
        self.output_path = output_path
        self._data = []

    def start(self, tag, attrib):
        for attr in attrib:
            if 'instr' in attr:
                with open(self.output_path, 'a') as fp:
                    fp.write(attrib[attr])

    def end(self, tag):
        with open(self.output_path, 'a') as fp:
            fp.write(''.join(self._data))

        self._data.clear()

    def data(self, data):
        self._data.append(data)

    def close(self):
        pass

KEY_XML_PLAIN_TEXT = 'xml_plain_text'

class XMLPlainTextAnalysis(Analysis):
    """What does the XML document look like if you remove all the XML tags?"""
    
    def initialize_details(self):
        self.details = {
            KEY_XML_PLAIN_TEXT: None,
        }
 
    def generate_summary(self):
        pass

class XMLPlainTextAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return XMLPlainTextAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            return False

        if _file.value.endswith('.noxml'):
            return False

        # make sure this is an XML document
        with open(local_file_path, 'rb') as fp:
            data = fp.read(1024)

        if b'<?xml' not in data:
            logging.debug("{} is not an XML document".format(local_file_path))
            return False

        # this file must have been extracted from a word document
        source_document = [r.target for r in _file.relationships if r.r_type == R_EXTRACTED_FROM]
        if not source_document:
            logging.debug("file {} was not extracted from anything".format(_file.value))
            return False

        source_document = source_document[0]
        if not source_document.has_tag('microsoft_office'):
            logging.debug("file {} was not tagged as microsoft_office".format(_file.value))
            return False

        output_path = '{}.noxml'.format(local_file_path)
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception as e:
                logging.error("unable to delete {}: {}".format(output_path, e))

        analysis = self.create_analysis(_file)

        parser = etree.XMLParser(target=_XMLPlainTextDumper(output_path))
        try:
            etree.parse(local_file_path, parser)
            if os.path.exists(output_path) and os.path.getsize(output_path):
                _file = analysis.add_observable(F_FILE, os.path.relpath(output_path, start=self.root.storage_dir))
                if _file:
                    analysis.details = { KEY_XML_PLAIN_TEXT : _file.value }
        except Exception as e:
            logging.warning("unable to parse XML file {}: {}".format(_file.value, e))

        return True
        
class _XMLParser(object):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.output_path = None
        self._data = []
        self.extracted_files = []
        self.path = []

    def start(self, tag, attrib):
        if tag == PART_TAG:
            if PART_NAME in attrib:
                file_name = _safe_filename(attrib[PART_NAME])
                self.output_path = os.path.join(self.output_dir, file_name[1:])

        if tag == DATA_TAG:
            self._data.clear()

    def end(self, tag):
        if tag == DATA_TAG and self.output_path and self._data:
            try:
                if not os.path.isdir(os.path.dirname(self.output_path)):
                    os.makedirs(os.path.dirname(self.output_path))

                logging.debug("extracting base64 encoded XML binary data into {}".format(self.output_path))
                with open(self.output_path, 'wb') as fp:
                    fp.write(base64.b64decode(''.join(self._data)))

                self.extracted_files.append(self.output_path)

            except Exception as e:
                logging.error("unable to extract base64 encoded data: {}".format(e))

            finally:
                self._data.clear()
                self.output_path = None

    def data(self, data):
        if self.output_path:
            self._data.append(data)

    def close(self):
        return self.extracted_files

PART_TAG = '{http://schemas.microsoft.com/office/2006/xmlPackage}part'
PART_NAME = '{http://schemas.microsoft.com/office/2006/xmlPackage}name'
DATA_TAG = '{http://schemas.microsoft.com/office/2006/xmlPackage}binaryData'

class XMLBinaryDataAnalysis(Analysis):
    def initialize_details(self):
        self.details = []

    def generate_summary(self):
        if not self.details:
            return None

        return 'XML Binary Data Analysis ({} files extracted)'.format(len(self.details))

class XMLBinaryDataAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return XMLBinaryDataAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            return False

        # make sure this is an XML document
        with open(local_file_path, 'rb') as fp:
            data = fp.read(1024)
        
        if b'<?xml' not in data:
            logging.debug("{} is not an XML document".format(local_file_path))
            return False

        if b'Word.Document' not in data:
            logging.debug("{} is not a Word.Document".format(local_file_path))
            return False

        try:

            analysis = self.create_analysis(_file)
            parser = etree.XMLParser(target=_XMLParser('{}.xml'.format(local_file_path)))
            extracted_files = etree.parse(local_file_path, parser)

            for extracted_file in extracted_files:
                rel_path = os.path.relpath(extracted_file, start=self.root.storage_dir)
                analysis.add_observable(F_FILE, rel_path)
                analysis.details.append(rel_path)

        except Exception as e:
            logging.info("xml parsing failed for {}: {}".format(local_file_path, e))
            return False

        return True

class OfficeParserAnalysis_v1_0(Analysis):
    """Does this OLE file have macros or olenative streams?"""

    def initialize_details(self):
        self.details = []

    def generate_summary(self):
        if not self.details:
            return None

        if not isinstance(self.details, list):
            return None

        return "OfficeParser Analysis ({} macro files)".format(len(self.details))

class OfficeParserAnalyzer_v1_0(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('officeparser_path')
        self.verify_path_exists(self.config['officeparser_path'])
        self.verify_config_exists('timeout')

    @property
    def officeparser_path(self):
        return self.config['officeparser_path']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def generated_analysis_type(self):
        return OfficeParserAnalysis_v1_0

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            return False

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return False

        # is this an OLE document?
        with open(local_file_path, 'rb') as fp:
            header = fp.read(8)
            
            if header != b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                logging.debug("{} is not an OLE Compound Document".format(local_file_path))
                return False

        # make sure this is not an MSI file
        if local_file_path.lower().endswith('.msi'):
            logging.debug("not extracting MSI file {}".format(_file.value))
            return False

        if file_type_analysis.file_type and 'windows installer' in file_type_analysis.file_type.lower():
            logging.debug("not extracting windows installer file {}".format(_file.value))
            return False

        officeparser_output_dir = '{}.officeparser'.format(local_file_path)
        if not os.path.isdir(officeparser_output_dir):
            try:
                os.makedirs(officeparser_output_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(
                    officeparser_output_dir, str(e)))
                return False

        # lol look at all these options
        p = Popen([
            'python2.7',
            self.officeparser_path,
            '-l', 'DEBUG',
            '--print-header',
            '--print-directory',
            '--print-fat',
            '--print-mini-fat',
            '--print-streams',
            '--print-expected-file-size',
            '--print-invalid-fat-count',
            '--check-stream-continuity',
            '--check-fat',
            '--check-orphaned-chains',
            '-o', officeparser_output_dir,
            '--extract-streams',
            '--extract-ole-streams',
            '--extract-macros',
            '--extract-unknown-sectors',
            '--create-manifest',
            local_file_path],
            stdout=PIPE,
            stderr=PIPE)

        try:
            stdout, stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired as e:
            logging.warning("timeout expired for officeparser on {}".format(local_file_path))
            _file.add_tag('officeparser_failed')
            _file.add_directive(DIRECTIVE_SANDBOX)

            #try:
                #p.kill()
            #except:
                #pass

            stdout, stderr = p.communicate()

        manifest_path = os.path.join(officeparser_output_dir, 'manifest')
        if not os.path.exists(manifest_path):
            #logging.warning("manifest {0} is missing".format(manifest_path))
            return False

        analysis = self.create_analysis(_file)

        with open(manifest_path, 'rb') as fp:
            while True:
                try:
                    output_file = fp.readline().decode()
                except Exception as e:
                    logging.warning("trouble reading {}: {}".format(manifest_path, e))
                    continue

                if output_file == '':
                    break
            
                output_file = output_file.strip()
                logging.debug("got extracted file {} from {}".format(output_file, local_file_path))

                # we don't want to add the stream_N_N.dat files
                # after running this thing for a year we have never seen this be useful
                # 5/10/2017 - due to CVE 2017-0199 this is no longer the case

                full_path = os.path.join(officeparser_output_dir, output_file)
                # only add normal files
                try:
                    if not os.path.isfile(full_path):
                        logging.info("skipping non-file {}".format(full_path))
                        continue
                except Exception as e:
                    logging.error("unable to check status of {}".format(full_path))
                    continue

                # and do not add if the file is empty
                try:
                    if not os.path.getsize(full_path):
                        logging.debug("skipping empty file {}".format(full_path))
                        continue
                except Exception as e:
                    logging.error("unable to check size of {}: {}".format(full_path, e))
                    report_exception()

                # if this is a macro file we want to see if it is an "empty macro file"
                if is_macro_ext(output_file):
                    if is_empty_macro(full_path):
                        logging.debug("macro file {} appears to be empty".format(full_path))
                        continue

                # and then FILE type indicators are relative to the alert storage directory
                file_observable = analysis.add_observable(F_FILE, 
                    os.path.relpath(full_path, start=self.root.storage_dir))

                if not file_observable:
                    continue

                # add a relationship back to the original file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)

                # extract URLs from these files
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)

                # point actions back at the source ole file
                file_observable.redirection = _file

                if is_macro_ext(output_file):
                    file_observable.add_tag('macro')
                    # always sandbox office documents tagged with macros
                    file_observable.add_directive(DIRECTIVE_SANDBOX)
                    analysis.details.append(output_file)

            return True

class OLEArchiverAnalysis_v1_0(Analysis):
    """What is the path to the archived copy of this file?"""

    def initialize_details(self):
        self.details = {
            'archive_path': None,
        }

    @property
    def archive_path(self):
        return self.details['archive_path']

    @archive_path.setter
    def archive_path(self, value):
        self.details['archive_path'] = value

class OLEArchiver_v1_0(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('ole_archive_dir')
        self.verify_path_exists(self.config['ole_archive_dir'])

    @property
    def ole_archive_dir(self):
        result = self.config['ole_archive_dir']
        if os.path.isabs(result):
            return result

        return os.path.join(saq.SAQ_HOME, result)

    @property
    def generated_analysis_type(self):
        return OLEArchiverAnalysis_v1_0

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            return False

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return False

        # and the file hash analysis
        hash_analysis = self.wait_for_analysis(_file, FileHashAnalysis)
        if hash_analysis is None:
            return False

        if hash_analysis.md5 is None:
            logging.debug("no hash available for {} - no archiving possible".format(local_file_path))
            return False

        if not file_type_analysis.is_ole_file and not file_type_analysis.is_office_ext:
            logging.debug("not archiving {} as ole file".format(local_file_path))
            return False

        logging.debug("archiving {} as OLE file".format(local_file_path))
        analysis = self.create_analysis(_file)

        # archive the file by md5
        dest_dir = os.path.join(self.ole_archive_dir, hash_analysis.md5[0:2])
        if not os.path.exists(dest_dir):
            logging.debug("creating directory {}".format(dest_dir))
            try:
                os.mkdir(dest_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(dest_dir, e))
                report_exception()
                return False

        dest_path = os.path.join(dest_dir, hash_analysis.md5)
        try:
            shutil.copy(local_file_path, dest_path)
        except Exception as e:
            logging.error("unable to copy {} to {}: {}".format(local_file_path, dest_path, e))
            report_exception()
            return False

        # and then save some meta data about it
        with open('{}.meta'.format(dest_path), 'w') as fp:
            fp.write('{}\n'.format(local_file_path))

        analysis.archive_path = dest_path
        return True

# DEPRECATED
class CompoundFileAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super(CompoundFileAnalysis, self).__init__(*args, **kwargs)

    def add_extracted_file(self, _file):
        self.details['extracted_files'].append(_file)

    @property
    def jinja_template_path(self):
        return "analysis/compound_file.html"

    def generate_summary(self):
        if self.details is not None and len(self.details['extracted_files']) > 0:
            return "Compound File Analysis ({0} extracted files)".format(
                len(self.details['extracted_files']))
        return None

class FileTypeAnalysis(Analysis):
    """What kind of file is this?"""

    def initialize_details(self):
        self.details = { 
            'type': None, 
            'mime': None }

    @property
    def file_type(self):
        if self.details is None:
            return None

        if 'type' not in self.details:
            return None

        return self.details['type']

    @property
    def mime_type(self):
        if self.details is None:
            return None

        if 'mime' not in self.details:
            return None

        return self.details['mime']

    @property
    def is_office_ext(self):
        if not self.details:
            return False

        if 'is_office_ext' not in self.details:
            return False

        return self.details['is_office_ext']

    @property
    def is_ole_file(self):
        if not self.details:
            return False

        if 'is_ole_file' not in self.details:
            return False

        return self.details['is_ole_file']

    @property
    def is_rtf_file(self):
        if not self.details:
            return False

        if 'is_rtf_file' not in self.details:
            return False

        return self.details['is_rtf_file']

    @property
    def is_pdf_file(self):
        if not self.details:
            return False

        if 'is_pdf_file' not in self.details:
            return False

        return self.details['is_pdf_file']

    @property
    def is_pe_file(self):
        if not self.details:
            return False

        if 'is_pe_file' not in self.details:
            return False

        return self.details['is_pe_file']

    @property
    def is_zip_file(self):
        if not self.details:
            return False

        if 'is_zip_file' not in self.details:
            return False

        return self.details['is_zip_file']

    @property
    def is_office_document(self):
        if not self.details:
            return False

        if 'is_office_document' not in self.details:
            return False

        return self.details['is_office_document']

    def generate_summary(self):
        if self.details['type'] is not None:
            return "File Type Analysis: ({0}) ({1})".format(
                self.details['type'] if self.details['type'] else '',
                self.details['mime'] if self.details['mime'] else '')
        return None

class FileTypeAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FileTypeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
    
    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        logging.debug("analyzing file {}".format(local_file_path))
        analysis = self.create_analysis(_file)

        # get the human readable
        p = Popen(['file', '-b', '-L', local_file_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        
        if len(stderr) > 0:
            logging.warning("file command returned error output for {0}".format(local_file_path))

        analysis.details['type'] = stdout.decode().strip()

        # get the mime type
        p = Popen(['file', '-b', '--mime-type', '-L', local_file_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        
        if len(stderr) > 0:
            logging.warning("file command returned error output for {0}".format(local_file_path))

        analysis.details['mime'] = stdout.decode().strip()

        analysis.details['is_office_ext'] = is_office_ext(local_file_path)
        analysis.details['is_ole_file'] = is_ole_file(local_file_path)
        analysis.details['is_rtf_file'] = is_rtf_file(local_file_path)
        analysis.details['is_pdf_file'] = is_pdf_file(local_file_path)
        analysis.details['is_pe_ext'] = is_pe_file(local_file_path)
        analysis.details['is_zip_file'] = is_zip_file(local_file_path)

        is_office_document = analysis.details['is_office_ext']
        is_office_document |= 'microsoft powerpoint' in analysis.file_type.lower()
        is_office_document |= 'microsoft excel' in analysis.file_type.lower()
        is_office_document |= 'microsoft word' in analysis.file_type.lower()
        is_office_document |= 'microsoft ooxml' in analysis.file_type.lower()
        is_office_document |= analysis.details['is_ole_file']
        is_office_document |= analysis.details['is_rtf_file']
        analysis.details['is_office_document'] = is_office_document

        # perform some additional analysis for some things we care about

        if is_office_document:
            _file.add_tag('microsoft_office')

        if analysis.is_ole_file:
            _file.add_tag('ole')

        if analysis.is_rtf_file:
            _file.add_tag('rtf')

        if analysis.is_pdf_file:
            _file.add_tag('pdf')

        if analysis.is_pe_file:
            _file.add_tag('executable')

        if analysis.is_zip_file:
            _file.add_tag('zip')

        return True

class PDFAnalysis(Analysis):
    def initialize_details(self):
        pass # nothing generated

class PDFAnalyzer(AnalysisModule):
    """What is the raw PDF data after removing stream filters?"""

    def verify_environment(self):
        self.verify_config_exists('pdfparser_path')
        self.verify_path_exists(self.config['pdfparser_path'])

    @property
    def pdfparser_path(self):
        return self.config['pdfparser_path']

    @property
    def generated_analysis_type(self):
        return PDFAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file.value))
            return False

        # do not analyze our own output
        if local_file_path.endswith('.pdfparser'):
            return False

        # this file must actually be a PDF
        with open(local_file_path, 'rb') as fp:
            # the header can be anywhere in the first 1024 bytes
            # they released a change to the spec
            header = fp.read(1024)
            if b'%PDF-' not in header:
                #logging.debug("{0} is not a PDF file".format(local_file_path))
                return False

        logging.debug("analyzing file {}".format(local_file_path))
        analysis = self.create_analysis(_file)

        # we'll create an output file for the output of the pdf analysis
        pdfparser_output_file = '{}.pdfparser'.format(local_file_path)

        # run pdf parser
        with open(pdfparser_output_file, 'wb') as fp:
            p = Popen(['python2.7', self.pdfparser_path,
            '-f', '-w', '-v', '-c', '--debug', local_file_path], stdout=fp, stderr=PIPE)
            try:
                _, stderr = p.communicate(timeout=10)
            except TimeoutExpired as e:
                logging.warning("pdfparser timed out on {}".format(local_file_path))
                #p.kill()
                _, stderr = p.communicate()

        if len(stderr) > 0:
            logging.warning("pdfparser returned errors for {}".format(local_file_path))

        # add the output file as a new file to scan
        # the FILE type indicators are relative to the alert storage directory
        file_observable = analysis.add_observable(F_FILE, 
            os.path.relpath(pdfparser_output_file, start=self.root.storage_dir))

        if file_observable:
            # point actions back at the source ole file
            file_observable.redirection = _file
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            # extract URLs from this file
            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)

        return True

KEY_STDOUT = 'stdout'
KEY_STDERR = 'stderr'
KEY_OUTPUT_PATH = 'output_path'

class PDFTextAnalysis(Analysis):
    """Converts a PDF to text for simple yara scanning."""

    def initialize_details(self):
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_OUTPUT_PATH: None,
        }

    @property
    def stdout(self):
        return self.details_property(KEY_STDOUT)

    @stdout.setter
    def stdout(self, value):
        self.details[KEY_STDOUT] = value

    @property
    def stderr(self):
        return self.details_property(KEY_STDERR)

    @stderr.setter
    def stderr(self, value):
        self.details[KEY_STDERR] = value

    @property
    def output_path(self):
        return self.details_property(KEY_OUTPUT_PATH)

    @output_path.setter
    def output_path(self, value):
        self.details[KEY_OUTPUT_PATH] = value

    def generate_summary(self):
        if not self.output_path:
            return None
        
        return "PDF Text Analysis"
    
class PDFTextAnalyzer(AnalysisModule):

    @property
    def pdftotext_path(self):
        return self.config['pdftotext_path']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    def verify_environment(self):
        self.verify_config_exists('pdftotext_path')
        self.verify_path_exists(self.config['pdftotext_path'])

    @property
    def generated_analysis_type(self):
        return PDFTextAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        
        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # is this a PDF file?
        if not is_pdf_file(local_file_path):
            logging.debug("{} is not a pdf file".format(local_file_path))
            return False

        analysis = self.create_analysis(_file)

        output_path = '{}.pdf_txt'.format(local_file_path)
        p = Popen([self.pdftotext_path, local_file_path, output_path], stdout=PIPE, stderr=PIPE)
        try:
            analysis.stdout, analysis.stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired as e:
            logging.error("timeout out executing {} on {}".format(self.pdftotext_path, local_file_path))
            return False
        
        if len(analysis.stderr) > 0:
            logging.debug("pdftotext returned errors for {}".format(local_file_path))

        # add the output file as a new file to scan
        # the FILE type indicators are relative to the alert storage directory
        if os.path.exists(output_path):
            file_observable = analysis.add_observable(F_FILE, os.path.relpath(output_path, start=self.root.storage_dir))

            if file_observable:
                # point actions back at the source ole file
                file_observable.redirection = _file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                analysis.output_path = file_observable.value

        return True

# DEPRECATED
class YaraScanResults(Analysis):
    @property
    def jinja_template_path(self):
        return 'analysis/yara_analysis.html'

    def generate_summary(self):
        if self.details is not None:
            return "Yara Scan Results: {0} results".format(len(self.details))
        return None

class YaraScanResults_v3_4(Analysis):
    """What yara rules match this file?"""

    def initialize_details(self):
        self.details = []

    @property
    def jinja_template_path(self):
        return 'analysis/yara_analysis_v3_4.html'

    def generate_summary(self):
        if self.details is not None:
            return "Yara Scan Results: {0} results".format(len(self.details))
        return None

#
# this module has two modes of operation
# the default mode is to use the Yara Scanner Server (see /opt/yara_scanner)
# if this is unavailable then local yara scanning will be used until the server is available again
#

class YaraScanner_v3_4(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('context_bytes')
        self.verify_config_exists('local_scanner_lifetime')

    @property
    def context_bytes(self):
        return self.config.getint('context_bytes')

    @property
    def local_scanner_lifetime(self):
        """The amount of time (in minutes) a local scanner is used before it expires."""
        return self.config.getint('local_scanner_lifetime')

    @property
    def base_dir(self):
        """Base directory of the yara_scanner server."""
        return saq.YSS_BASE_DIR

    @property
    def socket_dir(self):
        """Relative directory of the socket directory of the yara scanner server."""
        return saq.YSS_SOCKET_DIR

    @property
    def generated_analysis_type(self):
        return YaraScanResults_v3_4

    @property
    def valid_observable_types(self):
        return F_FILE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        #self.blacklist_path = os.path.join(saq.SAQ_HOME, saq.CONFIG['yara']['blacklist_path'])
        #self.blacklisted_rules = []

        # this is where we place files that fail scanning
        self.scan_failure_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['yara']['scan_failure_dir'])
        if not os.path.exists(self.scan_failure_dir):
            try:
                os.makedirs(self.scan_failure_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(self.scan_failure_dir, str(e)))
                report_exception()
                self.scan_failure_dir = None

        # in the case where the yara scanning server is unavailable a local scanner is used
        self.scanner = None

        # we use it for N minutes defined in the configuration
        self.scanner_start_time = None

    def initialize_local_scanner(self):
        logging.info("initializing local yara scanner")
        # initialize the scanner and compile the rules
        self.scanner = yara_scanner.YaraScanner()

        # load yara dirs and repos
        for option in saq.CONFIG['yara'].keys():
            if option.startswith('signature_dir'):
                self.scanner.track_yara_dir(os.path.join(saq.SAQ_HOME, saq.CONFIG['yara'][option]))
            elif option.startswith('signature_repo'):
                self.scanner.track_yara_repository(os.path.join(saq.SAQ_HOME, saq.CONFIG['yara'][option]))
            elif option.startswith('signature_file'):
                self.scanner.track_yara_file(os.path.join(saq.SAQ_HOME, saq.CONFIG['yara'][option]))

        self.scanner.load_rules()
        self.scanner_start_time = datetime.datetime.now()
        #self.load_blacklist()

    #def load_blacklist(self):
        #if self.scanner is None:
            #return

        # load the list of blacklisted rules
        #if os.path.exists(self.blacklist_path):
            #try:
                #with open(self.blacklist_path, 'r') as fp:
                    #for line in fp:
                        #self.blacklisted_rules.append(line.strip())

                #logging.debug("loaded {0} blacklisted rules from {1}".format(len(self.blacklisted_rules), self.blacklist_path))
                #self.blacklist_mtime = os.path.getmtime(self.blacklist_path)

                #self.scanner.blacklist = self.blacklisted_rules

            #except Exception as e:
                #logging.error("unable to load blacklist file {0}: {1}".format(self.blacklist_path, str(e)))
                #report_exception()
        #else:
            #logging.warning("blacklist file {0} does not exist".format(self.blacklist_path))

    def auto_reload(self):
        # have the signatures changed?
        #logging.debug("checking for rule modifications")
        if self.scanner:
            if self.scanner.check_rules():
                logging.info("detected yara rules modification - reloading")
                self.scanner.load_rules()

        # did the blacklist change?
        #try:
            #if self.blacklist_mtime is None or self.blacklist_mtime != os.path.getmtime(self.blacklist_path):
                #self.load_blacklist()
        #except Exception as e:
            #logging.error("unable to check blacklist {0}: {1}".format(self.blacklist_path, str(e)))

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file.value))
            return False

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return False

        # skip files that we do not want to scan with yara
        if _file.has_directive(DIRECTIVE_NO_SCAN):
            logging.debug("skipping yara scan of file {} (directive {})".format(_file, DIRECTIVE_NO_SCAN))
            return False

        analysis = None

        # scan it with yara
        try:
            no_alert_rules = set() # the set of rules that matches that have the no_alert modifier
            matches_found = False # set to True if at least one rule matched

            try:
                # this path needs to be absolute for the yara scanner server to know where to find it
                _full_path = local_file_path
                if not os.path.isabs(local_file_path):
                    _full_path = os.path.join(os.getcwd(), local_file_path)
                result = yara_scanner.scan_file(_full_path, base_dir=self.base_dir, socket_dir=self.socket_dir)
                matches_found = bool(result)

                logging.debug("scanned file {} with yss (matches found: {})".format(_full_path, matches_found))

                # if that worked and we have a local scanner see if we still need it
                # we keep it around for some length of time
                # even when we get the yara scanner server back
                if self.scanner:
                    if (datetime.datetime.now() - self.scanner_start_time).total_seconds() * 60 >= self.local_scanner_lifetime:
                        # get rid of it
                        logging.info("releasing local yara scanner")
                        self.scanner = None
                        self.scanner_start_time = None
                        gc.collect()
                
            except socket.error as e:
                logging.warning("failed to connect to yara socket server: {}".format(e))
                if not self.scanner:
                    self.initialize_local_scanner()

                matches_found = self.scanner.scan(local_file_path)
                result = self.scanner.scan_results
                # we want to keep using it for now...
                self.scanner_start_time = datetime.datetime.now()

            #if self.scanner.scan(local_file_path):
            if matches_found:
                logging.info("got yara results for {}".format(local_file_path))
                analysis = self.create_analysis(_file)
                analysis.details = result
                #logging.debug("MARKER: {}".format(analysis.details))

                # yara rules can have a meta directive called "modifiers" that changes how the results are interpreted
                # the value is a list of modifiers accepted as listed
                # no_alert - this rule alone does not generate an alert
                # directive=VALUE - add the given directive to the file being scanned where VALUE is the directive to add
                # anything that matches a yara rule is considered suspect

                alertable = False # initially set to False until we hit at least one rule that does NOT have the no_alert modifier
                for match_result in analysis.details:
                    if 'modifiers' in match_result['meta']:
                        modifier_no_alert = False
                        modifiers = [x.strip() for x in match_result['meta']['modifiers'].split(',')]
                        logging.debug("yara rule {} has modifiers {}".format(match_result['rule'], ','.join(modifiers)))
                        for modifier in modifiers:
                            if modifier == 'no_alert':
                                modifier_no_alert = True
                                no_alert_rules.add(match_result['rule'])
                                continue

                            if modifier.startswith('directive'):
                                key, modifier_directive = modifier.split('=', 1)
                                if modifier_directive not in VALID_DIRECTIVES:
                                    logging.warning("yara rule {} attempts to add invalid directive {}".format(match_result['rule'], modifier_directive))
                                else:
                                    logging.debug("assigned directive {} to {} by modifiers on yara rule {}".format(
                                                  modifier_directive, _file, match_result['rule']))
                                    _file.add_directive(modifier_directive)

                                continue

                            logging.warning("unknown modifier {} used in rule {}".format(modifier, match_result['rule']))
                            continue

                        # did at least one rule NOT have the no_alert modifier?
                        if not modifier_no_alert:
                            alertable = True
                    else:
                        # no modifiers at all?
                        alertable = True

                # if any rule matches (that does not have the no_alert modifier) then the whole thing becomes an alert
                if alertable:
                    #_file.add_tag('yara')
                    _file.add_directive(DIRECTIVE_SANDBOX)
                else:
                    logging.debug("yara results for {} only include rules with no_alert modifiers".format(local_file_path))
            else:
                logging.debug("no yara results for {}".format(local_file_path))
                return True
        except Exception as e:
            #report_exception()
            logging.error("error scanning file {}: {}".format(local_file_path, e))
            
            # we copy the files we cannot scan to a directory where we can debug it later
            if self.scan_failure_dir is not None:
                try:
                    dest_path = os.path.join(self.scan_failure_dir, os.path.basename(local_file_path))
                    while os.path.exists(dest_path):
                        dest_path = '{}_{}'.format(dest_path, datetime.datetime.now().strftime('%Y%m%d%H%M%S-%f'))

                    shutil.copy(local_file_path, dest_path)
                    logging.debug("copied {} to {}".format(local_file_path, dest_path))
                except Exception as e:
                    logging.error("unable to copy {} to {}: {}".format(local_file_path, self.scan_failure_dir, e))
                    report_exception()
            
            return False

        if not analysis:
            return False

        for yara_result in analysis.details:
            rule_observable = analysis.add_observable(F_YARA_RULE, yara_result['rule'])
            if rule_observable is None:
                continue

            # if this yara rule did not have the no_alert modifier then it becomes a detection point
            if yara_result['rule'] not in no_alert_rules:
                rule_observable.add_detection_point("{} matched yara rule {}".format(_file, yara_result['rule']))

            # if the name of the rule stars with "crits" then we also want to add indicators as observables
            if yara_result['rule'].lower().startswith('crits'):
                for string_match in yara_result['strings']:
                    position, string_id, value = string_match
                    # example: '0x45cf:$5537d11dbcb87f5c8053ae55: /webstat/image.php?id='
                    m = re.match(r'^\$([a-fA-F0-9]{24})$', string_id)
                    if m:
                        analysis.add_observable(F_INDICATOR, m.group(1))

            yara_result['context'] = []
            for position, string_id, value in yara_result['strings']:
                # we want some context around what we matched
                start_byte = position - self.context_bytes
                if start_byte < 0:
                    start_byte = 0

                length = self.context_bytes + len(value) + self.context_bytes

                with open(local_file_path, 'rb') as fp:
                    try:
                        fp.seek(start_byte)
                        context_data = fp.read(length)
                    except Exception as e:
                        logging.error("unable to seek to position {} in {}: {}".format(start_byte, local_file_path, e))
                        report_exception()

                    p = Popen(['hexdump', '-C'], stdin=PIPE, stdout=PIPE)
                    p.stdin.write(context_data)
                    stdout, _ = p.communicate()
                    p.wait()
                    yara_result['context'].append([position, string_id, value, stdout])

            # did this rule have any tags?
            for tag in yara_result['tags']:
                #rule_observable.add_tag(tag)
                _file.add_tag(tag)

        return True

# DEPRECATED
class CuckooSandboxAnalysis(Analysis):
    def generate_summary(self):
        if self.details is not None:
            return "Cuckoo Sandbox Analysis ({0} reports)".format(len(self.details.keys()))
        return None

# DEPRECATED
class CuckooSandboxAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return CuckooSandboxAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return

        # and file hash analysis
        file_hash_analysis = self.wait_for_analysis(_file, FileHashAnalysis)
        if file_hash_analysis is None:
            return

        analysis = CuckooSandboxAnalysis()
        _file.add_analysis(analysis)

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file.value))
            return

        # there are only certain things we'll analyze
        valid_type = False
        
        # valid by file extension
        if not valid_type:
            for valid_file_extension in saq.CONFIG[self.config_section]['valid_file_extension'].split(','):
                valid_file_extension = valid_file_extension.strip()
                if valid_file_extension == '':
                    continue

                # ignore leading dot in case user forgot
                if valid_file_extension.startswith('.'):
                    valid_file_extension = valid_file_extension[1:]

                if local_file_path.lower().endswith('.{0}'.format(valid_file_extension.lower())):
                    logging.debug("valid file extension {0} for {1}".format(valid_file_extension, local_file_path))
                    valid_type = True
                    break

        if not valid_type:
            # valid by mime type
            for valid_mime_type in saq.CONFIG[self.config_section]['valid_mime_type'].split(','):
                valid_mime_type = valid_mime_type.strip()
                if valid_mime_type == '':
                    continue

                if file_type_analysis.mime_type.lower().startswith(valid_mime_type.lower()):
                    logging.debug("valid mime type {0} for {1}".format(valid_mime_type, local_file_path))
                    valid_type = True
                    break

        if not valid_type:
            # valid by file type (human readable)
            for valid_file_type in saq.CONFIG[self.config_section]['valid_file_type'].strip().split(','):
                valid_file_type = valid_file_type.strip()
                if valid_file_type == '':
                    continue

                # note that these are just substring matches
                if valid_file_type.lower() in file_type_analysis.file_type:
                    logging.debug("valid file type {0} for {1}".format(valid_file_type, local_file_path))
                    valid_type = True
                    break

        # the rest are valid by file header
        if not valid_type:
            with open(local_file_path, 'rb') as fp:
                header = fp.read(1024)
                if b'%PDF-' in header:
                    logging.debug("valid by header (pdf)")
                    valid_type = True

        if not valid_type:
            with open(local_file_path, 'rb') as fp:
                header = fp.read(8)
                if header == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                    logging.debug("valid by header (compound document)")
                    valid_type = True

        if not valid_type:
            with open(local_file_path, 'rb') as fp:
                header = fp.read(2)
                if header == b'MZ':
                    logging.debug("valid by header (mz)")
                    valid_type = True

        if not valid_type:
            with open(local_file_path, 'rb') as fp:
                header = fp.read(4)
                if header == b'\\rtf':
                    logging.debug("valid by header (rtf)")
                    valid_type = True

        if not valid_type:
            logging.debug("file {0} is not a valid file type for cuckoo analysis".format(local_file_path))
            return

        logging.info("performing cuckoo analysis of {0}".format(local_file_path))

        # main processing loop
        # so this whole thing depends on nate's sandbox stuff
        # copy this file to the processing directory
        # this will kick off the analysis
        try:
            # make sure the file doesn't already exist in the processing directoy
            if not os.path.exists(os.path.join(saq.CONFIG[self.config_section]['processing_dir'], file_hash_analysis.md5.lower())):
                shutil.copy2(local_file_path, saq.CONFIG[self.config_section]['drop_dir'])
            else:
                logging.debug("sandbox is currently processing {0}".format(local_file_path))
        except Exception as e:
            logging.error("unable to copy {0} to {1}: {2}".format(
                local_file_path,
                saq.CONFIG[self.config_section]['drop_dir'],
                str(e)))

            return

        # and then we wait for a directory to appear in the "pickup" directory
        # with a name equal to the md5 hash of the file
        # we keep looking for N seconds until we give up
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=int(saq.CONFIG[self.config_section]['max_wait']))
        result_dir = os.path.join(saq.CONFIG[self.config_section]['pickup_dir'], file_hash_analysis.md5.lower())

        while True:
            # do the results exist?
            logging.debug("checking for sandbox results of {0} md5 {1}".format(local_file_path, file_hash_analysis.md5))
            if os.path.isdir(result_dir):
                logging.debug("found {0}".format(result_dir))
                break

            if datetime.datetime.now() > end_time:
                logging.warning("cuckoo sandbox analysis timed ot for {0} md5 {1}".format(local_file_path, file_hash_analysis.md5))
                return

            # make sure we're not shutting down
            # TODO

            # wait for a second and look again
            time.sleep(1)

        analysis.details = {}

        # ok if we found it then we get the results from the files inside, eh?
        # the reports are named report_0.json, report_1.json, etc...
        report_number = 0
        while True:
            report_path = os.path.join(result_dir, 'report_{0}.json'.format(report_number))
            if os.path.exists(report_path):
                logging.debug("got sandbox report file {0} for {1}".format(report_path, local_file_path))
                with open(report_path) as fp:
                    try:
                        #analysis.details[os.path.basename(report_path)] = json.load(fp)
                        sandbox_report = json.load(fp)
                        # all we really want out of this is the report name and number for link generation
                        analysis.details[str(report_number)] = { 
                            'machine': sandbox_report['info']['machine']['label'],
                            'id': sandbox_report['info']['machine']['id'] }
                        
                        # and observables of course :-)
                        if 'network' in sandbox_report:
                            network_report = sandbox_report['network']
                            if 'domains' in network_report:
                                fqdn_report = network_report['domains']
                                for item in fqdn_report:
                                    analysis.add_observable(F_FQDN, item['domain'])

                            for protocol in [ 'udp', 'tcp' ]:
                                if protocol in network_report:
                                    protocol_report = network_report[protocol]
                                    for item in protocol_report:
                                        for ipv4 in [ item['src'], item['dst'] ]:
                                            if ipv4 in rfc1918:
                                                continue

                                            analysis.add_observable(F_IPV4, ipv4)

                            if 'http' in network_report:
                                http_report = network_report['http']
                                for item in http_report:
                                    if 'uri' in item and len(item['uri']) > 0:
                                        analysis.add_observable(F_URL, item['uri'])
                                    #if 'user-agent' in item and len(item['user-agent']) > 0:
                                        #analysis.add_observable(F_INDICATOR

                        if 'dropped' in sandbox_report:
                            dropped_report = sandbox_report['dropped']
                            for item in dropped_report:
                                if 'md5' in item and len(item['md5']) > 0:
                                    analysis.add_observable(F_MD5, item['md5'])
                                if 'sha1' in item and len(item['sha1']) > 0:
                                    analysis.add_observable(F_SHA1, item['sha1'])
                                if 'sha256' in item and len(item['sha256']) > 0:
                                    analysis.add_observable(F_SHA256, item['sha256'])
                                if 'name' in item and len(item['name']) > 0:
                                    analysis.add_observable(F_FILE, item['name'])
                    except Exception as e:
                        logging.error("unable to load cuckoo report from json file {0}: {1}".format(
                            report_path, str(e)))

            else:
                break

            report_number += 1

        logging.debug("complete cuckoo analysis for {0}".format(local_file_path))

class ExtractedOLEAnalysis(Analysis):
    def initialize_details(self):
        self.details = []

    def generate_summary(self):
        if not self.details:
            return None

        return "Extracted OLE Analysis - ({})".format(','.join(self.details))

class ExtractedOLEAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('suspect_file_type')
        self.verify_config_exists('suspect_file_ext')

    @property
    def suspect_file_type(self):
        return map(lambda x: x.strip(), self.config['suspect_file_type'].split(','))

    @property
    def suspect_file_ext(self):
        return map(lambda x: x.strip(), self.config['suspect_file_ext'].split(','))

    @property
    def generated_analysis_type(self):
        return ExtractedOLEAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
    
    def execute_analysis(self, _file):
        # gather all the requirements for all the things we want to check
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return False

        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return

        # is this _file an output of the OfficeParserAnalysis?
        if any([isinstance(a, OfficeParserAnalysis_v1_0) for a in self.root.iterate_all_references(_file)]):
            analysis = self.create_analysis(_file)

            # is this file not a type of file we expect to see here?
            # we have a list of things we look for here in the configuration
            suspect = False
            for suspect_file_type in self.suspect_file_type:
                if suspect_file_type.lower().strip() in file_type_analysis.file_type.lower():
                    _file.add_detection_point("OLE attachment has suspect file type {}".format(suspect_file_type))
                    analysis.details.append(suspect_file_type)
                    suspect = True
                    break

            if not suspect:
                for suspect_file_ext in self.suspect_file_ext:
                    if _file.value.lower().endswith('.{}'.format(suspect_file_ext)):
                        _file.add_detection_point("OLE attachment has suspect file ext {}".format(suspect_file_ext))
                        analysis.details.append(suspect_file_ext)
                        suspect = True
                        break

            # one last check -- see if this file compiles as javascript
            # the file command may return plain text for some js files without extension
            if not suspect:
                # avoid super small files that compile as javascript because there's almost nothing in them
                if os.path.getsize(local_file_path) > 150:
                    p = Popen(['esvalidate', local_file_path], stdout=DEVNULL, stderr=DEVNULL)
                    p.wait()

                    if p.returncode == 0:
                        _file.add_detection_point("OLE attachment {} compiles as JavaScript".format(_file.value))
                        suspect = True

            if suspect:
                logging.info("found suspect ole attachment {} in {}".format(suspect_file_type, _file))
                _file.add_tag('suspect_ole_attachment')

            return True

        return False

class BinaryFileAnalysis(Analysis):
    def initialize_details(self):
        pass

    def generate_summary(self):
        return None

class BinaryFileAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BinaryFileAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def is_supported_file(self, path):
        result = self._is_rtf(path)
        # we only care about EPS files in Word documents because we heard it reported once
        result |= ( self._is_eps(path) and '.doc' in path )
        return result

    def _is_rtf(self, local_file_path):
        with open(local_file_path, 'rb') as fp:
            # is this an RTF file?
            header = fp.read(4)
            if header == b'{\\rt':
                return True

        return False

    def _is_eps(self, local_file_path):
        with open(local_file_path, 'rb') as fp:
            # is this an EPS file? (see https://en.wikipedia.org/wiki/Encapsulated_PostScript)
            header = fp.read(4)
            if header == b'\xc5\xd0\xd3\xc6':
                return True
            fp.seek(0)
            header = fp.read(11)
            if header == b'%!PS-Adobe-':
                return True

        return False

    def execute_analysis(self, _file):

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file.value))
            return False

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return False

        if not self.is_supported_file(local_file_path):
            return False

        analysis = self.create_analysis(_file)

        with open(local_file_path, 'rb') as fp:

            # we're basically looking for any non-binary that has a null byte
            # all of the malicious documents we've found have null bytes
            # and that seems to be somewhat rare with these types of files

            bytes_read = 0

            while True:
                _buffer = fp.read(8192)
                if len(_buffer) == 0:
                    break

                bytes_read += len(_buffer)
                # have we read the last bytes of the file?
                if bytes_read == file_size:
                    # if so, ignore the last byte
                    # RTF files often end with \x00 for some reason
                    _buffer = _buffer[:-1]

                if b'\x00' in _buffer:
                    _file.add_tag('unexpected_binary_data')
                    _file.add_directive(DIRECTIVE_SANDBOX)
                    return

        return True

# DEPRECATED
class RTFAnalysis_v1_0(Analysis):
    def generate_summary(self):
        return None

# DEPRECATED
class RTFAnalyzer_v1_0(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return RTFAnalysis_v1_0

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        analysis = RTFAnalysis_v1_0()
        _file.add_analysis(analysis)

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file.value))
            return

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return

        with open(local_file_path, 'rb') as fp:
            # is this an RTF file?
            header = fp.read(4)
            if header != b'{\\rt':
                return

            # we're basically looking for any RTF that has a null byte
            # all of the malicious documents we've found have null bytes
            # and that seems to be somewhat rare with RTF files

            while True:
                _buffer = fp.read(8192)
                if len(_buffer) == 0:
                    break

                if b'\x00' in _buffer:
                    _file.add_tag('rtf_binary')
                    _file.add_directive(DIRECTIVE_SANDBOX)
                    return

class RTFOLEObjectAnalysis(Analysis):
    """Does this RTF file have OLE objects inside?"""
    KEY_STDOUT = 'stdout'
    KEY_STDERR = 'stderr'
    KEY_RETURN_CODE = 'return_code'
    KEY_EXTRACTED_FILES = 'extracted_files'

    def initialize_details(self):
        self.details = {
            RTFOLEObjectAnalysis.KEY_STDOUT: None,
            RTFOLEObjectAnalysis.KEY_STDERR: None,
            RTFOLEObjectAnalysis.KEY_RETURN_CODE: None,
            RTFOLEObjectAnalysis.KEY_EXTRACTED_FILES: [],
        }

    @property
    def stdout(self):
        """Captured standard output of rtfobj.py"""
        return self.details[RTFOLEObjectAnalysis.KEY_STDOUT]

    @stdout.setter
    def stdout(self, value):
        assert value is None or isinstance(value, str)
        self.details[RTFOLEObjectAnalysis.KEY_STDOUT] = value

    @property
    def stderr(self):
        """Captured standard error of rtfobj.py"""
        return self.details[RTFOLEObjectAnalysis.KEY_STDERR]

    @stderr.setter
    def stderr(self, value):
        assert value is None or isinstance(value, str)
        self.details[RTFOLEObjectAnalysis.KEY_STDERR] = value

    @property
    def return_code(self):
        """Return code of rtfobj.py"""
        return self.details[RTFOLEObjectAnalysis.KEY_RETURN_CODE]

    @return_code.setter
    def return_code(self, value):
        assert value is None or isinstance(value, int)
        self.details[RTFOLEObjectAnalysis.KEY_RETURN_CODE] = value

    @property
    def extracted_files(self):
        """List of files extracted by rtfobj.py"""
        return self.details[RTFOLEObjectAnalysis.KEY_EXTRACTED_FILES]

    def generate_summary(self):
        if not self.details:
            return None

        if not self.extracted_files:
            return "RTF OLE Object Analysis - no objects detected"

        return "RTF OLE Object Analysis - {} files extracted".format(len(self.extracted_files))

class RTFOLEObjectAnalyzer(AnalysisModule):

    @property
    def rtfobj_path(self):
        """Path to the rtfobj.py tool from oletools package."""
        return self.config['rtfobj_path']
        

    def verify_environment(self):
        self.verify_config_exists('rtfobj_path')
        self.verify_path_exists(self.config['rtfobj_path'])

    @property
    def generated_analysis_type(self):
        return RTFOLEObjectAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return False

        # only analyze rtf files
        if not is_rtf_file(local_file_path):
            logging.debug("{} is not a rtf file".format(local_file_path))
            return False


        output_dir = '{}.rtfobj'.format(local_file_path)
        if os.path.exists(output_dir):
            return False

        try:
            os.mkdir(output_dir)
        except Exception as e:
            logging.error("unable to create directory {}: {}".format(output_dir, e))
            report_exception()
            return False

        analysis = self.create_analysis(_file)

        try:
            p = Popen(['python2.7', self.rtfobj_path, '-d', output_dir, '-s', 'all', local_file_path], 
                      stdout=PIPE, stderr=PIPE, universal_newlines=True)
            analysis.stderr, analysis.stdout = p.communicate()
            analysis.return_code = p.returncode
        except Exception as e:
            logging.error("execution of {} failed: {}".format(self.rtfobj_path, e))
            report_exception()
            return False

        # walk the output directory and add all discovered files as observables
        try:
            logging.debug("walking {}".format(output_dir))
            for root, dirs, files in os.walk(output_dir):
                logging.debug("looping {} {} {}".format(root, dirs, files))
                for file_name in files:
                    extracted_file = os.path.join(output_dir, file_name)
                    logging.debug("extracted_file = {}".format(extracted_file))
                    analysis.extracted_files.append(extracted_file)
                    f = analysis.add_observable(F_FILE, os.path.relpath(extracted_file, start=self.root.storage_dir))
                    if f:
                        f.add_tag('extracted_rtf')
                        f.redirection = _file
                        f.add_relationship(R_EXTRACTED_FROM, _file)

        except Exception as e:
            logging.error("failed to process output directory {}: {}".format(output_dir, e))
            report_exception()
            return False

        return True

class ExtractedRTFAnalysis(Analysis):
    def initialize_details(self):
        pass

    def generate_summary(self):
        return None

class ExtractedRTFAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('suspect_ext')
        self.verify_config_exists('suspect_mime_type')
        self.verify_config_exists('suspect_file_type')

    @property
    def suspect_ext(self):
        """Comma separated list of extensions that are automatically suspect if found inside an RTF OLE object."""
        return map(lambda x: x.strip(), self.config['suspect_ext'].split(','))

    @property
    def suspect_mime_type(self):
        """Comma separated list of mime types that are automatically suspect if found inside an RTF OLE object."""
        return map(lambda x: x.strip(), self.config['suspect_mime_type'].split(','))

    @property
    def suspect_file_type(self):
        """Comma separated list of types types that are automatically suspect if found inside an RTF OLE object."""
        return map(lambda x: x.strip(), self.config['suspect_file_type'].split(','))

    @property
    def generated_analysis_type(self):
        return ExtractedRTFAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        if not _file.has_tag('extracted_rtf'):
            return False

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return False

        analysis = self.create_analysis(_file)

        for ext in self.suspect_ext:
            if _file.value.lower().endswith('.{}'.format(ext)):
                _file.add_detection_point('file extracted from RTF has suspect file extension')
                _file.add_directive(DIRECTIVE_SANDBOX)
                #_file.add_tag('suspect')

        for mime_type in self.suspect_mime_type:
            if mime_type.lower() in file_type_analysis.mime_type.lower():
                _file.add_detection_point('file extracted from RTF has suspect mime type')
                _file.add_directive(DIRECTIVE_SANDBOX)
                #_file.add_tag('suspect')

        for file_type in self.suspect_file_type:
            if file_type.lower() in file_type_analysis.file_type.lower():
                _file.add_detection_point('file extracted from RTF has suspect file type')
                _file.add_directive(DIRECTIVE_SANDBOX)
                #_file.add_tag('suspect')

        return True

class MicrosoftScriptEncodingAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        if self.details:
            return 'Microsoft Script Encoding Analysis ({})'.format(self.details)

        return None

class MicrosoftScriptEncodingAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('decryption_program')
        self.verify_path_exists(self.config['decryption_program'])

    @property
    def decryption_program(self):
        return self.config['decryption_program']

    @property
    def generated_analysis_type(self):
        return MicrosoftScriptEncodingAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file.value))
            return False

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return False

        # these things start with #@~^
        with open(local_file_path, 'rb') as fp:
            header_bytes = fp.read(4)
            if header_bytes != b'#@~^':
                return False

        analysis = self.create_analysis(_file)

        # weird enough
        _file.add_tag('microsoft_script_encoding')
        _file.add_directive(DIRECTIVE_SANDBOX)

        # attempt to decode it
        output_path = '{}.decrypted'.format(local_file_path)
        stderr_path = '{}.decrypted.stderr'.format(local_file_path)
        if local_file_path.lower().endswith('.vbe'):
            output_path = '{}.vbs'.format(output_path)
        if local_file_path.lower().endswith('.jse'):
            output_path = '{}.js'.format(output_path)

        logging.debug("attempting to decode microsoft script encoded file {} to {}".format(local_file_path, output_path))
        with open(output_path, 'wb') as fp_out:
            with open(stderr_path, 'wb') as fp_err:
                p = Popen([self.decryption_program, local_file_path], stdout=fp_out, stderr=fp_err)
                p.communicate()
                p.wait()

        if os.path.getsize(output_path):
            file_observable = analysis.add_observable(F_FILE, os.path.relpath(output_path, start=self.root.storage_dir))
            if file_observable: file_observable.redirection = _file
            analysis.details = os.path.basename(output_path)

        return True

class URLExtractionAnalysis(Analysis):
    def initialize_details(self):
        self.details = []

    def generate_summary(self):
        if self.details is None or not len(self.details):
            return None

        return "URL Extraction Analysis ({} urls)".format(len(self.details))

class URLExtractionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return URLExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_EXTRACT_URLS ]

    @property
    def max_file_size(self):
        """The max file size to extract URLs from (in bytes.)"""
        return self.config.getint("max_file_size") * 1024 * 1024

    def execute_analysis(self, _file):
        from saq.modules.cloudphish import CloudphishAnalyzer

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return False
        
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return False

        # skip files that are too large
        if file_size > self.max_file_size:
            logging.debug("file {} is too large to extract URLs from".format(_file.value))
            return False

        analysis = self.create_analysis(_file)
        extracted_urls = []
        base_url = None

        if file_type_analysis.mime_type and 'html' in file_type_analysis.mime_type.lower():
            # if this file was downloaded from some url then we want all the relative urls to be aboslute to the reference url
            downloaded_from = _file.get_relationship_by_type(R_DOWNLOADED_FROM)
            if downloaded_from:
                base_url = downloaded_from.target.value

        # extract all the URLs out of this file
        with open(local_file_path, 'rb') as fp:
            extracted_urls = find_urls(fp.read(), base_url=base_url)
            logging.debug("extracted {} urls from {}".format(len(extracted_urls), local_file_path))

            # use the strings command to extract any urls that parse out that way
            #try:
                #p = Popen(['/usr/bin/strings', local_file_path], stderr=PIPE, stdout=PIPE)
                #_stdout, _stderr = p.communicate()
                #extracted_urls.extend(_extract_urls_raw(_stdout.replace(b'\\', b'/')))

                #p = Popen(['/usr/bin/strings', '-e', 'l', local_file_path], stderr=PIPE, stdout=PIPE)
                #_stdout, _stderr = p.communicate()
                #extracted_urls.extend(_extract_urls_raw(_stdout.replace(b'\\', b'/')))
                        
            #except Exception as e:
                #logging.error("error running strings to extract urls on {}: {}".format(local_file_path, e))
                #report_exception()

            # and then remove any duplicates
            #extracted_urls = _dedup_urls(extracted_urls)

            # is this an HTML file?
            #if file_type_analysis.mime_type and 'html' in file_type_analysis.mime_type.lower():
                ## if this file was downloaded from some url then we want all the relative urls to be aboslute to the reference url
                #downloaded_from = _file.get_relationship_by_type(R_DOWNLOADED_FROM)
                #base_url = None
                #if downloaded_from:
                    #base_url = downloaded_from.target.value

                    #for index, url in enumerate(extracted_urls):
                        #try:
                            #parsed_url = urlparse(url)
                            #if not parsed_url.netloc:
                                #extracted_urls[index] = urljoin(base_url, url)
                                #logging.debug("fixed relative url {} to {}".format(url, extracted_urls[index]))
                        #except Exception as e:
                            #logging.debug("unable to parse {} as url".format(url))
                    
                #extracted_urls.extend(_extract_urls_html(mf, base_url=base_url))
                #logging.debug("soup extracted {} urls from {}".format(len(extracted_urls), _file.value))

            # is this a PDF file?
            #if is_pdf_file(local_file_path) or local_file_path.endswith('.pdfparser'):
                #urls = _PDF_URL_REGEX_B.findall(mf)
                #urls = [re.sub(r'\s+', '', url.decode(errors='ignore')) for url in urls]
                #urls = list(set(urls))
                #extracted_urls.extend(urls)

        # parse out any embedded urls inside thesed urls
        #extracted_urls.extend(_extract_embedded_urls(extracted_urls))

        for url in extracted_urls:
            url_observable = analysis.add_observable(F_URL, url)
            if url_observable:
                # we don't want to crawl the internet
                #if not _file.has_relationship(R_DOWNLOADED_FROM):
                    #url_observable.add_directive(DIRECTIVE_CRAWL)
                analysis.details.append(url_observable.value)
                logging.debug("extracted url {} from {}".format(url_observable.value, _file.value))

                # XXX hack
                if self.engine.name == 'cloudphish':
                    url_observable.exclude_analysis(CloudphishAnalyzer)

        return True

#
# DEPRECATED
#

FILE_COLLECTION_STATUS_NEW = 'new'
FILE_COLLECTION_STATUS_PENDING = 'pending'
FILE_COLLECTION_STATUS_FAILED = 'failed'
FILE_COLLECTION_STATUS_COMPLETED = 'completed'

class FileCollectionAnalysis(Analysis):

    def initialize_details(self):
        self.details = {
            'status': FILE_COLLECTION_STATUS_NEW,
            'ticket': None,
            'error_message': None,
            'start_time': None,
            'local_file_path': None
        }

    def generate_summary(self):
        if self.details is None or not len(self.details):
            return None

        if self.status == FILE_COLLECTION_STATUS_FAILED:
            return "File Collection Failed - {}".format(self.error_message)

        return "File Collection Status - {}".format(self.status)

    @property
    def status(self):
        if not self.details:
            return None

        return self.details['status']

    @status.setter
    def status(self, value):
        self.details['status'] = value

    @property
    def ticket(self):
        if not self.details:
            return None

        return self.details['ticket']

    @ticket.setter
    def ticket(self, value):
        self.details['ticket'] = value
        self.details['start_time'] = datetime.datetime.now().timestamp()

    @property   
    def error_message(self):
        if not self.details:
            return None

        return self.details['error_message']

    @error_message.setter
    def error_message(self, value):
        self.details['error_message'] = value

    @property
    def start_time(self):
        if not self.details:
            return None

        return datetime.datetime.fromtimestamp(self.details['start_time'])

    @property
    def elapsed_time(self):
        if not self.details:
            return None

        return datetime.datetime.now() - self.start_time

    @property
    def local_file_path(self):
        if not self.details:
            return None

        return self.details['local_file_path']

    @local_file_path.setter
    def local_file_path(self, value):
        self.details['local_file_path'] = value

class VBScriptAnalysis(Analysis):
    def initialize_details(self):
        pass

    def generate_summary(self):
        return None

class VBScriptAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return VBScriptAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def large_hex_string_size(self):
        return self.config.getint('large_hex_string_size')

    @property
    def large_hex_string_quantity(self):
        return self.config.getint('large_hex_string_quantity')

    @property
    def large_hex_string_quantity_count(self):
        return self.config.getint('large_hex_string_quantity_count')

    @property
    def hex_string_percentage_limit(self):
        return self.config.getfloat('hex_string_percentage_limit')

    def execute_analysis(self, _file):

        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return False

        if not local_file_path.lower().endswith('.vbs'):
            return False

        consec_count = 0
        total_count = 0
        hex_string_lengths = []

        with open(local_file_path, 'rb') as fp:
            mm = mmap.mmap(fp.fileno(), 0, prot=mmap.PROT_READ)
            for line in mm:
                # ignore comments
                if line.lstrip().startswith(b"'") or line.lstrip().startswith(b'REM'):
                    continue

                for c in line:
                    # ignore whitespace
                    if chr(c).isspace():
                        continue

                    if (c > 47 and c < 58) or (c > 64 and c < 71) or (c > 96 and c < 103):
                        consec_count += 1
                        total_count += 1
                    else:
                        # ignore hex strings < 5
                        if consec_count >= 5:
                            hex_string_lengths.append(consec_count)
                        consec_count = 0

        if not hex_string_lengths:
            return False

        analysis = self.create_analysis(_file)

        logging.debug("total hex strings detected: {}".format(len(hex_string_lengths)))
        logging.debug("largest hex string: {}".format(max(hex_string_lengths)))
        logging.debug("percentage of hex string: {0:.2f}".format((total_count / file_size) * 100.0))

        distribution = {}
        for length in hex_string_lengths:
            if str(length) not in distribution:
                distribution[str(length)] = 1
            else:
                distribution[str(length)] += 1

        for length in distribution.keys():
            logging.debug("{} = {}".format(length, distribution[length]))

        # do we have a large number of hex strings of the same length that are larger than 50?
        for length in distribution.keys():
            if int(length) > self.large_hex_string_quantity:
                if distribution[length] > self.large_hex_string_quantity_count:
                    _file.add_detection_point("large number of large hex strings of same length")
                    _file.add_directive(DIRECTIVE_SANDBOX)
                    break

        # is a large percentage of the file hex strings?
        if (total_count / file_size) >= self.hex_string_percentage_limit:
            _file.add_detection_point("a large percentage of the file is ascii hex ({0:.2f}%)".format((total_count / file_size) * 100.0))
            _file.add_directive(DIRECTIVE_SANDBOX)

        # if we have a large hex string at all we at least tag it and send it to the sandbox
        if max(hex_string_lengths) > self.large_hex_string_size:
            _file.add_tag("large_hex_string")
            _file.add_directive(DIRECTIVE_SANDBOX)

        return True

class NoWhiteSpaceAnalysis(Analysis):
    """Removes all whitespace characters from a file and saves it as file_name.nowhitespace."""

    def initialize_details(self):
        self.details = 0

    def generate_summary(self):
        if self.details is None:
            return None

        if self.details < 1:
            return None

        return "Ignore Whitespace Characters ({} removed)".format(self.details)

class NoWhiteSpaceAnalyzer(AnalysisModule):
   
    @property
    def generated_analysis_type(self):
        return NoWhiteSpaceAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):

        from functools import partial

        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        if local_file_path.endswith('.nowhitespace'):
            return False

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return False

        if not is_rtf_file(local_file_path):
            return False

        analysis = self.create_analysis(_file)
        output_file = '{}.nowhitespace'.format(local_file_path)
        count = 0

        # this is probably not very efficient...
        with open(local_file_path, 'rb') as fp_in:
            with open(output_file, 'wb') as fp_out:
                for b in iter(partial(fp_in.read, 1), b''):
                    if b not in b' \t\r\n\f\v':
                        fp_out.write(b)
                    else:
                        count += 1

        analysis.details = count
        output_file = analysis.add_observable(F_FILE, os.path.relpath(output_file, start=self.root.storage_dir))
        if output_file: output_file.redirection = _file
        return True

class MetaRefreshExtractionAnalysis(Analysis):
    """Does this HTML file downloaded from the Internet have a meta-redirect?"""

    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        if self.details is None or not self.details:
            return None

        return "Detected meta-refresh to {}".format(self.details)

class MetaRefreshExtractionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MetaRefreshExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        # the file must have been downloaded from a URL
        # doesn't really matter what URL, just needs the downloaded_from relationship
        if not _file.has_relationship(R_DOWNLOADED_FROM):
            return False

        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return False

        analysis = self.create_analysis(_file)

        try:
            import bs4

            with open(local_file_path, 'rb') as fp:
                # we're only going took at the first 8K of the file
                # that's where these things are usually at and we don't want to kill RAM loading binary files
                # since we're not going to try to guess if it's HTML or not here
                content = fp.read(1024 * 8)

            # based this on this post
            # https://stackoverflow.com/questions/2318446/how-to-follow-meta-refreshes-in-python
            soup  = bs4.BeautifulSoup(content.decode(errors='ignore'), 'lxml')

            for meta in soup.find_all(lambda x: x.name.lower() == 'meta'):
                if 'http-equiv' in meta.attrs and meta.attrs['http-equiv'].lower() == 'refresh':
                    wait, text = meta['content'].split(';')
                    if text.strip().lower().startswith("url="):
                        url = text[4:]
                        url_observable = analysis.add_observable(F_URL, url)
                        if url_observable:
                            url_observable.add_directive(DIRECTIVE_CRAWL)
                        logging.info("found meta refresh url {} from {}".format(url, _file))

                        analysis.details = url
            
        except Exception as e:
            logging.info("meta refresh extraction failed (usually ok): {}".format(e))
            return False

        return True

class _xml_parser(object):
    def __init__(self):
        self.urls = [] # the list of urls we find

    def start(self, tag, attrib):
        if not tag.endswith('Relationship'):
            return

        if 'Type' not in attrib:
            return

        if 'TargetMode' not in attrib:
            return

        if 'Target' not in attrib:
            return

        if not attrib['Type'].endswith('/oleObject'):
            return

        if attrib['TargetMode'] != 'External':
            return

        self.urls.append(attrib['Target'])

    def end(self, tag):
        pass

    def data(self, data):
        pass

    def close(self):
        pass

KEY_URLS = 'urls'

class OfficeXMLRelationshipExternalURLAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_URLS: [],
        }

    @property
    def urls(self):
        return self.details_property(KEY_URLS)

    @urls.setter
    def urls(self, value):
        self.details[KEY_URLS] = value

    def generate_summary(self):
        if not self.urls:
            return None

        return "Office XML Rel Ext URL ({} urls extracted)".format(len(self.urls))

class OfficeXMLRelationshipExternalURLAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return OfficeXMLRelationshipExternalURLAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file):
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        if os.path.basename(local_file_path) != 'document.xml.rels':
            return False

        analysis = self.create_analysis(_file)

        parser_target = _xml_parser()
        parser = etree.XMLParser(target=parser_target)
        try:
            etree.parse(local_file_path, parser)
        except Exception as e:
            logging.warning("unable to parse XML file {}: {}".format(_file.value, e))

        for url in parser_target.urls:
            url = analysis.add_observable(F_URL, url)
            url.add_directive(DIRECTIVE_FORCE_DOWNLOAD)
            _file.add_detection_point('{} contains a link to an external oleobject'.format(_file.value))

        analysis.urls = parser_target.urls

        return True

class PCodeAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        if not self.details:
            return None

        return "PCode Analysis: decoded {} lines".format(self.details)

class PCodeAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return PCodeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def verify_environment(self):
        self.verify_path_exists(self.pcodedmp_path)

    @property
    def pcodedmp_path(self):
        """Returns the full path to the pcodedmp command line utility."""
        return self.config['pcodedmp_path']

    def execute_analysis(self, _file):
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        self.wait_for_analysis(_file, FileTypeAnalysis)
        if not is_office_file(_file):
            return False
        
        stderr_path = '{}.pcode.err'.format(local_file_path)
        stdout_path = '{}.pcode.bas'.format(local_file_path)

        with open(stderr_path, 'wb') as stderr_fp:
            with open(stdout_path, 'wb') as stdout_fp:
                # we use a wrapper program to filter out only the .bas lines
                p = Popen([os.path.join(saq.SAQ_HOME, 'bin', 'pcodedmp_wrapper'), 
                           self.pcodedmp_path, local_file_path], stdout=stdout_fp, stderr=stderr_fp)
                p.wait(timeout=30)

        if p.returncode != 0:
            logging.warning("pcodedmp returned error code {} for {}".format(p.returncode, _file.value))

        if os.path.getsize(stderr_path):
            logging.debug("pcodedmp recorded errors for {}".format(_file.value))
        else:
            os.remove(stderr_path)

        if os.path.getsize(stdout_path):
            analysis = self.create_analysis(_file)
            line_count = 0
            with open(stdout_path, 'rb') as fp:
                for line in fp:
                    line_count += 1
            analysis.details = line_count
            output_file = analysis.add_observable(F_FILE, os.path.relpath(stdout_path, start=self.root.storage_dir))
            output_file.redirection = _file
            return True

        os.remove(stdout_path)
        return False

class OfficeFileArchiveAction(Analysis):
    def initialize_details(self):
        self.details = None

    def generate_summary(self):
        return None

class OfficeFileArchiver(AnalysisModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.existing_subdir = None

    @property
    def generated_analysis_type(self):
        return OfficeFileArchiveAction

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def office_archive_dir(self):
        """Relative path to the directory that contains archived office documents."""
        return self.config['office_archive_dir']

    def verify_environment(self):
        self.verify_path_exists(self.office_archive_dir)

    def execute_analysis(self, _file):
        local_file_path = get_local_file_path(self.root, _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file.value))
            return False

        self.wait_for_analysis(_file, FileTypeAnalysis)
        if not is_office_file(_file):
            return False

        t = datetime.datetime.now()
        subdir = os.path.join(saq.SAQ_HOME, self.office_archive_dir, 
                              t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'))
        
        # is this different than the last time we checked?
        if subdir != self.existing_subdir:
            self.existing_subdir = subdir
            if not os.path.isdir(self.existing_subdir):
                os.makedirs(self.existing_subdir)

        i = 0
        target_path = os.path.join(self.existing_subdir, '{:06}_{}'.format(i, os.path.basename(_file.value)))
        while os.path.exists(target_path):
            i += 1
            target_path = os.path.join(self.existing_subdir, '{:06}_{}'.format(i, os.path.basename(_file.value)))

        shutil.copy(local_file_path, target_path)
        logging.debug("archived office file {}".format(target_path))

        analysis = self.create_analysis(_file)
        analysis.details = target_path
