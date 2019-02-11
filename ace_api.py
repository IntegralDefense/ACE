#!/usr/bin/env python3
# vim: ts=4:sw=4:et:cc=120

#
# python3 wrapper for ACE API calls

import sys

try:
    import requests
except ImportError:
    print("You need to install the python Requests library (see http://docs.python-requests.org/en/master/)")
    sys.exit(1)

try:
    import pytz
except ImportError:
    print("You need to install the pytz library (see https://pypi.org/project/pytz/)")
    sys.exit(1)

try:
    import tzlocal
except ImportError:
    print("You need to install the tzlocal library (see https://pypi.org/project/tzlocal/)")
    sys.exit(1)

import atexit
import copy
import datetime
import inspect
import io
import json
import logging
import os
import os.path
import pickle
import shutil
import socket
import tarfile
import tempfile
import traceback
import urllib3
import uuid
import warnings

# ignoring this: /usr/lib/python3/dist-packages/urllib3/connection.py:344:
# SubjectAltNameWarning: Certificate for localhost has no `subjectAltName`,
# falling back to check for a `commonName` for now. This feature is being
# removed by major browsers and deprecated by RFC 2818. (See
# https://github.com/shazow/urllib3/issues/497 for details.)

warnings.simplefilter('ignore', urllib3.exceptions.SecurityWarning)

# get our custom logger we use for this library
log = logging.getLogger(__name__)

# what HTTP method to use
METHOD_GET = 'get'
METHOD_POST = 'post'

def set_default_remote_host(remote_host):
    """Sets the default remote host used when no remote host is provided to the API calls.
    
    :param str remote_host: The ACE node you want to work with. Default: localhost
    """
    global default_remote_host
    default_remote_host = remote_host

def set_default_ssl_ca_path(ssl_verification):
    """Sets the default SSL verification mode. Behavior: 
      
       - If set to None (the default) then the system installed CAs are used.
       - If set to False, then SSL verification is disabled.
       - Else, it is assumed to be a file that contains the CAs to be used to verify the SSL certificates.

    :param ssl_verification: see behavior above.
    :type ssl_verification: str or None or False
    """
    global default_ssl_verification
    default_ssl_verification = ssl_verification

# list of api commands
api_commands = []

# list of support commands
support_commands = []

# the default remote host to use when no remote host is provided
default_remote_host = 'localhost'
default_ssl_verification = None

# the local timezone
LOCAL_TIMEZONE = pytz.timezone(tzlocal.get_localzone().zone)

# the datetime string format we use for this api
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'

def api_command(func):
    global api_commands
    api_commands.append(func)
    return func

def support_command(func):
    global support_commands
    support_commands.append(func)
    return func

def _execute_api_call(command, 
                      method=METHOD_GET, 
                      remote_host=None, 
                      ssl_verification=None, 
                      stream=False, 
                      data=None, 
                      files=None, 
                      params=None,
                      proxies=None,
                      timeout=None):

    if remote_host is None:
        remote_host = default_remote_host

    if ssl_verification is None:
        ssl_verification = default_ssl_verification

    if method == METHOD_GET:
        func = requests.get
    else:
        func = requests.post

    kwargs = { 'stream': stream }
    if params is not None:
        kwargs['params'] = params
    if ssl_verification is not None:
        kwargs['verify'] = ssl_verification
    if data is not None:
        kwargs['data'] = data
    if files is not None:
        kwargs['files'] = files
    if proxies is not None:
        kwargs['proxies'] = proxies
    if timeout is not None:
        kwargs['timeout'] = timeout

    r = func('https://{}/api/{}'.format(remote_host, command), **kwargs)
    r.raise_for_status()
    return r

@api_command
def get_supported_api_version(*args, **kwargs):
    """Get the API version for the ACE ecosystem you're working with.
    
    :return: Result dictionary containing the version string.
    :rtype: dict
    """
    return _execute_api_call('common/get_supported_api_version', *args, **kwargs).json()

@api_command
def get_valid_companies(*args, **kwargs):
    """Get a list of the companies supported by this ACE ecosystem.
    
    :return: Result dictionary containing a list of companies.
    :rtype: dict
    """
    return _execute_api_call('common/get_valid_companies', *args, **kwargs).json()

@api_command
def get_valid_observables(*args, **kwargs):
    """Get all of the valid observable types for this ACE ecosystem.

    :return: result dictionary containing observables names and discription.
    :rtype: dict
    """
    return _execute_api_call('common/get_valid_observables', *args, **kwargs).json()

@api_command
def get_valid_directives(*args, **kwargs):
    return _execute_api_call('common/get_valid_directives', *args, **kwargs).json()

@api_command
def ping(*args, **kwargs):
    """Connectivity check to the ACE ecosystem."""
    return _execute_api_call('common/ping', *args, **kwargs).json()

def parse_submit(args):
    # Utility funciton
    if args.event_time:
        # make sure the time is formatted correctly
        datetime.datetime.strptime(args.event_time, DATETIME_FORMAT)

    # parse the details JSON
    if args.details:
        if args.details.startswith('@'):
            with open(args.details, 'r') as fp:
                args.details = fp.read()

    # parse the observables
    observables = []
    if args.observables:
        for o in args.observables:
            o = o.split(':')
            _type = o[0]
            _value = o[1]
            _time = _tags = _directives = _limited_analysis = None

            if len(o) > 2:
                if o[2].strip():
                    datetime.datetime.strptime(o[2].strip(), DATETIME_FORMAT)
                    _time = o[2].strip()

            if len(o) > 3:
                if o[3].strip():
                    _tags = [_.strip() for _ in o[3].split(',')]

            if len(o) > 4:
                if o[4].strip():
                    _directives = [_.strip() for _ in o[4].split(',')]

            if len(o) > 5:
                if o[5].strip():
                    _limited_analysis = [_.strip() for _ in o[5].split(',')]

            o = { 'type': _type, 'value': _value }
            if _time:
                o['time'] = _time
            if _tags:
                o['tags'] = _tags
            if _directives:
                o['directives'] = _directives
            if _limited_analysis:
                o['limited_analysis'] = _limited_analysis

            observables.append(o)

    args.observables = observables

    files = []
    if args.files:
        for f in args.files:
            if '-->' in f:
                source_file, dest_file = f.split('-->')
            else:
                source_file = f
                dest_file = os.path.basename(f)

            files.append((dest_file, open(source_file, 'rb')))

    args.files = files

    return args

@api_command
def submit(
    description, 
    analysis_mode='analysis',
    tool='ace_api',
    tool_instance='ace_api:{}'.format(socket.getfqdn()),
    type='generic',
    event_time=None,
    details={},
    observables=[],
    tags=[],
    files=[],
    *args, **kwargs):
    """Submit a request to ACE for analysis and/or correlation.
    
    :param str discription: A brief description of this analysis data (Why? What? How?).
    :param str analysis_mode: (optional) The ACE mode this analysis should be put into. 'correlation' will force an alert creation. 'analysis' will only alert if a detection is made. Default: 'analysis'
    :param str tool: (optional) The "tool" that is submitting this analysis. Meant for distinguishing your custom hunters and detection tools. Default: 'ace_api'.
    :param str tool_instance: (optional) The instance of the tool that is submitting this analysis.
    :param str type: (optional) The type of analysis this is, kinda like the focus of the alert. Mainly used internally by some ACE modules. Default: 'generic'
    :param datetime event_time: (optional) Assign a time to this analysis. Usually, the time associated to what ever event triggered this analysis creation. Default: now()
    :param dict details: (optional) A dictionary of additional details to get added to the alert, think notes and comments.
    :param list observables: (optional) A list of observables to add to the request.
    :param list tags: (optional) If this request becomes an Alert, these tags will get added to it.
    :param list files: (optional) A list of (file_name, file_descriptor) tuples to be included in this ACE request.
    :return: A result dictionary. If submission was successful, the UUID of the analysis will be contained. Like this:
        {'result': {'uuid': '960b0a0f-3ea2-465f-852f-ebccac6ae282'}}
    :rtype: dict
    """

    # make sure you passed in *something* for the description
    assert(description)

    # default event time is now
    if event_time is None:
        event_time = datetime.datetime.now()

    # no timezone yet?
    # convert to UTC and then to the correct datetime format string for ACE
    if isinstance(event_time, datetime.datetime):
        if event_time.tzinfo is None:
            formatted_event_time = LOCAL_TIMEZONE.localize(event_time).astimezone(pytz.UTC).strftime(DATETIME_FORMAT)
        else:
            formatted_event_time = event_time.astimezone(pytz.UTC).strftime(DATETIME_FORMAT)
    else:
        # otherwise we assume the event time is already formatted
        formatted_event_time = event_time

    # make sure the observables are in the correct format
    for o in observables:
        assert isinstance(o, dict)
        assert 'type' in o, "missing type in observable {}".format(o)
        assert 'value' in o, "missing value in observable {}".format(o)
        for key in o.keys():
            assert key in [ 'type', 'value', 'time', 'tags', 'directives', 'limited_analysis' ], "unknown observable property {} in {}".format(key, o)

        # make sure any times are formatted
        if 'time' in o and isinstance(o['time'], datetime.datetime):
            if o['time'].tzinfo is None:
                o['time'] = LOCAL_TIMEZONE.localize(o['time'])
            o['time'] = o['time'].astimezone(pytz.UTC).strftime(DATETIME_FORMAT)

    # make sure the tags are strings
    for t in tags:
        assert isinstance(t, str), "tag {} is not a string".format(t)

    # if details is a string interpret it as JSON
    #if isinstance(details, str):
        #details = json.loads(details)

    # make sure each file is a tuple of (something, str)
    _error_message = "file parameter {} invalid: each element of the file parameter must be a tuple of " \
                     "(file_name, file_descriptor)"

    files_params = []
    for index, f in enumerate(files):
        assert isinstance(f, tuple), _error_message.format(index)
        assert len(f) == 2, _error_message.format(index)
        assert f[1], _error_message.format(index)
        assert isinstance(f[0], str), _error_message.format(index)
        files_params.append(('file', (f[0], f[1])))

    # OK everything seems legit
    return _execute_api_call('analysis/submit', data={
        'analysis': json.dumps({
            'analysis_mode': analysis_mode,
            'tool': tool,
            'tool_instance': tool_instance,
            'type': type,
            'description': description,
            'event_time': formatted_event_time,
            'details': details,
            'observables': observables,
            'tags': tags, 
        }),
    }, files=files_params, method=METHOD_POST, *args, **kwargs).json()

@api_command
def resubmit_alert(uuid, *args, **kwargs):
    """Resubmit an alert for analysis. This means the alert will be re-analyzed as-if it was new.

    :param str uuid: The uuid of the alert to be resubmitted.
    :return: A result dictionary (has 'result' key).
    :rtype: dict
    """
    return _execute_api_call('analysis/resubmit/{}'.format(uuid), *args, **kwargs).json()

@api_command
def get_analysis(uuid, *args, **kwargs):
    """Get any analysis results.

    :param str uuid: The UUID of the analysis request.
    :return: Result dictionary containing any and all analysis results.
    :rtype: dict
    """
    return _execute_api_call('analysis/{}'.format(uuid), *args, **kwargs).json()

@api_command
def load_analysis(uuid_or_datapath, download_everything=None, target_dir=None, *args, **kwargs):
    """Load an analysis by it's uuid OR it's analysis result data.json file.
    This loads an Analysis object with the basic contextual data. If download_everything is True, assumes uuid_or_datapath is a valid UUID.

    :param str uuid_or_datapath: An alert UUID or path to an alert/analysis data.json file.
    :param bool download_everything: (optional) If true, download EVERYTHING and load file handles.
    :param str target_dir: (optional) Directory name to write the data. Default: UUID
    :return: Analysis object
    """
    uuid = uuid_or_datapath
    data = None
    data_dir = None

    if download_everything:
        if target_dir is None:
            target_dir = uuid
        data_dir = target_dir
        download(uuid, data_dir)
        uuid_or_datapath = os.path.join(uuid, 'data.json')

    if os.path.exists(uuid_or_datapath):
        with open(uuid_or_datapath, 'r') as fp:
            data = json.loads(fp.read())
    if not data:
        result = _execute_api_call('analysis/{}'.format(uuid), *args, **kwargs).json()
        data = result['result']

    files = []
    observables = []
    details = data['details']
    for o_key in data['observables']:
        o = data['observable_store'][o_key]
        observables.append({'type': o['type'], 'value': o['value'], 'directives': o['directives']})
        if o['type'] == 'file':
            files.append((o['value'], "This analysis has undergone load-shock-therapy.\n"\
                                      "Use the download_everything flag to actually load file data" ))

    # if we downloaded everything, load the things
    if data_dir is not None:
        details_file = details['file_path']
        with open(os.path.join(data_dir, '.ace', details_file), 'r') as fp:
            details = json.loads(fp.read())
        # open file handles
        files = [(f[0], open(f[0], 'rb')) for f in files] 

    a = Analysis(data['description'],
                analysis_mode=data['analysis_mode'],
                tool=data['tool'],
                tool_instance=data['tool_instance'],
                type=data['type'],
                event_time=data['event_time'],
                details=details,
                observables=observables,
                tags=data['tags'],
                files=files
                )
    a.uuid = data['uuid']
    return a

@api_command
def get_analysis_details(uuid, name, *args, **kwargs):
    # Get external details.
    return _execute_api_call('analysis/details/{}/{}'.format(uuid, name), *args, **kwargs).json()

@api_command
def get_analysis_file(uuid, name, output_file=None, output_fp=None, *args, **kwargs):
    #Get a file from an analysis result.
    # Coming back to this one
    #:param str uuid: The UUID of the analysis.
    #:param str name: The name or UUID of the file.
    if output_file is None and output_fp is None:
        output_fp = sys.stdout.buffer
    elif output_fp is None:
        output_fp = open(output_file, 'wb')

    r = _execute_api_call('analysis/file/{}/{}'.format(uuid, name), stream=True, *args, **kwargs)
    
    size = 0
    for chunk in r.iter_content(io.DEFAULT_BUFFER_SIZE):
        if chunk:
            output_fp.write(chunk)
            size += len(chunk)

    if output_file is not None:
        output_fp.close()

    return True

@api_command
def get_analysis_status(uuid, *args, **kwargs):
    """Get the status of an analysis.

    :param str uuid: The analysis UUID.
    :return: Result dictionary
    """
    return _execute_api_call('analysis/status/{}'.format(uuid), *args, **kwargs).json()

@api_command
def download(uuid, target_dir, *args, **kwargs):
    """Download everything related to this uuid and write it to target_dir.
    
    :param str uuid: The ACE analysis/alert uuid.
    :param str target_dir: The directory you want everything written to.
    """ 
    if not os.path.isdir(target_dir):
        os.makedirs(target_dir)

    fp, tar_path = tempfile.mkstemp(prefix='download_{}'.format(uuid), suffix='.tar')

    try:
        r = _execute_api_call('engine/download/{}'.format(uuid), stream=True, *args, **kwargs)

        size = 0
        for chunk in r.iter_content(io.DEFAULT_BUFFER_SIZE):
            if chunk:
                os.write(fp, chunk)
                size += len(chunk)

        os.close(fp)

        t = tarfile.open(tar_path, 'r|')
        t.extractall(path=target_dir)

    finally:
        try:
            os.remove(tar_path)
        except:
            sys.stderr.write("unable to delete temporary file {}: {}\n".format(tar_path, e))

@api_command
def upload(uuid, source_dir, overwrite=False, sync=True, *args, **kwargs):
    """Upload an ACE analysis/alert directory.

    :param str uuid: A new UUID for ACE to use.
    :param str source_dir: The directory to upload.
    """
    if not os.path.isdir(source_dir):
        raise ValueError("{} is not a directory".format(source_dir))

    fp, tar_path = tempfile.mkstemp(suffix='.tar', prefix='upload_{}'.format(uuid))
    try:
        tar = tarfile.open(fileobj=os.fdopen(fp, 'wb'), mode='w|')
        tar.add(source_dir, '.')
        tar.close()

        with open(tar_path, 'rb') as fp:
            return _execute_api_call('engine/upload/{}'.format(uuid), data={
                'upload_modifiers': json.dumps({
                    'overwrite': overwrite,
                    'sync': sync,
                })},
                method=METHOD_POST,
                files=[('archive', (os.path.basename(tar_path), fp))]).json()
    finally:
        try:
            os.remove(tar_path)
        except Exception as e:
            log.warning("unable to remove {}: {}".foramt(tar_path, e))

@api_command
def clear(uuid, lock_uuid, *args, **kwargs):
    # Clear/Delete an analysis?
    return _execute_api_call('engine/clear/{}/{}'.format(uuid, lock_uuid), *args, **kwargs).status_code == 200

@api_command
def cloudphish_submit(url, reprocess=False, ignore_filters=False, context={}, *args, **kwargs):
    """Submit a URL for Cloudphish to analyze.

    :param str url: The URL
    :param bool reprocess: (optional) If True, re-analyze the URL and ignore the cache.
    :param bool ignore_filters: (optional) What?
    :param dict context: (optional) Additional context to associated to the analysis.
    """
    # make sure the following keys are not in the context
    for key in [ 'url', 'reprocess', 'ignore_filters' ]:
        if key in context:
            raise ValueError("context cannot contain the keys url, reprocess or ignore_filters")

    data = {
        'url': url,
        'reprocess': '1' if reprocess else '0',
        'ignore_filters': '1' if ignore_filters else '0'
    }

    data.update(context)

    return _execute_api_call('cloudphish/submit', data=data, method=METHOD_POST, *args, **kwargs).json()

@api_command
def cloudphish_download(url=None, sha256=None, output_path=None, output_fp=None, *args, **kwargs):
    """Download content from Cloudphish. 
    Note: either the url OR the sha256 of the url is expected to passed.

    :param str url: (optional) The url
    :param str sha256: (optional) The sha256 of the url.
    :param str output_path: (optional) The path to write the content. Default: stdout
    :param str output_fp: (optional) a file handle/buffer to write the content. Default: stdout
    """
    if url is None and sha256 is None:
        raise ValueError("you must supply either url or sha256 to cloudphish_download")

    if output_path is None and output_fp is None:
        output_fp = sys.stdout.buffer
    elif output_fp is None:
        output_fp = open(output_path, 'wb')

    params = { }
    if url:
        params['url'] = url
    if sha256:
        params['s'] = sha256

    r = _execute_api_call('cloudphish/download', params=params, stream=True, *args, **kwargs)
    
    size = 0
    for chunk in r.iter_content(io.DEFAULT_BUFFER_SIZE):
        if chunk:
            output_fp.write(chunk)
            size += len(chunk)

    if output_path is not None:
        output_fp.close()

    return True

@api_command
def cloudphish_clear_alert(url=None, sha256=None, *args, **kwargs):
    params = {}
    if url is not None:
        params['url'] = url
    if sha256 is not None:
        params['s'] = sha256

    return _execute_api_call('cloudphish/clear_alert', params=params).status_code == 200

#
# supporting backwards comptability for the old ace_client_lib.client library
#

class AlertSubmitException(Exception):
    pass

class Analysis(object):
    """A ACE Analysis object.

    :param str discription: (optional) A brief description of this analysis data (Why? What? How?).
    :param str analysis_mode: (optional) The ACE mode this analysis should be put into. 'correlation' will force an alert creation. 'analysis' will only alert if a detection is made. Default: 'analysis'
    :param str tool: (optional) The "tool" that is submitting this analysis. Meant for distinguishing your custom hunters and detection tools. Default: 'ace_api'.
    :param str tool_instance: (optional) The instance of the tool that is submitting this analysis.
    :param str type: (optional) The type of analysis this is, kinda like the focus of the alert. Mainly used internally by some ACE modules. Default: 'generic'
    :param datetime event_time: (optional) Assign a time to this analysis. Usually, the time associated to what ever event triggered this analysis creation. Default: now()
    :param dict details: (optional) A dictionary of additional details to get added to the alert, think notes and comments.
    :param list observables: (optional) A list of observables to add to the request.
    :param list tags: (optional) If this request becomes an Alert, these tags will get added to it.
    :param list files: (optional) A list of (file_name, file_descriptor) tuples to be included in this ACE request.
    """
    def __init__(self, description, *args, **kwargs):
        # these just get passed to ace_api.submit function
        self.submit_args = args
        self.submit_kwargs = kwargs

        self.remote_host = default_remote_host
        self.ssl_verification = default_ssl_verification

        # default submission
        self.submit_kwargs = {
            'description': description,
            'analysis_mode': 'analysis',
            'tool': 'ace_api',
            'tool_instance': 'ace_api:{}'.format(socket.getfqdn()),
            'type': 'generic',
            'event_time': None,
            'details': {},
            'observables': [],
            'tags': [],
            'files': [],
        }

        for key, value in kwargs.items():
            if key in self.submit_kwargs:
                self.submit_kwargs[key] = value
            elif key == 'desc':
                self.submit_kwargs['description'] = value
            elif key == 'alert_type':
                self.submit_kwargs['type'] = value
            else:
                logging.debug("ignoring parameter {}".format(key))

        # this gets set after a successful call to submit
        self.uuid = None

        # and this gets set after an unsuccessful call to subit
        #self.uri = None
        #self.key = None

        # always try and close file pointers
        atexit.register(self._cleanup)

    def _cleanup(self):
        for file_name, fp in self.submit_kwargs['files']:
            try:
                fp.close()
            except:
                pass

    def __str__(self):
        return 'Analysis({})'.format(self.submit_kwargs)

    @property
    def validate_files(self):
        # make sure each file is a tuple of (something, str)
        _error_message = "Can not submit Analysis, file {} invalid: each element of the file parameter "\
                         "must be a tuple of (file_name, file_descriptor)"

        for index, f in enumerate(self.submit_kwargs['files']):
            assert isinstance(f, tuple), _error_message.format(index)
            assert len(f) == 2, _error_message.format(index)
            assert f[1], _error_message.format(index)
            assert isinstance(f[0], str), _error_message.format(index)

    @property
    def description(self):
        if 'description' in self.submit_kwargs:
            return self.submit_kwargs['description']

        return None

    @property
    def status(self):
        """Return the human readable status of this Analysis.

            - If this Analysis does not have a uuid, the status is 'UNKNOWN: UUID is None'.
            - A status of 'COMPLETE: No detections' is returned if this Analysis has a uuid but ACE returned a 404 for it (ACE deletes any analysis that didn't become an Alert).
            - 'ANALYZING' means ACE is working on the root analysis.
            - 'DELAYED' means ACE is waiting for one or more Analysis Modules to complete it's work.
            - 'NEW' means ACE has received the Analysis but hasn't started working on it yet. Analysis shouldn't stay in the NEW state long.
            - 'COMPLETE (Alerted with # detections)' means the Analysis became an Alert and has # detection points.
        """
        if self.uuid is None:
            return "UNKNOWN: UUID is None. Not submitted?"
        result = None
        try:
            result = get_analysis_status(self.uuid, remote_host=self.remote_host, ssl_verification=self.ssl_verification)
        except requests.exceptions.HTTPError as e:
            # UUID is not none, so ACE had to have received this analysis and then delete it after finding no detections
            return "COMPLETE: No detections"
        if 'result' not in result:
            logging.error("Unexpected result when getting analysis status: {}".format(result))
            return result
        result = result['result']
        if 'locks' in result and result['locks'] is not None:
            return "ANALYZING"
        if 'delayed_analysis' in result:
            assert isinstance(result['delayed_analysis'], list)
        if len(result['delayed_analysis']) > 0:
            return "DELAYED"
        if 'workload' in result and result['workload'] is not None:
            return "NEW"
        if 'alert' in result and result['alert'] is not None:
            a = result['alert']
            return "COMPLETE (Alerted with {} detections)".format(a['detection_count'])

        return "UNKNOWN"

    def set_description(self, description):
        self.submit_kwargs['description'] = description
        return self

    def set_remote_host(self, remote_host):
        """Set the remote host."""
        self.remote_host = remote_host
        return self

    def set_ssl_verification(self, ssl_verification):
        """Set the ssl verification behavior.

           - If set to None (the default) then the system installed CAs are used.
           - If set to False, then SSL verification is disabled.
           - Else, it is assumed to be a file that contains the CAs to be used to verify the SSL certificates.

        :param ssl_verification: see behavior above.
        :type ssl_verification: str or None or False
        """        
        self.ssl_verification = ssl_verification
        return self

    def add_tag(self, value):
        """Add a tag to this Analysis."""
        self.submit_kwargs['tags'].append(value)
        return self

    def add_observable(self, o_type, o_value, o_time=None, directives=[], limited_analysis=[], tags=[]):
        """Add an observable to this analysis.
        To all of the observable types and discriptions supported by the ACE instance you're working with, use ace_api.get_valid_observables().

        :param str o_type: The type of observable.
        :param str o_value: The value of the observable.
        """
        o = {
            'type': o_type,
            'value': o_value
        }

        if o_time is not None:
            o['time'] = o_time

        if directives:
            o['directives'] = directives

        if limited_analysis:
            o['limited_analysis'] = limited_analysis

        if tags:
            o['tags'] = tags

        self.submit_kwargs['observables'].append(o)
        return self

    def add_asset(self, value, *args, **kwargs):
        """Add a F_IPV4 identified to be a managed asset.

        :param str value: The value of the asset.
        """
        return self.add_observable('asset', value, *args, **kwargs)

    def add_email_address(self, value, *args, **kwargs):
        """Add an email address observable.

        :param str value: An email address
        """
        return self.add_observable('email_address', value, *args, **kwargs) 

    def add_email_conversation(self, value, *args, **kwargs):
        """Add a conversation between a source email address (MAIL FROM) and a destination email address (RCPT TO).

        :param str value: Email conversation formated like 'source_email_address|destination_email_address'
        """
        return self.add_observable('email_conversation', value, *args, **kwargs)

    def add_file(self, file_name_or_path, data_or_fp=None, relative_storage_path=None, *args, **kwargs):
        """Add a file to this analysis.

        :param str filename: The name of the file. Assumed to be a valid path to the file if data_or_fp is None.
        :param data_or_fp: (optional) A string or file pointer.
        :param str relative_storage_path: (optional) Where the file should be stored, relative to the analysis directory. Default is the root of the analysis.
        :type data_or_fp: str or None or _io.TextIOWrapper or _io.BufferedReader 
        """
        # get just the file name
        file_name = None
        if relative_storage_path is not None:
            file_name = relative_storage_path
        else:
            file_name = os.path.relpath(file_name_or_path)
        if data_or_fp is None:
            if not os.path.exists(file_name_or_path):
                logging.error("'{}' does not exist.".format(file_name_or_path))
                return self
            fp = open(file_name_or_path, 'rb')
            self.submit_kwargs['files'].append((file_name, fp))
            self.add_observable('file', file_name, *args, **kwargs)
            return self
        else:
            self.submit_kwargs['files'].append((file_name, data_or_fp))
            self.add_observable('file', file_name, *args, **kwargs)
            return self

    def add_file_location(self, file_location, *args, **kwargs):
        """Add a file location observable. This is the path to a file on a specific hostname.

        :param str file_locaiton: The location of file with format hostname@full_path
        """
        return self.add_observable('file_location', file_location, *args, **kwargs)

    def add_file_name(self, file_name, *args, **kwargs):
        """A the name of a file as an observable. See add_file to add the file itself.

        :param str file_name: a file name (no directory path)
        """
        return self.add_observable('file_name', file_name, *args, **kwargs)

    def add_file_path(self, file_path, *args, **kwargs):
        """Add a file path.

        :param str file_path: The file path.
        """
        return self.add_observable('file_path', file_path, *args, **kwargs)

    def add_fqdn(self, fqdn, *args, **kwargs):
        """Add a fully qualified domain name observable.

        :param str fqdn: fully qualified domain name
        """
        return self.add_observable('fqdn', fqdn, *args, **kwargs)


    def add_hostname(self, hostname, *args, **kwargs):
        """Add a host or workstation name.

        :param str hostname: host or workstation name
        """
        return self.add_observable('hostname', hostname, *args, **kwargs)


    def add_indicator(self, indicator, *args, **kwargs):
        """Add a CRITS indicator object id.

        :param str indicator: crits indicator object id
        """
        return self.add_observable('indicator', indicator, *args, **kwargs)

    def add_ipv4(self, ipv4, *args, **kwargs):
        """Add an IP address (version 4).

        :param str ipv4: IP address (version 4)
        """
        return self.add_observable('ipv4', ipv4, *args, **kwargs)

    def add_ipv4_conversation(self, ipv4_conversation, *args, **kwargs):
        """Add two IPV4 that were communicating.
        Formatted as 'aaa.bbb.ccc.ddd_aaa.bbb.ccc.ddd'

        :param str ipv4_conversation: Two IPV4 that were communicating. Formatted as 'aaa.bbb.ccc.ddd_aaa.bbb.ccc.ddd'
        """
        return self.add_observable('ipv4_conversation', ipv4_conversation, *args, **kwargs)

    def add_md5(self, md5_value, *args, **kwargs):
        """Add an MD5 hash.

        :param str md5_value: MD5 hash
        """
        return self.add_observable('md5', md5_value, *args, **kwargs)

    def add_message_id(self, message_id, *args, **kwargs):
        """Add an email Message-ID.

        :param str message_id: The email Message-ID
        """
        return self.add_observable('message_id', message_id, *args, **kwargs)

    def add_process_guid(self, guid, *args, **kwargs):
        """Add a CarbonBlack Response global process identifier.

        :param str guid: The Cb Response global process identifier
        """
        return self.add_observable('process_guid', guid, *args, **kwargs)

    def add_sha1(self, sha1, *args, **kwargs):
        """Add a SHA1 hash.

        :param str sha1: SHA1 hash
        """
        return self.add_observable('sha1', sha1, *args, **kwargs)

    def add_sha256(self, sha256, *args, **kwargs):
        """Add a SHA256 hash.

        :param str sha256: SHA256 hash
        """
        return self.add_observable('sha256', sha256, *args, **kwargs)

    def add_snort_sig(self, snort_sig, *args, **kwargs):
        """Add snort signature ID.

        :param str snort_sig: A snort signature ID
        """
        return self.add_observable('snort_sig', snort_sig, *args, **kwargs)

    def add_test(self, test, *args, **kwargs):
        # unittesting observable #
        return self.add_observable('test', test, *args, **kwargs)

    def add_url(self, url, *args, **kwargs):
        """Add a URL

        :param str url: The URL
        """
        return self.add_observable('url', url, *args, **kwargs)

    def add_user(self, user, *args, **kwargs):
        """Add a user observable to this analysis. Most support is arount NT an user ID. 

        :param str user: The user ID/name to add.
        """
        return self.add_observable('user', user, *args, **kwargs)

    def add_yara_rule(self, yara_rule, *args, **kwargs):
        """Add the name of a yara rule.

        :param str yara_rule: The name of the rule
        """
        return self.add_observable('yara_rule', yara_rule, *args, **kwargs)

    def add_attachment_link(self, source_path, relative_storage_path):
        self.add_file(source_path, relative_storage_path=relative_storage_path)
        return self

    def submit(self, remote_host=None, fail_dir=".saq_alerts", save_on_fail=True, ssl_verification=None):
        """Submit this Analysis object to ACE.

        :param str remote_host: (optional) Specify the ACE host you want to submit to in 'host:port' format.
        :param str fail_dir: (optional) Where any failed submissions are saved.
        :param bool save_on_fail: (optional) If true, save a copy of failed submissions to fail_dir.
        :param ssl_verificaiton: (optional) Change the SSL verificaiton behavior.
        :type ssl_verification: str or False or None
        """
        if remote_host:
            if remote_host.startswith('http'):
                from urllib.parse import urlparse
                parsed_url = urlparse(remote_host)
                logging.warn("remote_host in legacy format. Attempting to correct from '{}' to '{}'".format(remote_host, parsed_url.netloc))
                remote_host = parsed_url.netloc
        else:
            remote_host = self.remote_host

        if ssl_verification is None:
            ssl_verification = self.ssl_verification

        self.validate_files

        try:
            result = submit(remote_host=remote_host, 
                               ssl_verification=ssl_verification, 
                               *self.submit_args, **self.submit_kwargs)

            if 'result' in result:
                if 'uuid' in result['result']:
                    self.uuid = result['result']['uuid']

            return self

        except Exception as submission_error:
            logging.warning("unable to submit alert {}: {} (attempting to save alert to {})".format(
                            self, submission_error, fail_dir))

            if not save_on_fail:
                raise submission_error

            if fail_dir is None:
                logging.error("save_on_fail is set to True but fail_dir is set to None")
                raise submission_error

            self.uuid = str(uuid.uuid4())
            dest_dir = os.path.join(fail_dir, self.uuid)
            if not os.path.isdir(dest_dir):
                try:
                    os.makedirs(dest_dir)
                except Exception as e:
                    logging.error("unable to create directory {} to save alert {}: {}".format(
                                  dest_dir, self, e))
                    raise e

            # copy any files we wanted to submit to the directory
            for relative_storage_path, fp in self.submit_kwargs['files']:
                destination_path = os.path.join(dest_dir, relative_storage_path)
                destination_dir = os.path.dirname(destination_path)
                if destination_dir:
                    if not os.path.isdir(destination_dir):
                        os.makedirs(destination_dir)
                try:
                    # the call to submit caused the fp to get read. Restting with seek
                    fp.seek(0)
                    with open(destination_path, 'wb') as _f:
                        _f.write(fp.read())
                    fp.close()
                except Exception as e:
                    logging.error("unable to copy file data from {} to {}: {}".format(fp, destination_path, e))

            # now we need to reference the copied files 
            self.submit_kwargs['files'] = [(os.path.join(dest_dir, f[0]), f[0]) for f in self.submit_kwargs['files']]

            # remember these values for submit_failed_alerts()
            self.ssl_verification = ssl_verification

            # to write it out to the filesystem
            with open(os.path.join(dest_dir, 'alert'), 'wb') as fp:  
                pickle.dump(self, fp)

            logging.debug("saved alert {} to {}".format(self, dest_dir))
            raise submission_error

        finally:
            # we make sure we close our file descriptors
            for file_name, fp in self.submit_kwargs['files']:
                if not isinstance(fp, str):
                    if not fp.closed:
                        try:
                            fp.close()
                        except Exception as e:
                            logging.error("unable to close file descriptor for {}".format(file_name))


class Alert(Analysis):
    """This class primarily supports backwards compatibility with the old client lib.
    
        - SSL verification default behavior is different.
        - Analysis mode default is correlation, forcing alert creation without detection.
        - Files are handles differently.

    There is no reason to use this class rather than the Analysis class.
    If you want to force an analysis submission to become an alert, you should declare your Analysis with the analysis_mode set to 'correlation'.
    """
    def __init__(self, description, *args, **kwargs):
        super().__init__(description, *args, **kwargs)
        # default mode for legacy api is correlation
        self.submit_kwargs['analysis_mode'] = 'correlation'

    def add_attachment_link(self, source_path, relative_storage_path):
        self.submit_kwargs['files'].append((source_path, relative_storage_path))
        return self

    def add_file(self, source_path, relative_storage_path=None, *args, **kwargs):
        """Add a file to this Alert.

        :param str source_path: The path to the file.
        :param str relative_storage_path: (optional) Where the file should be stored, relative to the analysis directory. Default is the root of the analysis.
        """
        file_name = os.path.basename(source_path)
        if relative_storage_path is None:
            relative_storage_path = file_name
        if not os.path.exists(source_path):
            logging.error("'{}' does not exist.".format(source_path))
            return self
        self.submit_kwargs['files'].append((source_path, relative_storage_path))
        self.add_observable('file', file_name, *args, **kwargs)
        return self

    # support legacy submit function
    def submit(self, uri=None, key=None, fail_dir=".saq_alerts", save_on_fail=True, ssl_verification=None):

        self.uri = uri
        self.key = key
        remote_host = self.remote_host
        if uri is not None:
            from urllib.parse import urlparse
            parsed_url = urlparse(uri)
            remote_host = parsed_url.netloc

        kwargs = {}
        kwargs.update(self.submit_kwargs)
        # originally kwargs['files'] was a tuple of (source_path, relative_storage_path)
        # the file params should be a tuple of (relative_storage_path, file descriptor)
        # NOTE: The assuption is that this Alert.submit funciton will only be used by legacy code
        # where kwargs['files'] is a tuple of (source_path, relative_storage_path)
        self.submit_kwargs['files'] = [(f[1], open(f[0], 'rb')) for f in kwargs['files']]
        # the old "api" didn't even use SSL so if this Alert class is used to submit the
        # ACE default SSL cert location should be used rather than the OS's trusted certs
        # basically, this is changing the default behavior of ace_api for ssl_verifcation
        if ssl_verification is None:
            ssl_verification = '/opt/ace/ssl/ca-chain.cert.pem'

        return super(Alert, self).submit(remote_host=remote_host, fail_dir=fail_dir, save_on_fail=save_on_fail, ssl_verification=ssl_verification)


@support_command
def submit_failed_alerts(remote_host=None, ssl_verification=None, fail_dir='.saq_alerts', delete_on_success=True, *args, **kwargs):
    """Submits any alerts found in .saq_alerts, or, the directory specified by the fail_dir parameter."""
    if not os.path.isdir(fail_dir):
        return

    for subdir in os.listdir(fail_dir):
        target_path = os.path.join(fail_dir, subdir, 'alert')
        try:
            logging.info("loading {}".format(target_path))
            with open(target_path, 'rb') as fp:
                alert = pickle.load(fp)
        except Exception as e:
            logging.error("unable to load {}: {}".format(target_path, e))
            continue

        try:
            # we allow the user to change what server we're sending to
            # otherwise
            kwargs = {}
            if remote_host is not None:
                kwargs['uri'] = 'https://{}'.format(remote_host)
                logging.info("submitting {} to {}".format(target_path, kwargs['uri']))
            if ssl_verification is not None:
                kwargs['ssl_verification'] = ssl_verification

            if isinstance(alert, Alert):
                alert.submit(save_on_fail=False, **kwargs)
            elif isinstance(alert, Analysis):
                # we need to open file handles for the Analysis class
                # because they are saved a tuple of (source_path, relative_storage_path) on fail
                alert.submit_kwargs['files'] = [(f[1], open(f[0], 'rb')) for f in alert.submit_kwargs['files']]
                alert.submit(save_on_fail=False, **kwargs)

            if delete_on_success:
                try:
                    target_dir = os.path.join(fail_dir, subdir)
                    shutil.rmtree(target_dir)
                except Exception as e:
                    logging.error("unable to delete directory {}: {}".format(target_dir, e))
        except Exception as e:
            logging.error("unable to submit {}: {}".format(target_path, e))


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ACE API Command Line Wrapper")
    subparsers = parser.add_subparsers(dest='cmd')

    all_commands = api_commands[:]
    all_commands.extend(support_commands)

    for command in all_commands:
        subcommand_parser = subparsers.add_parser('api-' + command.__name__.replace('_', '-'), help=command.__doc__)
        if command in api_commands:
            subcommand_parser.add_argument('remote_host', help="The remote host to connect to in host[:port] format.")
            subcommand_parser.add_argument('--ssl-verification', required=False, default='/opt/ace/ssl/ca-chain.cert.pem',
                help="Optional path to root CA ssl to load.")
        command_signature = inspect.signature(command)
        for p_name, parameter in command_signature.parameters.items():
            if p_name not in [ 'args', 'kwargs' ]:
                # if this command does NOT have a default_value then it's a positional command
                if parameter.default == inspect.Parameter.empty:
                    subcommand_parser.add_argument(parameter.name, help="(REQUIRED)")
                else:
                    subcommand_parser.add_argument('--{}'.format(parameter.name.replace('_', '-')), 
                                                   required=False,
                                                   dest=parameter.name,
                                                   default=parameter.default,
                                                   help="(default: {})".format(parameter.default))

        subcommand_parser.set_defaults(func=command, conv=None)

    submit_command_parser = subparsers.add_parser('submit')
    submit_command_parser.add_argument('remote_host', help="The remote host to connect to in host[:port] format.")
    submit_command_parser.add_argument('description', help="The description (title) of the analysis.")
    submit_command_parser.add_argument('--ssl-verification', required=False, default='/opt/ace/ssl/ca-chain.cert.pem',
        help="Optional path to root CA ssl to load.")
    submit_command_parser.add_argument('-m', '--mode', '--analysis_mode', dest='analysis_mode',
        help="The mode of analysis. Defaults of analysis. Set it to correlation to automatically become an alert.")
    submit_command_parser.add_argument('--tool', 
        help="The name of the tool that generated the analysis request. Defaults to ace_api")
    submit_command_parser.add_argument('--tool_instance',
        help="The instance of the tool that generated the analysis request. Defautls to ace_api(ipv4).")
    submit_command_parser.add_argument('--type',
        help="The type of the analysis. Defaults to generic.")
    submit_command_parser.add_argument('-t', '--time', '--event-time', dest='event_time',
        help="""The time of the event that triggered the analysis, or the source reference time for all analysis. 
                The expected format is {DATETIME_FORMAT}. Defaults to current time and current time zone.""")
    submit_command_parser.add_argument('-d', '--details', dest='details',
        help="""The free form JSON dict that makes up the details of the analysis.""")
    submit_command_parser.add_argument('-o', '--observables', nargs='+', dest='observables',
        help="""Adds the given observable to the analysis in the following format:
                type:value:[:time][:tags_csv][:directives_csv][:limited_analysis_csv]
                Any times must be in {DATETIME_FORMAT} format.""")
    submit_command_parser.add_argument('-T', '--tags', nargs='+', dest='tags',
        help="""The list of tags to add to the analysis.""")
    submit_command_parser.add_argument('-f', '--files', nargs='+', dest='files',
        help="""The list of files to add to the analysis.
                Each file name can optionally be renamed in the remote submission by using the format
                source_path-->dest_path where dest_path is a relative path.""")
    submit_command_parser.set_defaults(func=submit, conv=parse_submit)

    args = parser.parse_args()

    try:
        # do we need to preprocess the arguments?
        if args.conv:
            args = args.conv(args)

        # call the handler for the given command
        params = copy.copy(vars(args))
        if 'cmd' in params:
            del params['cmd']
        if 'func' in params:
            del params['func']
        if 'conv' in params:
            del params['conv']

        # remove any parameters not set
        params = {key: value for key, value in params.items() if value is not None}

        result = args.func(**params)
        #result = commands[args.command](remote_host=args.remote_host, 
                                        #ssl_verification=args.ssl_verification, 
                                        #*args.command_arguments)

        if args.func in api_commands:
            print(json.dumps(result, sort_keys=True, indent=4))

    except Exception as e:
        sys.stderr.write("unable to execute api call: {}\n".format(e))
        traceback.print_exc()
        if hasattr(e, 'response'):
            if hasattr(e.response, 'text'):
                print(e.response.text)

if __name__ == '__main__':
    main()
