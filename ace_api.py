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
    """Sets the default remote host used when no remote host is provided to the API calls."""
    global default_remote_host
    default_remote_host = remote_host

def set_default_ssl_ca_path(ssl_verification):
    """Sets the default SSL verification mode. 
       If set to None (the default) then the default (installed) CAs are used.
       If set to False, then SSL verification is disabled.
       Other it is assumed to be a file that contains the CAs to be used to verify the SSL certificates."""
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
    return _execute_api_call('common/get_supported_api_version', *args, **kwargs).json()

@api_command
def get_valid_companies(*args, **kwargs):
    return _execute_api_call('common/get_valid_companies', *args, **kwargs).json()

@api_command
def get_valid_observables(*args, **kwargs):
    return _execute_api_call('common/get_valid_observables', *args, **kwargs).json()

@api_command
def ping(*args, **kwargs):
    return _execute_api_call('common/ping', *args, **kwargs).json()

def parse_submit(args):
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
    """Submit an analysis request to ACE."""

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
    if isinstance(details, str):
        details = json.loads(details)

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
def get_analysis(uuid, *args, **kwargs):
    return _execute_api_call('analysis/{}'.format(uuid), *args, **kwargs).json()

@api_command
def get_analysis_details(uuid, name, *args, **kwargs):
    return _execute_api_call('analysis/details/{}/{}'.format(uuid, name), *args, **kwargs).json()

@api_command
def get_analysis_file(uuid, name, output_file=None, output_fp=None, *args, **kwargs):
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
    return _execute_api_call('analysis/status/{}'.format(uuid), *args, **kwargs).json()

@api_command
def download(uuid, target_dir, *args, **kwargs):

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
    return _execute_api_call('engine/clear/{}/{}'.format(uuid, lock_uuid), *args, **kwargs).status_code == 200

@api_command
def cloudphish_submit(url, reprocess=False, ignore_filters=False, context={}, *args, **kwargs):

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

class Alert(object):
    def __init__(self, *args, **kwargs):
        # these just get passed to ace_api.submit function
        self.submit_args = args
        self.submit_kwargs = kwargs

        # we only use this (now) when we save a failed submission

        # default submission
        self.submit_kwargs = {
            'description': None,
            'analysis_mode': 'correlation',
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
        self.url = None
        self.key = None
        self.ssl_verification = None

    def __str__(self):
        return 'Alert({})'.format(self.submit_kwargs)

    @property
    def description(self):
        if 'description' in self.submit_kwargs:
            return self.submit_kwargs['description']

        return None

    def add_tag(self, value):
        self.submit_kwargs['tags'].append(value)

    def add_observable(self, o_type, o_value, o_time=None, is_suspect=False, directives=[]):
        o = {
            'type': o_type,
            'value': o_value
        }

        if o_time is not None:
            o['time'] = o_time

        if directives:
            o['directives'] = directives

        self.submit_kwargs['observables'].append(o)

    def add_attachment_link(self, source_path, relative_storage_path):
        self.submit_kwargs['files'].append((source_path, relative_storage_path))

    def submit(self, uri=None, key=None, fail_dir=".saq_alerts", save_on_fail=True, ssl_verification=None):

        if uri is None:
            uri = self.uri

        if key is None:
            key = self.key

        if ssl_verification is None:
            ssl_verification = self.ssl_verification

        from urllib.parse import urlparse
        parsed_url = urlparse(uri)
        remote_host = parsed_url.netloc

        kwargs = {}
        kwargs.update(self.submit_kwargs)
        # currently kwargs['files'] is a tuple of (source_path, relative_storage_path)
        # the file params should be a tuple of (remote_name, file descriptor)
        kwargs['files'] = [(f[1], open(f[0], 'rb')) for f in kwargs['files']]

        try:
            result = submit(remote_host=remote_host, 
                               # the old "api" didn't even use SSL so we just use the ACE default SSL cert location
                               ssl_verification=ssl_verification if ssl_verification else '/opt/ace/ssl/ca-chain.cert.pem', 
                               *self.submit_args, **kwargs)

            if 'result' in result:
                if 'uuid' in result['result']:
                    self.uuid = result['result']['uuid']

            return self.uuid

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
            for source_path, relative_storage_path in self.submit_kwargs['files']:
                destination_path = os.path.join(dest_dir, relative_storage_path)
                destination_dir = os.path.dirname(destination_path)
                if destination_dir:
                    if not os.path.isdir(destination_dir):
                        os.makedirs(destination_dir)

                try:
                    shutil.copy2(source_path, destination_path)
                except Exception as e:
                    logging.error("unable to copy file from {} to {}: {}".format(source_path, destination_path, e))

            # now we need to reference the copied files
            self.submit_kwargs['files'] = [(os.path.join(dest_dir, f[1]), f[1]) for f in self.submit_kwargs['files']]

            # remember these values for submit_failed_alerts()
            self.uri = uri
            self.key = key
            self.ssl_verification = ssl_verification
                
            # to write it out to the filesystem
            with open(os.path.join(dest_dir, 'alert'), 'wb') as fp:  
                pickle.dump(self, fp)

            logging.debug("saved alert {} to {}".format(self, dest_dir))
            raise submission_error

        finally:
            # we make sure we close our file descriptors
            for file_name, fp in kwargs['files']:
                try:
                    fp.close()
                except Exception as e:
                    logging.error("unable to close file descriptor for {}".format(file_name))

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
            if ssl_verification is not None:
                kwargs['ssl_verification'] = ssl_verification

            alert.submit(save_on_fail=False, **kwargs)

            if delete_on_success:
                try:
                    target_dir = os.path.join(fail_dir, subdir)
                    shutil.rmtree(target_dir)
                except Exception as e:
                    logging.error("unable to delete directory {}: {}".format(target_dir, e))
        except Exception as e:
            logging.error("unable to submit {}: {}".format(target_path, e))

if __name__ == '__main__':
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
