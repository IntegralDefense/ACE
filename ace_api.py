#!/usr/bin/env python3
# vim: ts=4:sw=4:et:cc=120

#
# python3 wrapper for ACE API calls

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

import datetime
import io
import json
import logging
import os
import os.path
import socket
import sys
import tarfile
import tempfile
import traceback
import urllib3
import warnings

# ignoring this: /usr/lib/python3/dist-packages/urllib3/connection.py:344:
# SubjectAltNameWarning: Certificate for localhost has no `subjectAltName`,
# falling back to check for a `commonName` for now. This feature is being
# removed by major browsers and deprecated by RFC 2818. (See
# https://github.com/shazow/urllib3/issues/497 for details.)

warnings.simplefilter('ignore', urllib3.exceptions.SecurityWarning)

# get our custom logger we use for this library
log = logging.getLogger(__name__)

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

# dictionary that maps command names to their functions
commands = { }

# the default remote host to use when no remote host is provided
default_remote_host = 'localhost'
default_ssl_verification = None

# the local timezone
LOCAL_TIMEZONE = pytz.timezone(tzlocal.get_localzone().zone)

# the datetime string format we use for this api
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'

def api_command(func):
    global commands
    commands[func.__name__] = func
    return func

def _execute_api_call(command, remote_host=None, ssl_verification=None, stream=False, data=None, files=None):
    if remote_host is None:
        remote_host = default_remote_host

    if ssl_verification is None:
        ssl_verification = default_ssl_verification

    if data is None:
        # if we're not passing data then it's a GET
        r = requests.get('https://{}/api/{}'.format(remote_host, command), verify=ssl_verification, stream=stream)
    else:
        # otherwise it's a POST
        r = requests.post('https://{}/api/{}'.format(remote_host, command), verify=ssl_verification, stream=stream,
                          data=data, files=files)

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

    # make sure you passed in *something* for the description
    assert(description)

    # default event time is now
    if event_time is None:
        event_time = datetime.datetime.now()

    # convert to UTC and then to the correct datetime format string for ACE
    formatted_event_time = LOCAL_TIMEZONE.localize(event_time).astimezone(pytz.UTC).strftime(DATETIME_FORMAT)

    # make sure the observables are in the correct format
    for o in observables:
        assert isinstance(o, dict)
        assert 'type' in o, "missing type in observable {}".format(o)
        assert 'value' in o, "missing value in observable {}".format(o)
        for key in o.keys():
            assert key in [ 'type', 'value', 'time', 'tags', 'directives', 'limited_analysis' ], "unknown observable property {} in {}".format(key, o)

        # make sure any times are formatted
        if isinstance(o['time'], datetime.datetime):
            o['time'] = LOCAL_TIMEZONE.localize(o['time']).astimezone(pytz.UTC).strftime(DATETIME_FORMAT)

    # make sure the tags are strings
    for t in tags:
        assert isinstance(t, str), "tag {} is not a string".format(t)

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
    }, files=files_params).json()

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
                files=[('archive', (os.path.basename(tar_path), fp))]).json()
    finally:
        try:
            os.remove(tar_path)
        except Exception as e:
            log.warning("unable to remove {}: {}".foramt(tar_path, e))

@api_command
def clear(uuid, lock_uuid, *args, **kwargs):
    return _execute_api_call('engine/clear/{}/{}'.format(uuid, lock_uuid), *args, **kwargs).status_code == 200

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="ACE API Command Line Wrapper")
    parser.add_argument('remote_host', help="The remote host to connect to in host[:port] format.")
    parser.add_argument('command', choices=commands.keys(), help="The API command to execute.")
    parser.add_argument('command_arguments', nargs='*', help="The arguments to the API call.")
    parser.add_argument('--ssl-verification', required=False, default='/opt/ace/ssl/ca-chain.cert.pem',
        help="Optional path to root CA ssl to load.")
    args = parser.parse_args()

    try:
        result = commands[args.command](remote_host=args.remote_host, 
                                        ssl_verification=args.ssl_verification, 
                                        *args.command_arguments)
        print(json.dumps(result, sort_keys=True, indent=4))
    except Exception as e:
        sys.stderr.write("unable to execute api call: {}\n".format(e))
        if hasattr(e, 'response'):
            print(e.response.text)
