#!/usr/bin/env python3
# vim: ts=4:sw=4:et:cc=120

#
# python3 wrapper for ACE API calls

try:
    import requests
except ImportError:
    print("You need to install the python Requests library (see http://docs.python-requests.org/en/master/)")
    sys.exit(1)

import io
import json
import os
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

def set_default_node(node):
    """Sets the default node used when no node is provided to the API calls."""
    global default_node
    default_node = node

def set_default_ssl_ca_path(ssl_verification):
    """Sets the default SSL verification mode. 
       If set to None (the default) then the default (installed) CAs are used.
       If set to False, then SSL verification is disabled.
       Other it is assumed to be a file that contains the CAs to be used to verify the SSL certificates."""
    global default_ssl_verification
    default_ssl_verification = ssl_verification

# dictionary that maps command names to their functions
commands = { }

# the default node to use when no node is provided
default_node = 'localhost'
default_ssl_verification = None

def api_command(func):
    global commands
    commands[func.__name__] = func
    return func

def _execute_api_call(command, node=None, ssl_verification=None, stream=False):
    if node is None:
        node = default_node

    if ssl_verification is None:
        ssl_verification = default_ssl_verification

    r = requests.get('https://{}/api/{}'.format(node, command), verify=ssl_verification, stream=stream)
    r.raise_for_status()
    return r

@api_command
def ping(*args, **kwargs):
    return _execute_api_call('common/ping', *args, **kwargs).json()

@api_command
def transfer(uuid, target_dir, *args, **kwargs):

    if not os.path.isdir(target_dir):
        os.makedirs(target_dir)

    fp, tar_path = tempfile.mkstemp(prefix='transfer_{}'.format(uuid), suffix='.tar')

    try:
        r = _execute_api_call('engine/transfer/{}'.format(uuid), stream=True, *args, **kwargs)

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
def clear(uuid, lock_uuid, *args, **kwargs):
    return _execute_api_call('engine/clear/{}/{}'.format(uuid, lock_uuid), *args, **kwargs).status_code == 200

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="ACE API Command Line Wrapper")
    parser.add_argument('node', help="The remote node to connect to in host[:port] format.")
    parser.add_argument('command', choices=commands.keys(), help="The API command to execute.")
    parser.add_argument('command_arguments', nargs='*', help="The arguments to the API call.")
    parser.add_argument('--ssl-verification', required=False, default='/opt/ace/ssl/ca-chain.cert.pem',
        help="Optional path to root CA ssl to load.")
    args = parser.parse_args()

    try:
        result = commands[args.command](node=args.node, 
                                        ssl_verification=args.ssl_verification, 
                                        *args.command_arguments)
        print(json.dumps(result, sort_keys=True, indent=4))
    except Exception as e:
        sys.stderr.write("unable to execute api call: {}\n".format(e))
        if hasattr(e, 'response'):
            print(e.response.text)
