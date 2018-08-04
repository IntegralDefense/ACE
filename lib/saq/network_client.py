#!/usr/bin/env python3
# vim: sw=4:ts=4:et:cc=120

import io
import logging
import os.path
import shutil
import socket
import ssl
import tempfile
import uuid

from subprocess import Popen, PIPE, DEVNULL

def submit_alerts(remote_host, remote_port, ssl_cert, ssl_hostname, ssl_key, ca_path, dirs):
    """Submits the given alerts to the given ACE system. """
    """Returns the list of alerts that were successfully submitted."""
    assert remote_host
    assert remote_port
    assert ssl_cert
    assert ssl_hostname
    assert ssl_key
    assert ca_path
    assert dirs

    if isinstance(dirs, str):
        assert dirs
        dirs = [dirs]
    else:
        assert isinstance(dirs, list)
        assert dirs

    if not os.path.exists(ssl_cert):
        raise RuntimeError("missing ssl_cert {}".format(ssl_cert))

    if not os.path.exists(ssl_key):
        raise RuntimeError("missing ssl_key {}".format(ssl_key))

    if not os.path.exists(ca_path):
        raise RuntimeError("missing ca_path {}".format(ca_path))
     
    tar_files = []
    result = []

    temp_dir = tempfile.mkdtemp(suffix='.submit')
    for storage_dir in dirs:

        tar_file = os.path.join(temp_dir, '{}.tar'.format(str(uuid.uuid4())))
        p = Popen(['tar', 'cf', tar_file, '-C', storage_dir, '.'], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        _stdout, _stderr = p.communicate()
        p.wait()

        if _stderr:
            logging.warning("tar command printed text to stderr for {}: {}".format(storage_dir, _stderr))

        if p.returncode != 0:
            logging.error("tar command return non-zero status for {}".format(storage_dir))
            continue
            

        tar_files.append(tar_file)
        result.append(storage_dir)

    # submit all of the given emails to the remote system
    tar_command = ['tar', 'zc']
    tar_command.extend(tar_files)

    client_socket = None

    try:
        # round robin select the sensor to send to
        context = ssl.create_default_context()
        context.load_verify_locations(ca_path)
        context.load_cert_chain(ssl_cert, keyfile=ssl_key)
        client_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=ssl_hostname)
        logging.debug("connecting to {}:{}".format(remote_host, remote_port))
        client_socket.connect((remote_host, remote_port))

        p = Popen(tar_command, stdout=PIPE, stderr=DEVNULL) # XXX catch error output
        total_bytes = 0
        while True:
            data = p.stdout.read(io.DEFAULT_BUFFER_SIZE)
            if data == b'':
                break

            client_socket.sendall(data)
            total_bytes += len(data)

        logging.debug("sent {} bytes to {}:{}".format(total_bytes, remote_host, remote_port))
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()
        client_socket = None
        p.wait()

        if p.returncode:
            raise RuntimeError("tar command returned {}".format(p.returncode))

        return result

    except Exception as e:
        logging.error("unable to submit to {}:{}: {}".format(remote_host, remote_port, e))
        raise e

    finally:
        if client_socket:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except:
                pass

        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            logging.error("unable to delete temporary directory {}: {}".format(temp_dir, e))
            report_exception()
