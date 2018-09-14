#!/usr/bin/env python3
# vim: sw=4:ts=4:et

import argparse
import os
import os.path
import logging
import logging.config
import logging.handlers
import ssl
import sys
import io
import time
import traceback
import signal
import socket

from configparser import ConfigParser
from subprocess import Popen, PIPE, DEVNULL

PID_FILE = 'brotex_client.pid'

class BrotexClient(object):
    def __init__(self, config_path):
        self.config = ConfigParser()
        self.config.read(config_path)

        self.data_dir = self.config['brotex']['data_dir']
        if not os.path.isdir(self.data_dir):
            logging.error("missing data_dir {}".format(self.data_dir))
            sys.exit(1)

        # the number of tar files we send at once
        self.batch_size = self.config['brotex'].getint('batch_size')

        # root signing cert for SSL
        self.root_cert_store = self.config['brotex']['root_cert_store']

        # number of seconds until a socket times out
        self.network_timeout = self.config['brotex'].getint('network_timeout')

        # the index to the next engine to send files to
        self.engine_index = 0
        # the list of valid engine URIs available for processing
        self.engine_uris = []
        for section in self.config.keys():
            if section.startswith('engine_'):
                self.engine_uris.append((self.config[section]['remote_host'], 
                                         self.config[section].getint('remote_port'), 
                                         self.config[section]['remote_host_name']))

        self.shutdown = False

    def start(self):
        # initialize signal handler
        def handler(signum, frame):
            logging.warning("got signal {} in frame {}".format(signum, frame))
            self.shutdown = True

        signal.signal(signal.SIGTERM, handler)
        self.shutdown = False
        self.run()

    def stop(self):
        self.shutdown = True

    def run(self):
        while not self.shutdown:
            try:
                self.execute()
            except KeyboardInterrupt:
                logging.warning("caught user interrupt")
                sys.exit(1)
            except Exception as e:
                logging.error("uncaught exception: {}".format(e))
                traceback.print_exc()
                time.sleep(1) # throttle

    def execute(self):

        file_buffer = []
        files_available = 0

        while True:
            find_p = Popen(['find', '-L', self.data_dir, '-type', 'f', '-name', '*.tar', '-mmin', '+1', '-print0'], 
                           stdout=PIPE, stderr=DEVNULL)
            xargs_p = Popen(['xargs', '-r0', 'stat', '--printf', r'%Y\t%n\n'], stdin=find_p.stdout, stdout=PIPE, stderr=DEVNULL)
            sort_p = Popen(['sort'], stdin=xargs_p.stdout, stdout=PIPE, stderr=DEVNULL)
            cut_p = Popen(['cut', '-f', '2-'], stdin=sort_p.stdout, stdout=PIPE, stderr=DEVNULL)
            _stdout, _stderr = cut_p.communicate()
            cut_p.wait()

            for line in _stdout.decode().split('\n'):
                line = line.strip()
                if not line.endswith('.tar'):
                    continue

                if self.shutdown:
                    break

                #line = os.path.join(self.data_dir, line)
                # make sure we can read the file
                try:
                    if not os.path.exists(line):
                        logging.error("file {} does not exist - skipping".format(line))
                        continue
                except Exception as e:
                    logging.error("unable to state file {}: {}".format(line, e))
                    continue

                logging.debug("found {}".format(line))
                file_buffer.append(line)
                files_available += 1

                if len(file_buffer) >= self.batch_size:
                    try:
                        self.submit(file_buffer)
                    except Exception as e:
                        time.sleep(1)
                        break

                    self.delete(file_buffer)
                    file_buffer = []

            if len(file_buffer):
                try:
                    self.submit(file_buffer)
                except Exception as e:
                    time.sleep(1)
                    break

                self.delete(file_buffer)
                file_buffer = []

            break

        # if nothing is availabe to send then sleep for a second and try again (throttle)
        if not self.shutdown and not files_available:
            time.sleep(1)

    def kill(self):
        if not os.path.exists(PID_FILE):
            logging.info("no daemon process detected")
            sys.exit(0)

        try:
            pid = None
            with open(PID_FILE, 'r') as fp:
                pid = int(fp.read())

            logging.info("killing pid {}".format(pid))
            os.kill(pid, signal.SIGKILL)

            try:
                os.remove(PID_FILE)
            except Exception as e:
                logging.error("unable to remote pid file {}".format(PID_FILE))

        except Exception as e:
            logging.error("unable to kill pid {}: {}".format(pid, e))

    def daemonize(self):
        """Spawns a fork into the background."""
        if os.path.exists(PID_FILE):
            logging.error("the file {} already exists - try running with the -k option first", PID_FILE)
            sys.exit(1)

        pid = None

        # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
        try:
            pid = os.fork()
        except OSError as e:
            logging.fatal("{0} ({1})".format(e.strerror, e.errno))
            sys.exit(1)

        if pid == 0:
            os.setsid()

            try:
                pid = os.fork()
            except OSError as e:
                logging.fatal("{0} ({1})".format(e.strerror, e.errno))
                sys.exit(1)

            if pid > 0:
                # write the pid to a file
                with open(PID_FILE, 'w') as fp:
                    fp.write(str(pid))

                logging.info("recorded process id {}".format(pid))
                os._exit(0)
        else:
            os._exit(0)

        import resource
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
            maxfd = MAXFD

            for fd in range(0, maxfd):
                try:
                    os.close(fd)
                except OSError:   # ERROR, fd wasn't open to begin with (ignored)
                    pass

        if (hasattr(os, "devnull")):
            REDIRECT_TO = os.devnull
        else:
            REDIRECT_TO = "/dev/null"

        os.open(REDIRECT_TO, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)

    def submit(self, file_buffer):
        tar_command = ['tar', 'zc']
        tar_command.extend(file_buffer)

        remote_host, remote_port, remote_host_name = self.engine_uris[self.engine_index]
        self.engine_index += 1
        if self.engine_index >= len(self.engine_uris):
            self.engine_index = 0

        client_socket = None

        try:
            # round robin select the sensor to send to
            context = ssl.create_default_context()
            context.load_verify_locations(self.root_cert_store)
            client_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=remote_host_name)
            client_socket.settimeout(self.network_timeout)
            logging.info("connecting to {}:{}".format(remote_host, remote_port))
            client_socket.connect((remote_host, remote_port))

            p = None
            try:
                p = Popen(tar_command, stdout=PIPE, stderr=DEVNULL)
                total_bytes = 0
                while True:
                    data = p.stdout.read(io.DEFAULT_BUFFER_SIZE)
                    if data == b'':
                        break

                    client_socket.sendall(data)
                    total_bytes += len(data)

                logging.info("sent {} bytes to {}:{}".format(total_bytes, remote_host, remote_port))
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
                client_socket = None
                p.wait()

                if p.returncode:
                    raise RuntimeError("tar command returned {}".format(p.returncode))

                p = None

            finally:
                if p is not None:
                    try:
                        logging.error("killing process tar process {}".format(p.pid))
                        p.kill()
                        p.wait()
                    except Exception as e:
                        logging.error("unable to kill tar process: {}".format(e))

        except socket.timeout as e:
            logging.error("network connection timed out")
            raise e

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

    def delete(self, file_buffer):
        for file_path in file_buffer:
            try:
                os.remove(file_path)
            except Exception as e:
                logging.error("unable to remove {}: {}".format(file_path, e))

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Brotex Client")
    parser.add_argument('-c', '--config', required=False, dest='config_path', default='etc/brotex_client.ini',
        help="Path to configuration file.")
    parser.add_argument('-L', '--logging-config', required=False, dest='logging_config_path', default='etc/brotex_client_logging.ini',
        help="Path to logging configuration file.")
    parser.add_argument('-d', '--daemon', required=False, dest='daemon', action='store_true', default=False,
        help="Execute as a background process.  Use -k to kill the existing process.")
    parser.add_argument('-k', '--kill', required=False, dest='kill_daemon', action='store_true', default=False,
        help="Kill the existing daemon.")
    args = parser.parse_args()

    # make sure the logging subdir exists
    if not os.path.isdir('logs'):
        try:
            os.mkdir('logs')
        except Exception as e:
            sys.stderr.write("cannot create logs subdir: {}".format(e))
            sys.exit(1)

    try:
        logging.config.fileConfig(args.logging_config_path)
    except Exception as e:
        sys.stderr.write("unable to load logging configuration file {0}: {1}".format(
            args.logging_config_path, str(e)))
        sys.exit(1)

    client = BrotexClient(args.config_path)

    if args.kill_daemon:
        client.kill()
        sys.exit(0)

    if args.daemon:
        client.daemonize()

    client.start()
