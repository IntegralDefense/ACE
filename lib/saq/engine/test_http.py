# vim: sw=4:ts=4:et

import filecmp
import logging
import multiprocessing
import os
import os.path
import re
import shutil
import tempfile

from subprocess import Popen

import saq, saq.test

from saq.anp import *
from saq.constants import *
from saq.engine import MODE_LOCAL, MODE_CLIENT, MODE_SERVER
from saq.engine.http import HTTPScanningEngine
from saq.test import *

class HTTPEngineTestCase(ACEEngineTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.bro_http_dir = saq.CONFIG['engine_http_scanner']['bro_http_dir']
        self.bro_work_dir = tempfile.mkdtemp(dir=os.path.join(saq.SAQ_HOME, 'var', 'tmp'))

        os.mkdir(os.path.join(self.bro_work_dir, 'ace'))
        with open(os.path.join(self.bro_work_dir, 'ace', 'ace_local.bro'), 'w') as fp:
            Popen(['sed', '-e', 's:bro/http";:bro/http_unittest";:', os.path.join(saq.SAQ_HOME, 'bro', 'ace_local.bro')], stdout=fp).wait()
        shutil.copy(os.path.join(saq.SAQ_HOME, 'bro', 'ace_http.bro'), os.path.join(self.bro_work_dir, 'ace', 'ace_http.bro'))
        
        if os.path.isdir(self.bro_http_dir):
            shutil.rmtree(self.bro_http_dir)

        os.makedirs(self.bro_http_dir)

        # TODO figure out this path dynamically
        self.bro_bin_path = '/opt/bro/bin/bro'

        # disable encryption
        saq.ENCRYPTION_PASSWORD = None

        # create temporary root directory for server side operations
        self.temp_root_dir = os.path.join(saq.SAQ_HOME, 'var', 'test', 'anp_receive')
        if os.path.isdir(self.temp_root_dir):
            shutil.rmtree(self.temp_root_dir)

        os.makedirs(self.temp_root_dir)

    def tearDown(self, *args, **kwargs):
        super().tearDown(*args, **kwargs)

        if os.path.isdir(self.bro_work_dir):
            shutil.rmtree(self.bro_work_dir)

    def process_pcap(self, pcap_path):
        Popen([self.bro_bin_path, '-C', '-r', pcap_path, os.path.join('ace', 'ace_http.bro')], cwd=self.bro_work_dir).wait()
        
    def test_http_engine_000_startup_mode_local(self):
        engine = self.create_engine(HTTPScanningEngine)
        self.assertEquals(engine.mode, MODE_LOCAL)
        self.start_engine(engine)
        engine.stop()
        self.wait_engine(engine)

    @reset_config
    def test_http_engine_001_startup_mode_server(self):
        saq.CONFIG['engine_http_scanner']['mode'] = MODE_SERVER
        engine = self.create_engine(HTTPScanningEngine)
        self.start_engine(engine)

        anp_interface = engine.config.get('anp_listening_address',
                        saq.CONFIG['anp_defaults']['anp_listening_address'])
        anp_port = engine.config.get('anp_listening_port',
                        saq.CONFIG['anp_defaults'].getint('anp_listening_port'))

        wait_for_log_count('listening for connections on {} port {}'.format(anp_interface, anp_port), 1, 5)

        engine.stop()
        self.wait_engine(engine)

    @reset_config
    def test_http_engine_002_startup_mode_client(self):
        saq.CONFIG['engine_http_scanner']['mode'] = MODE_CLIENT
        engine = self.create_engine(HTTPScanningEngine)
        self.start_engine(engine)

        wait_for_log_count('no streams available to send', 1, 5)

        engine.stop()
        self.wait_engine(engine)

    @reset_config
    def test_http_engine_003_scan_local_mode(self):
        self.disable_all_modules()
        engine = self.create_engine(HTTPScanningEngine)
        self.assertEquals(engine.mode, MODE_LOCAL)
        self.start_engine(engine)

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        wait_for_log_count('completed analysis RootAnalysis', 1, 5)

        # we should not have any files in the bro_http_dir
        self.assertEquals(len(os.listdir(self.bro_http_dir)), 0)

        engine.stop()
        self.wait_engine(engine)

    @reset_config
    def test_http_engine_004_client_mode(self):
        # first we create an ANP server on a different process so that we can change saq.SAQ_HOME
        # so that we can receive files relative to a different base directory
        # otherwise the COPY_FILE command will just over-write what it's sending
        import threading
        import multiprocessing

        global_control_event = multiprocessing.Event()

        def server_process_execute():
            # NOTE there's an assumption here that you don't have any other threads running that this would inherit
            # copy the ssl certs we need into the new "root" directory
            shutil.copytree(os.path.join(saq.SAQ_HOME, 'ssl'), os.path.join(self.temp_root_dir, 'ssl'))
            saq.SAQ_HOME = self.temp_root_dir

            control_event = threading.Event()

            def command_handler(anp, command):
                if command.command == ANP_COMMAND_EXIT:
                    control_event.set()

                return anp.send_message(ANPCommandOK())

            anp_server = ACENetworkProtocolServer(saq.CONFIG['engine_http_scanner'].get('anp_listening_address', 
                                                  saq.CONFIG['anp_defaults']['anp_listening_address']),
                                                  saq.CONFIG['engine_http_scanner'].getint('anp_listening_port', 
                                                  saq.CONFIG['anp_defaults'].getint('anp_listening_port')),
                                                  command_handler)

            anp_server.start()
            control_event.wait(10)
            anp_server.stop()

            global_control_event.set()
            os._exit(0)

        server_process = multiprocessing.Process(target=server_process_execute)
        server_process.start()
            
        saq.CONFIG['engine_http_scanner']['mode'] = MODE_CLIENT
        self.disable_all_modules()
        engine = self.create_engine(HTTPScanningEngine)
        self.start_engine(engine)

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        wait_for_log_count('received command copy_file', 4, 5)

        # wait for the files to show up under the new relative root system

        # var/test/anp_receive/var/bro/http_unittest/CC3W0d17FEploH7kci.1.request
        # var/test/anp_receive/var/bro/http_unittest/CC3W0d17FEploH7kci.1.reply.entity
        # var/test/anp_receive/var/bro/http_unittest/CC3W0d17FEploH7kci.1.ready
        # var/test/anp_receive/var/bro/http_unittest/CC3W0d17FEploH7kci.1.reply

        target_files = []
        for log_record in search_log('received command copy_file'):
            m = re.search(r'(C[^.]+\.\d\.(?:request|reply.entity|ready|reply))', log_record.getMessage())
            if m:
                target_files.append(m.group(1))

        self.assertEquals(len(target_files), 4)

        for file_name in target_files:
            src_path = os.path.join('var', 'bro', 'http_unittest', file_name)
            self.wait_for_condition(lambda: not os.path.exists(src_path))
            self.assertFalse(os.path.exists(src_path))
            dest_path = os.path.join(self.temp_root_dir, 'var', 'bro', 'http_unittest', file_name)
            self.wait_for_condition(lambda: os.path.exists(os.path.join(self.temp_root_dir, 
                                    'var', 'bro', 'http_unittest', file_name)))

        engine.stop()
        global_control_event.wait()

    @reset_config
    def test_http_engine_005_server_mode(self):
        saq.CONFIG['engine_http_scanner']['mode'] = MODE_SERVER
        self.disable_all_modules()
        engine = self.create_engine(HTTPScanningEngine)
        self.start_engine(engine)
        # make sure engine has started

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        client = anp_connect(saq.CONFIG['engine_http_scanner']['anp_listening_address'],
                             saq.CONFIG['engine_http_scanner'].getint('anp_listening_port'))

        client.send_message(ANPCommandAVAILABLE())
        result = client.recv_message()

        self.assertEquals(result.command, ANP_COMMAND_OK)

        stream_id = None
        target_files = []
        for file_name in os.listdir(os.path.join(self.bro_http_dir)):
            # grab the stream id
            m = re.search(r'^(C[^.]+\.\d)\..*', file_name)
            if m:
                stream_id = m.group(1)
            else:
                continue

            source_path = os.path.join(self.bro_http_dir, file_name)
            dest_path = os.path.join(saq.CONFIG['engine_http_scanner']['bro_http_dir'], file_name)
            target_files.append(dest_path)
            client.send_message(ANPCommandCOPY_FILE(dest_path, source_path))
            result = client.recv_message()
            self.assertEquals(result.command, ANP_COMMAND_OK)

        client.send_message(ANPCommandPROCESS(stream_id))
        result = client.recv_message()
        self.assertEquals(result.command, ANP_COMMAND_OK)
        
        client.send_message(ANPCommandEXIT())

        wait_for_log_count('executing post analysis on RootAnalysis', 1, 5)
        for path in target_files:
            self.wait_for_condition(lambda: not os.path.exists(path))
        
        engine.stop()

    @reset_config
    def test_http_engine_006_server_mode_alert(self):
        saq.CONFIG['engine_http_scanner']['mode'] = MODE_SERVER
        saq.FORCED_ALERTS = True
        self.disable_all_modules()

        alert_fired = multiprocessing.Event()

        class _custom_engine(HTTPScanningEngine):
            def post_analysis(self2, root):
                if self2.should_alert(root):
                    #root.submit()
                    alert_fired.set()
                    self2.cancel_analysis()
                else:
                    # any outstanding analysis left?
                    if root.delayed:
                        logging.debug("{} has delayed analysis -- waiting for cleanup...".format(root))
                        return

        engine = self.create_engine(_custom_engine)
        self.start_engine(engine)
        # make sure engine has started

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        client = anp_connect(saq.CONFIG['engine_http_scanner']['anp_listening_address'],
                             saq.CONFIG['engine_http_scanner'].getint('anp_listening_port'))

        client.send_message(ANPCommandAVAILABLE())
        result = client.recv_message()

        self.assertEquals(result.command, ANP_COMMAND_OK)

        stream_id = None
        target_files = []
        for file_name in os.listdir(os.path.join(self.bro_http_dir)):
            # grab the stream id
            m = re.search(r'^(C[^.]+\.\d)\..*', file_name)
            if m:
                stream_id = m.group(1)
            else:
                continue

            source_path = os.path.join(self.bro_http_dir, file_name)
            dest_path = os.path.join(saq.CONFIG['engine_http_scanner']['bro_http_dir'], file_name)
            target_files.append(dest_path)
            client.send_message(ANPCommandCOPY_FILE(dest_path, source_path))
            result = client.recv_message()
            self.assertEquals(result.command, ANP_COMMAND_OK)

        client.send_message(ANPCommandPROCESS(stream_id))
        result = client.recv_message()
        self.assertEquals(result.command, ANP_COMMAND_OK)
        
        client.send_message(ANPCommandEXIT())

        wait_for_log_count('executing post analysis on RootAnalysis', 1, 5)
        for path in target_files:
            self.wait_for_condition(lambda: not os.path.exists(path))

        # make sure the alert fired
        self.assertTrue(alert_fired.wait(5))
        
        engine.stop()
        saq.FORCED_ALERTS = False

    @reset_config
    def test_http_engine_007_whitelisted_fqdn(self):
        self.disable_all_modules()
        
        saq.CONFIG['engine_http_scanner']['whitelist_path'] = os.path.join('var', 'tmp', 'brotex.whitelist')
        with open(os.path.join(saq.SAQ_HOME, 'var', 'tmp', 'brotex.whitelist'), 'w') as fp:
            fp.write('http_host:www.pdf995.com\n')
        
        engine = self.create_engine(HTTPScanningEngine)
        self.assertEquals(engine.mode, MODE_LOCAL)
        self.start_engine(engine)

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        #wait_for_log_count('completed analysis RootAnalysis', 1, 5)
        wait_for_log_count('whitelisted by fqdn', 1, 5)

        # we should not have any files in the bro_http_dir
        self.assertEquals(len(os.listdir(self.bro_http_dir)), 0)

        engine.stop()
        self.wait_engine(engine)

        os.remove(os.path.join(saq.SAQ_HOME, 'var', 'tmp', 'brotex.whitelist'))
