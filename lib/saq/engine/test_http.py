# vim: sw=4:ts=4:et

import os
import os.path
import shutil
import tempfile
import logging

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

        anp_interface = engine.config['anp_listening_address']
        anp_port = engine.config['anp_listening_port']

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
            saq.SAQ_HOME = os.path.join(saq.SAQ_HOME, 'var', 'test', 'anp_receive')
            if not os.path.exists(saq.SAQ_HOME):
                os.makedirs(saq.SAQ_HOME)

            control_event = threading.Event()

            def command_handler(anp, command):
                if command.command == ANP_COMMAND_EXIT:
                    control_event.set()

                return anp.send_message(ANPCommandOK())

            logging.info("MARKER: 1 {}".format(saq.SAQ_HOME))
            anp_server = ACENetworkProtocolServer(saq.CONFIG['engine_http_scanner']['anp_listening_address'],
                                                  saq.CONFIG['engine_http_scanner'].getint('anp_listening_port'),
                                                  command_handler)

            anp_server.start()
            control_event.wait(10)
            anp_server.stop()

            global_control_event.set()
            logging.info("MARKER: done!")
            os._exit(0)

        server_process = multiprocessing.Process(target=server_process_execute)
        server_process.start()
            
        saq.CONFIG['engine_http_scanner']['mode'] = MODE_CLIENT
        self.disable_all_modules()
        engine = self.create_engine(HTTPScanningEngine)
        self.start_engine(engine)

        self.process_pcap(os.path.join(saq.SAQ_HOME, 'test_data', 'pcaps', 'http_download_pdf.pcap'))

        wait_for_log_count('sending stream', 1, 5)

        # wait for the files to show up under the new relative root system

        engine.stop()
        global_control_event.wait()
