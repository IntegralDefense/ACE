# vim: sw=4:ts=4:et:cc=120

import logging
import os.path
import shutil
import tempfile

from subprocess import Popen

import saq
from saq.collectors.test import CollectorBaseTestCase

class BroBaseTestCase(CollectorBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        self.bro_work_dir = tempfile.mkdtemp(dir=os.path.join(saq.TEMP_DIR))

        os.mkdir(os.path.join(self.bro_work_dir, 'ace'))
        with open(os.path.join(self.bro_work_dir, 'ace', 'ace_local.bro'), 'w') as fp:
            Popen(['sed', '-e', 's:data/var:data_unittest/var:', 
                  os.path.join(saq.SAQ_HOME, 'bro', 'ace_local.example.bro')], stdout=fp).wait()

        shutil.copy(os.path.join(saq.SAQ_HOME, 'bro', 'ace_http.bro'), os.path.join(self.bro_work_dir, 'ace', 'ace_http.bro'))
        shutil.copy(os.path.join(saq.SAQ_HOME, 'bro', 'ace_smtp.bro'), os.path.join(self.bro_work_dir, 'ace', 'ace_smtp.bro'))
        self.bro_bin_path = '/opt/bro/bin/bro'

    def tearDown(self, *args, **kwargs):
        super().tearDown(*args, **kwargs)

        if os.path.isdir(self.bro_work_dir):
            shutil.rmtree(self.bro_work_dir)

        #logging.info("MARKER: {}".format(self.bro_work_dir))

    def process_pcap(self, pcap_path):
        # have bro process this pcap file of a download of a PDF file
        logging.debug("processing pcap...")
        Popen([self.bro_bin_path, '-C', '-r', pcap_path, os.path.join('ace', 'ace_http.bro'), os.path.join('ace', 'ace_smtp.bro')], cwd=self.bro_work_dir).wait()
