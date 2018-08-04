# vim: sw=4:ts=4:et:cc=120
#
# base functionality for all sandbox-type of analysis
#

import logging

import saq
from saq.constants import *
from saq.modules import AnalysisModule

class SandboxAnalysisModule(AnalysisModule):

    @property
    def supported_extensions(self):
        if 'supported_extensions' in self.config:
            return map(lambda x: x.strip().lower(), self.config['supported_extensions'].split(','))
        return []

    @property
    def use_proxy(self):
        """Returns True if this sandbox is configured to use the proxy, False otherwise.  Defaults to True."""
        if 'use_proxy' in self.config:
            return self.config.getboolean('use_proxy')
    
        return True

    @property
    def proxies(self):
        if not self.use_proxy:
            return {}

        return {
            'http': saq.CONFIG['proxy']['http'],
            'https': saq.CONFIG['proxy']['https'],
        }

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_SANDBOX ]

    def is_sandboxable_file(self, file_path):
        """Returns True if the given file should be sent to a sandbox, False otherwise."""
        # does this file have a supported file extension?
        file_extension = None
        try:
            file_extension = file_path.rsplit('.', 1)[-1]
        except IndexError:
            pass

        if file_extension in self.supported_extensions:
            return True
            logging.debug("{} is a supported file extension".format(file_extension))

        # do some magic analysis to see if it's an important file type
        with open(file_path, 'rb') as fp:
            mz_header_check = fp.read(2)
            if mz_header_check == b'MZ':
                logging.debug("found MZ header in {}".format(file_path))
                return True

            fp.seek(0)
            ole_header_check = fp.read(8)
            if ole_header_check == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                logging.debug("found OLE header in {}".format(file_path))
                return True

            fp.seek(0)
            pdf_header_check = fp.read(1024)
            if b'%PDF' in pdf_header_check:
                logging.debug("found PDF header in {}".format(file_path))
                return True

            fp.seek(0)
            rtf_header_check = fp.read(4)
            if rtf_header_check == b'{\\rt':
                logging.debug("found RTF header in {}".format(file_path))
                return True

        logging.debug("{} is not a supported file type for vx analysis".format(file_path))
        return False
