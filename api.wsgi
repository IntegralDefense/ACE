#!/usr/bin/env python
import os
import os.path
import sys
import logging

# apache env vars and wsgi are different
# so we use the location of this saq.wsgi file as the root of ACE
# which is what SAQ_HOME would be pointing to
os.environ['SAQ_HOME'] = os.path.dirname(os.path.realpath(__file__))
saq_home = os.environ['SAQ_HOME']
#sys.stderr.write("\n\nsaq_home = {}\n\n".format(saq_home))

# additional config files are stored in SAQ_CONFIG_PATHS env var which are
# loaded from load_local_environment bash script sourced by load_environment
path = os.path.join(saq_home, 'load_local_environment')
if os.path.exists(path):
    # we execute a shell and source the script then output the value and capture the output
    from subprocess import Popen, PIPE
    p = Popen(['/bin/bash', '-c', 'source {} && echo $SAQ_CONFIG_PATHS'.format(path)], stdout=PIPE, universal_newlines=True)
    _stdout, _stderr = p.communicate()
    os.environ['SAQ_CONFIG_PATHS'] = _stdout.strip()

# adjust search path
sys.path.append(os.path.join(saq_home, 'lib'))
sys.path.append(os.path.join(saq_home))

# if no logging is specified then how we log depends on what mode we're in
logging_config_path = os.path.join(saq_home, 'etc', 'api_logging.ini')

# initialize saq
# note that config paths are determined by the env vars we dug out above
import saq
saq.initialize(saq_home=saq_home, config_paths=None, logging_config_path=logging_config_path, relative_dir=saq_home, use_flask=True)

# initialize flask
from api import create_app
application = create_app()
