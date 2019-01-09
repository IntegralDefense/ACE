# vim: sw=4:ts=4:et
# configuration settings for the GUI

import saq

class Config(object):
    SECRET_KEY = saq.CONFIG['gui']['secret_key']
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    INSTANCE_NAME = saq.CONFIG.get('global', 'instance_name')

    GUI_DISPLAY_METRICS = saq.CONFIG['gui'].getboolean('display_metrics')
    GUI_DISPLAY_EVENTS = saq.CONFIG['gui'].getboolean('display_events')

    # also see lib/saq/database.py:initialize_database
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}/{database}?charset=utf8'.format(
        username=saq.CONFIG.get('database_ace', 'username'),
        password=saq.CONFIG.get('database_ace', 'password'),
        hostname=saq.CONFIG.get('database_ace', 'hostname'),
        database=saq.CONFIG.get('database_ace', 'database'))

    SQLALCHEMY_POOL_TIMEOUT = 10
    SQLALCHEMY_POOL_RECYCLE = 60

    # gets passed as **kwargs to create_engine call of SQLAlchemy
    # this is used by the non-flask applications to configure SQLAlchemy db connection
    SQLALCHEMY_DATABASE_OPTIONS = { 
        'pool_recycle': 60,
        'pool_size': 5,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # are we using SSL for MySQL connections? (you should be)
        if 'ssl_ca' in saq.CONFIG['database_ace'] \
        or 'ssl_cert' in saq.CONFIG['database_ace'] \
        or 'ssl_key' in saq.CONFIG['database_ace']:
            ssl_options = { 'ca': saq.CONFIG['database_ace']['ssl_ca'] }
            if 'ssl_cert' in saq.CONFIG['database_ace']:
                ssl_options['cert'] = saq.CONFIG['database_ace']['ssl_cert']
            if 'ssl_key' in saq.CONFIG['database_ace']:
                ssl_options['key'] = saq.CONFIG['database_ace']['ssl_key']

            self.SQLALCHEMY_DATABASE_OPTIONS['connect_args'] = {}
            self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['ssl'] = ssl_options

    @staticmethod
    def init_app(app):
        pass

class ProductionConfig(Config):
    
    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False

class DevelopmentConfig(Config):

    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True

# the keys for this dict match the instance_type config setting in global section of etc/saq.ini
config = {
    'DEV': DevelopmentConfig(),
    'QA': ProductionConfig(),
    'PRODUCTION': ProductionConfig(),
}
