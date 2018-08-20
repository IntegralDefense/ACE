# vim: sw=4:ts=4:et
# configuration settings for the GUI

import saq

class Config(object):
    import sys; sys.stderr.write('\n\nEDIT YOUR SECRET KEY\nopen config.py and remove this line and set the SECRET_KEY value to something\n\n'); sys.exit(1)
    SECRET_KEY = ''
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    INSTANCE_NAME = saq.CONFIG.get('global', 'instance_name')

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
    'DEV': DevelopmentConfig,
    'QA': ProductionConfig,
    'PRODUCTION': ProductionConfig,
}
