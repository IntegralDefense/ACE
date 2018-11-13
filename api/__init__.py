# vim: sw=4:ts=4:et

import json
import logging
import time

import saq
from saq.analysis import _JSONEncoder

from flask import Flask, make_response, abort, Response, request
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import event
from sqlalchemy.engine import Engine

#@event.listens_for(Engine, "before_cursor_execute")
#def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    #if saq.CONFIG['global'].getboolean('log_sql_exec_times'):
        #context._query_start_time = time.time()
        #logging.info("START QUERY {} ({})".format(statement, parameters))
    # Modification for StackOverflow answer:
    # Show parameters, which might be too verbose, depending on usage..
    #logging.debug("Parameters:\n%r" % (parameters,))

#@event.listens_for(Engine, "after_cursor_execute")
#def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    #if saq.CONFIG['global'].getboolean('log_sql_exec_times'):
        #total = time.time() - context._query_start_time
        #logging.info("END QUERY {:02f} {} ({})".format(total * 1000, statement, parameters))

    # Modification for StackOverflow: times in milliseconds
    #logger.debug("Total Time: %.02fms" % (total*1000))

#login_manager = LoginManager()
#login_manager.session_protection = 'strong'
#login_manager.login_view = 'auth.login'

# we need to subclass this thing so that we can disable connection pooling
# connection pooling is broken for MySQL (see lib/saq/database.py)
class CustomSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, app, info, options):
        SQLAlchemy.apply_driver_hacks(self, app, info, options)
        options['pool_recycle'] = 60 # return these after a minute

db = CustomSQLAlchemy()

def create_app(testing=False):
    class _config(object):
        SECRET_KEY = saq.CONFIG['api']['secret_key']
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

    class _test_config(_config):
        TESTING = True

    app = Flask(__name__)
    app.config.from_object(_test_config if testing else _config)

    #login_manager.init_app(app)
    db.init_app(app)

    from .common import common as common_blueprint
    app.register_blueprint(common_blueprint)

    from .analysis import analysis_bp as analysis_blueprint
    app.register_blueprint(analysis_blueprint)

    from .engine import engine_bp as engine_blueprint
    app.register_blueprint(engine_blueprint)

    return app

def json_request():
    if not request.json:
        abort(Response("Request must be in JSON format as dict.", 400))

    if not isinstance(request.json, dict):
        abort(Response("Request must be in JSON format as dict.", 400))

    return request.json
    
def json_result(data):
    response = make_response(json.dumps(data, cls=_JSONEncoder, sort_keys=True))
    response.mimetype = 'application/json'
    return response
