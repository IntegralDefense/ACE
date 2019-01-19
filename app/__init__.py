# vim: sw=4:ts=4:et

import logging
import time

import saq

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
#from flask.ext.moment import Moment
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from config import config

import sqlalchemy.pool

from sqlalchemy import event
from sqlalchemy.engine import Engine

@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if saq.CONFIG['global'].getboolean('log_sql_exec_times'):
        context._query_start_time = time.time()
        logging.info("START QUERY {} ({})".format(statement, parameters))
    # Modification for StackOverflow answer:
    # Show parameters, which might be too verbose, depending on usage..
    #logging.debug("Parameters:\n%r" % (parameters,))

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if saq.CONFIG['global'].getboolean('log_sql_exec_times'):
        total = time.time() - context._query_start_time
        logging.info("END QUERY {:02f} {} ({})".format(total * 1000, statement, parameters))

    # Modification for StackOverflow: times in milliseconds
    #logger.debug("Total Time: %.02fms" % (total*1000))

bootstrap = Bootstrap()
#moment = Moment()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

class CustomSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, app, info, options):
        # add SSL (if configured)
        options.update(config[saq.CONFIG['global']['instance_type']].SQLALCHEMY_DATABASE_OPTIONS)
        SQLAlchemy.apply_driver_hacks(self, app, info, options)

db = CustomSQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(config[saq.CONFIG['global']['instance_type']])
    config[saq.CONFIG['global']['instance_type']].init_app(app)

    bootstrap.init_app(app)
    #moment.init_app(app)
    login_manager.init_app(app)
    db.init_app(app)
    
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .analysis import analysis as analysis_blueprint
    app.register_blueprint(analysis_blueprint)
    
    #from .cloudphish import cloudphish as cloudphish_blueprint
    #app.register_blueprint(cloudphish_blueprint)

    from .vt_hash_cache import vt_hash_cache_bp as vt_hash_cache_blueprint
    app.register_blueprint(vt_hash_cache_blueprint)

    return app
