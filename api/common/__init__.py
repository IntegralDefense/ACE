# vim: sw=4:ts=4:et
#
# ACE API common routines

import json

from .. import db, json_result

from saq.constants import *
from saq.database import Company

from flask import Blueprint
common = Blueprint('common', __name__, url_prefix='/common')

@common.route('/ping', methods=['GET'])
def ping():
    return json_result({'result': 'pong'})

@common.route('/get_supported_api_version', methods=['GET'])
def get_supported_api_version():
    return json_result({'result': 1})

@common.route('/get_valid_companies', methods=['GET'])
def get_valid_companies():
    result = []
    for company in db.session.query(Company):
        result.append(company.json)

    return json_result({'result': result})
    
@common.route('/get_valid_observables', methods=['GET'])
def get_valid_observables():
    result = []
    for o_type in VALID_OBSERVABLE_TYPES:
        result.append({'name': o_type, 'description': OBSERVABLE_DESCRIPTIONS[o_type]})

    return json_result({'result': result})
