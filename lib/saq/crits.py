# vim: sw=4:ts=4:et
#
# utility functions and constants for CRITS support

import json
import logging

import saq
from saq.constants import *
from saq.intel import *

import requests

# mongodb imports
from bson import json_util
from bson.objectid import ObjectId
from pymongo import MongoClient

indicator_type_mapping = None
observable_type_mapping = None

def load_indicator_type_mapping():
    global indicator_type_mapping
    if indicator_type_mapping is None:
        indicator_type_mapping = {}
        for k in saq.CONFIG['crits_indicator_type_mapping'].keys():
            indicator_type_mapping[k] = saq.CONFIG['crits_indicator_type_mapping'][k]

def get_indicator_type_mapping(indicator_type):
    load_indicator_type_mapping()
    try:
        # return the internal CRITS indicator type for the given default type
        return indicator_type_mapping[indicator_type]
    except KeyError:
        # or just return the indicator type if it's not a default type
        return indicator_type

def load_observable_type_mapping():
    global observable_type_mapping
    if observable_type_mapping is None:
        observable_type_mapping = {}
        for k in saq.CONFIG['crits_observable_type_mappping'].keys():
            observable_type_mapping[k] = saq.CONFIG['crits_observable_type_mappping'][k]

def get_observables_by_type_mapping(indicator_type):
    return observable_type_mapping[indicator_type] 

#CRITS_TYPE_MAPPING = {
    #F_IPV4 : 'Address - ipv4-addr',
    #F_IPV4_CONVERSATION : None,
    #F_FQDN : 'URI - Domain Name',
    #F_HOSTNAME : None,
    #F_ASSET : None,
    #F_USER : None,
    #F_URL : 'URI - URL',
    #F_PCAP : None,
    #F_FILE : None,
    #F_SUSPECT_FILE : None,
    #F_FILE_PATH : 'Windows - FilePath',
    #F_FILE_NAME : 'Windows - FileName',
    #F_EMAIL_ADDRESS : 'Email - Address',
    #F_YARA : None,
    #F_YARA_RULE : None,
    #F_INDICATOR : None,
    #F_MD5 : 'Hash - MD5',
    #F_SHA1 : 'Hash - SHA1',
    #F_SHA256 : 'Hash - SHA256',
    #F_SNORT_SIGNATURE : None 
#}

def submit_indicator(observable):
    """Add the given Observable as an indicator to CRITS.  Returns the CRITS id or None if the operation fails."""
    load_mappings()
    if not CRITS_INDICATOR_TYPE_MAPPING[observable.type]:
        logging.debug("{} is not a supported type for crits".format(observable))
        return None

    data = {
        'api_key' : saq.CONFIG['crits']['api_key'],
        'username' : saq.CONFIG['crits']['username'],
        'source' : saq.CONFIG['global']['company_name'],
        'reference' : 'https://{}:{}/analysis?direct={}'.format(saq.CONFIG['gui']['listen_address'], saq.CONFIG['gui']['listen_port'], observable.alert.uuid),
        'method' : None,
        'add_domain' : True,
        'add_relationship' : True,
        'indicator_confidence' : 'low',
        'indicator_impact' : 'low',
        'type' : CRITS_OBSERVABLE_TYPE_MAPPING[observable.type],
        'value' : observable.value
    }

    result = requests.post("{}/api/v1/indicators/".format(saq.CONFIG['crits']['url']), data=data, verify=False)
    if result.status_code != 200:
        logging.error("got status code {} from crits for {}".format(result.status_code, observable))
        return None

    try:
        logging.debug(result.text)
        result = json.loads(result.text)
        return result['id']
    except Exception as e:
        logging.error("got a non or unexpected json result back from crits for {}: {}".format(observable, str(e)))
        return None

def update_status(crits_id, status):
    assert isinstance(crits_id, str)
    assert status in [ 'Informational', 'Analyzed' ]

    # API support for changing the status message was not implemented at the time I wrote this
    # download the crits indicator JSON directly from the crits mongo database
    client = MongoClient(saq.CONFIG['crits']['mongodb_uri'])
    db = client['crits']
    collection = db['indicators']

    logging.debug("updating status of {} to {}".format(crits_id, status))
    result = collection.update({'_id': ObjectId(crits_id)}, {'$set': {'status': status}})
    # this actually isn't an error, it does not update if the value is the same as previous
    #if result['nModified'] != 1:
        #logging.error("unable to update crits indicator {}: update count = {}".format(crits_id, reuslt['nModified']))

    return result['nModified']

def sync_crits_activity(alert):
    """Syncs the disposition to the indicators in the given Alert in the crits database."""
    from saq.database import Alert
    assert isinstance(alert, Alert)

    alert.load()
    crits_ids = {}

    # return if there are no indicator observables in this alert
    if F_INDICATOR not in alert.observable_types:
        return

    for indobs in alert.get_observables_by_type("indicator"):
        for x in indobs.json:
            crits_ids[indobs.json['value']] = indobs

    import requests
    requests.packages.urllib3.disable_warnings()

    baseurl = saq.CONFIG.get('crits', 'url')
    api_key = saq.CONFIG.get('crits', 'api_key')
    activity_url = saq.CONFIG.get('crits','activity_url')
    indicators_endpoint = saq.CONFIG.get('crits','indicators_endpoint')
    user = saq.CONFIG.get('crits','username')


    # for each unique crits object id found in the observables
    for crits_id in crits_ids:

        description = {'uuid':alert.uuid,
                       'disposition':alert.disposition,
                       'type':alert.alert_type,
                       'storage_dir':alert.storage_dir,
                       'disposition_user':str(alert.disposition_user)
                      }

        activity = {'start_date':  alert.insert_date.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'end_date':    alert.disposition_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'description': json.dumps(description, sort_keys=True),
                    'analyst':     user,
                    'date':        alert.insert_date.strftime('%Y-%m-%d %H:%M:%S.%f')
                   }
       
        headers = {'Content-Type' : 'application/json'}

        headers = {'Content-Type' : 'application/json'}

        params = { 'api_key':     api_key,
                   'username':    user
                   }

        data = { 'action':      'activity_add',
                 'activity':    activity
               }

        #verify this activity does not already exist in the indicator, if yes just return without doing anything
        url = baseurl +  indicators_endpoint + crits_id + "?username=" + user + "&api_key=" + api_key
        getdata = {'username':user, 'api_key':api_key}
        r = requests.get(url , data=getdata, verify=False)

        if r.status_code == 200 or r.status_code == 201:
            existing_activity = r.json()['activity']
            for act_item in existing_activity:
                if (act_item['description'] == json.dumps(description, sort_keys=True)):
                    logging.debug("Activity already exists for {}".format(crits_id))
                    return
        else:
            logging.warning("unable to query activity for crits object: {} , status code: {}".format(crits_id, str(r.status_code)))

        # add unique activity
        r = requests.patch(activity_url + crits_id+"/",headers=headers,params=params,data=json.dumps(data),verify=False)
        if r.status_code == 200 or r.status_code == 201:
            logging.info("added activity to {} for alert {}, {}, {}".format(crits_id, alert.uuid, data, r))
        else:
            logging.error("activity not added to {} for alert {}, status {}".format(crits_id, alert.uuid, str(r.status_code)))
            logging.error("     : {}{}{}".format(activity_url,crits_id, data))
