import datetime
import importlib
import io
import json
import logging
import math
import os
import os.path
import pymysql
import random
import re
import shutil
import smtplib
import socket
import traceback
import uuid
import zipfile

from collections import defaultdict
from datetime import timedelta
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from operator import attrgetter
from subprocess import Popen, PIPE, DEVNULL

import businesstime
import pandas as pd
import requests
from pymongo import MongoClient

import saq
import virustotal
import vxstreamlib
import splunklib

from saq import SAQ_HOME
from saq.constants import *
from saq.crits import update_status
from saq.analysis import Tag
from saq.database import User, UserAlertMetrics, Comment, get_db_connection, Event, EventMapping, \
                         ObservableMapping, Observable, Tag, TagMapping, EngineWorkload, Malware, \
                         MalwareMapping, Company, CompanyMapping, Campaign, Alert, \
                         ProfilePointAlertMapping, ProfilePoint, ProfilePointTagMapping
from saq.email import search_archive, get_email_archive_sections
from saq.error import report_exception
from saq.gui import GUIAlert
from saq.performance import record_execution_time
from saq.network_client import submit_alerts

from app import db
from app.analysis import *
from flask import jsonify, render_template, redirect, request, url_for, flash, session, \
                  make_response, g, send_from_directory, send_file
from flask_login import login_user, logout_user, login_required, current_user

from sqlalchemy import and_, or_, func, distinct
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import text, func

# used to determine where to redirect to after doing something
REDIRECT_MAP = {
    'analysis': 'analysis.index',
    'management': 'analysis.manage'
}

# controls if we prune analysis by default or not
DEFAULT_PRUNE = True

# additional functions to make available to the templates
@analysis.context_processor
def generic_functions():
    def generate_unique_reference():
        return str(uuid.uuid4())

    return { 'generate_unique_reference': generate_unique_reference }

# utility routines

def get_profile_point_counts():
    """Returns a dict mapping of profile point tag to total counts."""
    # first figure out the total count for each tag
    # there really shouldn't be that many tags so we can safely store them all in memory
    result = {} # key = tag_name, value = count
    for tag_name, count in db.session.query(Tag.name, func.count('*')).\
                         join(ProfilePointTagMapping).\
                         join(ProfilePoint).\
                         group_by(Tag.name):

        result[tag_name] = count

    return result

def get_current_alert_uuid():
    """Returns the current alert UUID the analyst is looking at, or None if they are not looking at anything."""
    target_dict = request.form if request.method == 'POST' else request.args

    # either direct or alert_uuid are used
    if 'direct' in target_dict:
        return target_dict['direct']
    elif 'alert_uuid' in target_dict:
        return target_dict['alert_uuid']

    logging.debug("missing direct or alert_uuid in get_current_alert for user {0}".format(current_user))
    return None

def get_current_alert():
    """Returns the current Alert for this analysis page, or None if the uuid is invalid."""
    alert_uuid = get_current_alert_uuid()
    if alert_uuid is None:
        return None

    try:
        return db.session.query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
    except:
        pass

    return None

def filter_special_tags(tags):
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] == 'special']
    return [tag for tag in tags if tag.name not in special_tag_names]

@analysis.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

@analysis.route('/json', methods=['GET'])
@login_required
def download_json():
    result = {}

    alert = get_current_alert()
    if alert is None:
        return '{}'

    try:
        alert.load()
    except Exception as e:
        logging.error("unable to load alert uuid {0}: {1}".format(request.args['uuid'], str(e)))
        return '{}'

    nodes = []
    next_node_id = 1
    for analysis in alert.all_analysis:
        analysis.node_id = 0 if analysis is alert else next_node_id
        next_node_id += 1
        node = {
            'id': analysis.node_id,
            # yellow if it's the alert otherwise white for analysis nodes
            'color': '#FFFF00' if analysis is alert else '#FFFFFF',
            # there is a bug in the library preventing this from working
            # 'fixed': True if analysis is alert else False,
            # 'physics': False if analysis is alert else True,
            'hidden': False,  # TODO try to hide the ones that didn't have any analysis
            'shape': 'box',
            'label': type(analysis).__name__,
            'details': type(analysis).__name__ if analysis.jinja_template_path is None else analysis.jinja_display_name,
            'observable_uuid': None if analysis.observable is None else analysis.observable.id,
            'module_path': analysis.module_path}

        # if analysis.jinja_template_path is not None:
        # node['details'] = analysis.jinja_display_name

        nodes.append(node)

    for observable in alert.all_observables:
        observable.node_id = next_node_id
        next_node_id += 1
        nodes.append({
            'id': observable.node_id,
            'color': OBSERVABLE_NODE_COLORS[observable.type],
            'label': observable.type,
            'details': str(observable)})

    edges = []
    for analysis in alert.all_analysis:
        for observable in analysis.observables:
            edges.append({
                'from': analysis.node_id,
                'to': observable.node_id,
                'hidden': False})
            for observable_analysis in observable.all_analysis:
                edges.append({
                    'from': observable.node_id,
                    'to': observable_analysis.node_id,
                    'hidden': False})

    tag_nodes = {}  # key = str(tag), value = {} (tag node)
    tag_edges = []

    tagged_objects = alert.all_analysis
    tagged_objects.extend(alert.all_observables)

    for tagged_object in tagged_objects:
        for tag in tagged_object.tags:
            if str(tag) not in tag_nodes:
                next_node_id += 1
                tag_node = {
                    'id': next_node_id,
                    'color': '#FFFFFF',
                    'shape': 'star',
                    'label': str(tag)}

                tag_nodes[str(tag)] = tag_node

            tag_node = tag_nodes[str(tag)]
            tag_edges.append({'from': tagged_object.node_id, 'to': tag_node['id']})

    nodes.extend(tag_nodes.values())
    edges.extend(tag_edges)

    response = make_response(json.dumps({'nodes': nodes, 'edges': edges}))
    response.mime_type = 'application/json'
    return response

@analysis.route('/redirect_to', methods=['GET', "POST"])
@login_required
def redirect_to():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    try:
        file_uuid = request.values['file_uuid']
    except KeyError:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    try:
        target = request.values['target']
    except KeyError:
        logging.error("missing target")
        return "missing target", 500

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # both of these requests require the sha256 hash
    # as on 12/23/2015 the FileObservable stores these hashes as a part of the observable
    # so we use that if it exists, otherwise we compute it on-the-fly
    if file_observable.sha256_hash is None:
        if not file_observable.compute_hashes():
            flash("unable to compute file hash of {}".format(file_observable.value))
            return redirect(url_for('analysis.index'))

    if target == 'vt':
        return redirect('https://www.virustotal.com/en/file/{}/analysis/'.format(file_observable.sha256_hash))
    elif target == 'vx':
        return redirect('{}/sample/{}?environmentId={}'.format(
            saq.CONFIG['vxstream']['gui_baseuri'],
            file_observable.sha256_hash,
            saq.CONFIG['vxstream']['environmentid']))

    flash("invalid target {}".format(target))
    return redirect(url_for('analysis.index'))

@analysis.route('/email_file', methods=["POST"])
@login_required
def email_file():
    toemails = request.form.get('toemail', "").split(";")
    compress = request.form.get('compress', 'off')
    encrypt = request.form.get('encrypt', 'off')
    file_uuid = request.form.get('file_uuid', "")
    emailmessage = request.form.get("emailmessage", "")

    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    subject = request.form.get("subject", "ACE file attached from {}".format(alert.description))

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
                file_uuid, alert, current_user))
        flash("internal error")
        return redirect("/analysis?direct=" + alert.uuid)

    # get the full path to the file to expose
    full_path = os.path.join(SAQ_HOME, alert.storage_dir, file_observable.value)
    if not os.path.exists(full_path):
        logging.error("file path {0} does not exist for alert {1} user {2}".format(full_path, alert, current_user))
        flash("internal error")
        return redirect("/analysis?direct=" + alert.uuid)
    if compress == "on":
        if not os.path.exists(full_path + ".zip"):
            try:
                zf = zipfile.ZipFile(full_path + ".zip",
                                     mode='w',
                                     compression=zipfile.ZIP_DEFLATED,
                                     )
                with open(full_path, "rb") as fp:
                    msg = fp.read()
                try:
                    zf.writestr(os.path.basename(full_path), msg)
                finally:
                    zf.close()
            except Exceptoin as e:
                logging.error("Could not compress " + full_path + ': ' + str(e))
                report_exception()
                flash("internal error compressing " + full_path)
                return redirect("/analysis?direct=" + alert.uuid)

        full_path += ".zip"

    if encrypt == "on":
        try:
            passphrase = saq.CONFIG.get("gpg", "symmetric_password")
        except:
            logging.warning("passphrase not specified in configuration, using default value of infected")
            passphrase = "infected"

        if not os.path.exists(full_path + ".gpg"):
            p = Popen(['gpg', '-c', '--passphrase', passphrase, full_path], stdout=PIPE)
            (stdout, stderr) = p.communicate()

        full_path += ".gpg"

    try:
        smtphost = saq.CONFIG.get("smtp", "server")
        smtpfrom = saq.CONFIG.get("smtp", "mail_from")
        msg = MIMEMultipart()
        msg['From'] = smtpfrom
        msg['To'] = COMMASPACE.join(toemails)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        msg.attach(MIMEText(emailmessage))
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(full_path, "rb").read())
        encode_base64(part)
        #part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(full_path))
        part.add_header('Content-Disposition', os.path.basename(full_path))
        msg.attach(part)
        smtp = smtplib.SMTP(smtphost)
        smtp.sendmail(smtpfrom, toemails, msg.as_string())
        smtp.close()
    except Exception as e:
        logging.error("unable to send email: {}".format(str(e)))
        report_exception()

    return redirect("/analysis?direct=" + alert.uuid)

@analysis.route('/download_file', methods=['GET', "POST"])
@login_required
def download_file():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    if request.method == "POST":
        file_uuid = request.form['file_uuid']
    else:
        file_uuid = request.args.get('file_uuid', None)

    if file_uuid is None:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    if request.method == "POST":
        mode = request.form['mode']
    else:
        mode = request.args.get('mode', None)

    if mode is None:
        logging.error("missing mode")
        return "missing mode", 500

    response = make_response()

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # get the full path to the file to expose
    full_path = os.path.join(SAQ_HOME, alert.storage_dir, file_observable.value)
    if not os.path.exists(full_path):
        logging.error("file path {0} does not exist for alert {1} user {2}".format(full_path, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if request.method == "POST" and mode == "vxstream":
        baseuri = saq.CONFIG.get("vxstream", "baseuri")
        gui_baseuri = saq.CONFIG.get('vxstream', 'gui_baseuri')
        if baseuri[-1] == "/":
            baseuri = baseuri[:-1]
        environmentid = saq.CONFIG.get("vxstream", "environmentid")
        apikey = saq.CONFIG.get("vxstream", "apikey")
        secret = saq.CONFIG.get("vxstream", "secret")
        server = vxstreamlib.VxStreamServer(baseuri, apikey, secret)
        submission = server.submit(full_path, environmentid)
        
        url = gui_baseuri + "/sample/" + submission.sha256 + "?environmentId=" + environmentid
        return url

    if request.method == "POST" and mode == "virustotal":
        apikey = saq.CONFIG.get("virus_total","api_key")
        vt = virustotal.VirusTotal(apikey)
        res = vt.send_file(full_path)
        if res:
            logging.debug("VT result for {}: {}".format(full_path, str(res)))
            return res['permalink']
        return "", 404

    if mode == 'raw':
        return send_from_directory(os.path.dirname(full_path), 
                                   os.path.basename(full_path), 
                                   as_attachment=True,
                                   attachment_filename=os.path.basename(full_path).encode().decode('latin-1', errors='ignore'))
    elif mode == 'hex':
        p = Popen(['hexdump', '-C', full_path], stdout=PIPE)
        (stdout, stderr) = p.communicate()
        response = make_response(stdout)
        response.headers['Content-Type'] = 'text/plain'
        return response
    elif mode == 'zip':
        try:
            dest_file = '{}.zip'.format(os.path.join(saq.SAQ_HOME, saq.CONFIG['global']['tmp_dir'], str(uuid.uuid4())))
            logging.debug("creating encrypted zip file {} for {}".format(dest_file, full_path))
            p = Popen(['zip', '-e', '--junk-paths', '-P', 'infected', dest_file, full_path])
            p.wait()

            # XXX we're reading it all into memory here
            with open(dest_file, 'rb') as fp:
                encrypted_data = fp.read()

            response = make_response(encrypted_data)
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = 'filename={}.zip'.format(os.path.basename(full_path))
            return response

        finally:

            try:
                os.remove(dest_file)
            except Exception as e:
                logging.error("unable to remove file {}: {}".format(dest_file, str(e)))
                report_exception()
    elif mode == 'text':
        with open(full_path, 'rb') as fp:
            result = fp.read()

        response = make_response(result)
        response.headers['Content-Type'] = 'text/plain'
        return response
    elif mode == 'malicious':
        maliciousdir = os.path.join(saq.SAQ_HOME, saq.CONFIG["malicious_files"]["malicious_dir"])
        if not os.path.isdir(maliciousdir):
            logging.error("malicious_dir {} does not exist")
            return "internal error (review logs)", 404
            
        if file_observable.sha256_hash is None:
            if not file_observable.compute_hashes():
                return "unable to compute file hash of {}".format(file_observable.value), 404

        malicioussub = os.path.join(maliciousdir, file_observable.sha256_hash[0:2])
        if not os.path.isdir(malicioussub):
            try:
                os.mkdir(malicioussub)
            except Exception as e:
                logging.error("unable to create dir {}: {}".format(malicioussub, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        lnname = os.path.join(malicioussub, file_observable.sha256_hash)
        if not os.path.exists(lnname):
            try:
                os.symlink(full_path, lnname)
            except Exception as e:
                logging.error("unable to create symlink from {} to {}: {}".format(
                    full_path, lnname, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        if not os.path.exists(lnname + ".alert"):
            fullstoragedir = os.path.join(saq.SAQ_HOME, alert.storage_dir)
            try:
                os.symlink(fullstoragedir, lnname + ".alert")
            except Exception as e:
                logging.error("unable to create symlink from {} to {}: {}".format(
                    fullstoragedir, lnname, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        # TODO we need to lock the alert here...
        file_observable.add_tag("malicious")
        alert.sync()

        # who gets these alerts?
        malicious_alert_recipients = saq.CONFIG['malicious_files']['malicious_alert_recipients'].split(',')

        msg = MIMEText('{} has identified a malicious file in alert {}.\r\n\r\nACE Direct Link: {}\r\n\r\nRemote Storage: {}'.format(
            current_user.username,
            alert.description,
            '{}/analysis?direct={}'.format(saq.CONFIG['gui']['base_uri'], alert.uuid),
            lnname))

        msg['Subject'] = "malicious file detected - {}".format(os.path.basename(file_observable.value))
        msg['From'] = saq.CONFIG.get("smtp", "mail_from")
        msg['To'] = ', '.join(malicious_alert_recipients)

        with smtplib.SMTP(saq.CONFIG.get("smtp", "server")) as mail:
            mail.send_message(msg, 
                from_addr=saq.CONFIG.get("smtp", "mail_from"), 
                to_addrs=malicious_alert_recipients)

        return "analysis?direct=" + alert.uuid, 200

    return "", 404

# this is legacy attachments stuff for what existed before observable type FILE usage was corrected
@analysis.route('/download_attachment', methods=['GET'])
@login_required
def download_attachment():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    attachment_uuid = request.args.get('attachment_uuid', None)
    if attachment_uuid is None:
        logging.error("missing attachment_uuid")
        return "missing attachment_uuid", 500

    mode = request.args.get('mode', None)
    if mode is None:
        logging.error("missing mode")
        return "missing mode", 500

    response = make_response()

    # find the attachment with this uuid
    for analysis in alert.all_analysis:
        for attachment in analysis.attachments:
            if attachment.uuid == attachment_uuid:
                if mode == 'raw':
                    # logging.debug("base dir = {0}".format(os.path.join(SAQ_HOME, analysis.storage_dir)))
                    # logging.debug("attachment.path = {0}".format(attachment.path))
                    # return send_from_directory(os.path.join(SAQ_HOME, alert.storage_dir), attachment.path, as_attachment=True)
                    return send_from_directory(SAQ_HOME, attachment.path, as_attachment=True)
                elif mode == 'hex':
                    # p = Popen(['hexdump', '-C', os.path.join(SAQ_HOME, alert.storage_dir, attachment.path)], stdout=PIPE)
                    attachment_path = os.path.join(SAQ_HOME, attachment.path)
                    logging.debug("displaying hex dump for {0}".format(attachment_path))
                    p = Popen(['hexdump', '-C', os.path.join(SAQ_HOME, attachment.path)], stdout=PIPE)
                    (stdout, stderr) = p.communicate()
                    response = make_response(stdout)
                    response.headers['Content-Type'] = 'text/plain';
                    return response
                elif mode == 'text':
                    with open(os.path.join(SAQ_HOME, attachment.path), 'rb') as fp:
                        result = fp.read()

                    response = make_response(result)
                    response.headers['Content-Type'] = 'text/plain';
                    return response

    return "", 404

@analysis.route('/add_tag', methods=['POST'])
@login_required
def add_tag():
    for expected_form_item in ['tag', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    tags = request.form['tag'].split()
    if len(tags) < 1:
        flash("you must specify one or more tags to add")
        return redirection

    # you have to be able to lock all of the alerts before you can continue
    locked_alerts = []

    try:
        for uuid in uuids:
            logging.debug("attempting to lock alert {} for tagging".format(uuid))
            alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == uuid).one()

            if not alert.lock():
                flash("unable to modify alert: alert is currently being analyzed")
                return redirection

            locked_alerts.append(alert)

        for alert in locked_alerts:

            if not alert.load():
                raise RuntimeError("alert.load() returned false")

            for tag in tags:
                alert.add_tag(tag)

            alert.sync()

        db.session.commit()
        if redirect_to == "analysis.manage":
            session['checked'] = uuids
        return redirection

    finally:
        for alert in locked_alerts:
            alert.unlock()

@analysis.route('/add_observable', methods=['POST'])
@login_required
def add_observable():
    from saq.common import validate_time_format

    for expected_form_item in ['alert_uuid', 'add_observable_type', 'add_observable_value', 'add_observable_time']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuid = request.form['alert_uuid']
    o_type = request.form['add_observable_type']
    o_value = request.form['add_observable_value']

    redirection_params = {'direct': uuid}
    redirection = redirect(url_for('analysis.index', **redirection_params))

    o_time = request.form['add_observable_time']

    if o_type not in VALID_OBSERVABLE_TYPES:
        flash("invalid observable type {0}".format(o_type))
        return redirection

    if o_value == '':
        flash("missing observable value")
        return redirection

    if o_time != '' and not validate_time_format(o_time):
        flash("invalid observable time format")
        return redirection

    try:
        alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
    except Exception as e:
        logging.error("unable to load alert {0} from database: {1}".format(uuid, str(e)))
        flash("internal error")
        return redirection

    if not alert.lock():
        flash("unable to modify alert: alert is currently being analyzed")
        return redirection

    try:
        if not alert.load():
            raise RuntimeError("alert.load() returned false")
    except Exception as e:
        logging.error("unable to load alert {0} from filesystem: {1}".format(uuid, str(e)))
        flash("internal error")
        return redirection

    alert.add_observable(o_type, o_value, None if o_time == '' else o_time)

    try:
        alert.sync()
    except Exception as e:
        logging.error("unable to sync alert: {0}".format(str(e)))
        flash("internal error")
        return redirection

    flash("added observable")
    return redirection

@analysis.route('/add_comment', methods=['POST'])
@login_required
def add_comment():
    user_comment = None
    uuids = None
    redirect_to = None

    for expected_form_item in ['comment', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    # the analysis page will require the direct uuid to get back to the alert the user just commented on
    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    user_comment = request.form['comment']
    if len(user_comment.strip()) < 1:
        flash("comment cannot be empty")
        return redirection

    for uuid in uuids:
        comment = Comment(
            user=current_user,
            uuid=uuid,
            comment=user_comment)

        db.session.add(comment)

    db.session.commit()

    flash("added comment to {0} item{1}".format(len(uuids), "s" if len(uuids) != 1 else ''))

    if redirect_to == "analysis.manage":
        session['checked'] = uuids
    return redirection

@analysis.route('/delete_comment', methods=['POST'])
@login_required
def delete_comment():
    comment_id = request.form.get('comment_id', None)
    if comment_id is None:
        flash("missing comment_id")
        return redirect(url_for('analysis.index'))

    # XXX use delete() instead of select then delete
    comment = db.session.query(Comment).filter(Comment.comment_id == comment_id).one()
    if comment.user.id != current_user.id:
        flash("invalid user for this comment")
        return redirect(url_for('analysis.index'))

    db.session.delete(comment)
    db.session.commit()

    return redirect(url_for('analysis.index', direct=request.form['direct']))

@analysis.route('/assign_ownership', methods=['POST'])
@login_required
def assign_ownership():
    analysis_page = False
    management_page = False
    alert_uuids = []

    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        # otherwise we will have an alert_uuids field with one or more alert UUIDs set
        management_page = True
        alert_uuids = request.form['alert_uuids'].split(',')
        session['checked'] = alert_uuids
    else:
        logging.error("neither of the expected request fields were present")
        flash("internal error")
        return redirect(url_for('analysis.index'))

    test_uuids=list(alert_uuids)
    for alert_uuid in alert_uuids:
        alert = db.session.query(GUIAlert).filter_by(uuid=alert_uuid).one()
        if alert.disposition is not None:
            test_uuids.remove(alert_uuid)
            flash("uuid " + alert_uuid + "has already been dispositioned and cannot transfer ownership.")

    alert_uuids=list(test_uuids)
    if len(alert_uuids):
        db.session.execute(GUIAlert.__table__.update().where(GUIAlert.uuid.in_(alert_uuids)).values(
            owner_id=int(request.form['selected_user_id']),
            owner_time=datetime.datetime.now()))
        db.session.commit()

    flash("assigned ownership of {0} alert{1}".format(len(alert_uuids), "" if len(alert_uuids) == 1 else "s"))
    if analysis_page:
        return redirect(url_for('analysis.index', direct=alert_uuids[0]))

    return redirect(url_for('analysis.manage'))

@analysis.route('/take_ownership', methods=['POST'])
@login_required
def take_ownership():
    analysis_page = False
    management_page = False
    alert_uuids = []

    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        # otherwise we will have an alert_uuids field with one or more alert UUIDs set
        management_page = True
        alert_uuids = request.form['alert_uuids'].split(',')
        session['checked'] = alert_uuids
    else:
        logging.error("neither of the expected request fields were present")
        flash("internal error")
        return redirect(url_for('analysis.index'))

    test_uuids=list(alert_uuids)
    for alert_uuid in alert_uuids:
        alert = db.session.query(GUIAlert).filter_by(uuid=alert_uuid).one()
        if alert.disposition is not None:
            test_uuids.remove(alert_uuid)
            flash("uuid " + alert_uuid + "has already been dispositioned and cannot transfer ownership.")

    alert_uuids=list(test_uuids)
    if len(alert_uuids):
        db.session.execute(GUIAlert.__table__.update().where(GUIAlert.uuid.in_(alert_uuids)).values(
            owner_id=current_user.id,
            owner_time=datetime.datetime.now()))
        db.session.commit()

    flash("took ownership of {0} alert{1}".format(len(alert_uuids), "" if len(alert_uuids) == 1 else "s"))
    if analysis_page:
        return redirect(url_for('analysis.index', direct=alert_uuids[0]))

    return redirect(url_for('analysis.manage'))

@analysis.route('/remediate', methods=['POST'])
@login_required
def remediate():
    # load all the alerts from the database we're going to process
    alerts = []
    alert_uuids = request.values['alert_uuids'].split(',')
    session['checked'] = alert_uuids
    for uuid in alert_uuids:
        alerts.append(db.session.query(GUIAlert).filter_by(uuid=uuid.strip()).one())

    # process them all at once
    from saq.remediation import remediate_phish

    messages = []

    try:
        messages = remediate_phish(alerts)
    except Exception as e:
        flash("unable to remediate phish: {}".format(str(e)))
        report_exception()

    # set the remediation time
    for alert in alerts:
        alert.removal_time = datetime.datetime.now()
        alert.removal_user_id = current_user.id
        db.session.add(alert)

    db.session.commit()

    for message in messages:
        flash(message)

    return redirect(url_for('analysis.manage'))

@analysis.route('/unremediate', methods=['POST'])
@login_required
def unremediate():
    # load all the alerts from the database we're going to process
    alerts = []
    alert_uuids = request.values['alert_uuids'].split(',')
    session['checked'] = alert_uuids
    for uuid in alert_uuids:
        alerts.append(db.session.query(GUIAlert).filter_by(uuid=uuid.strip()).one())

    # process them all at once
    from saq.remediation import unremediate_phish

    messages = []

    try:
        messages = unremediate_phish(alerts)
    except Exception as e:
        flash("unable to restore email: {}".format(str(e)))
        report_exception()

    for message in messages:
        flash(message)

    return redirect(url_for('analysis.manage'))

@analysis.route('/new_alert', methods=['POST'])
@login_required
def new_alert():
    # get submitted data
    insert_date = request.form.get('new_alert_insert_date', None)
    # reformat date
    insert_date = datetime.datetime.strptime(insert_date, '%m-%d-%Y %H:%M:%S').strftime(event_time_format)
    description = request.form.get('new_alert_description', None)

    comment = ''

    # create alert from data
    alert = Alert()
    alert.company_id = saq.CONFIG['gui'].getint('default_company_id')
    target_company = request.form.get('target_company', None)
    if target_company is not None:
        if int(target_company) != -1: # if it is not the default...
            alert.company_id = int(target_company)
    alert.uuid = str(uuid.uuid4())
    alert.tool = "gui"
    alert.tool_instance = socket.gethostname()
    alert.alert_type = "manual"
    alert.description = description
    alert.event_time = insert_date
    alert.details = {'user': current_user.username, 'comment': comment}
    alert.storage_dir = os.path.join(saq.CONFIG['global']['tmp_dir'], alert.uuid)

    # create alert directory structure
    dest_path = os.path.join(SAQ_HOME, alert.storage_dir)
    if not os.path.isdir(dest_path):
        try:
            os.makedirs(dest_path)
        except Exception as e:
            logging.error("unable to create directory {0}: {1}".format(dest_path, str(e)))
            report_exception()
            return
    alert.save()

    # add observables to alert
    for key in request.form.keys():
        if key.startswith("observables_types_"):
            index = key[18:]
            otype = request.form.get("observables_types_{}".format(index))
            otime = request.form.get("observables_times_{}".format(index))
            if otime == "":
                otime = None
            else:
                otime = datetime.datetime.strptime(otime, '%m-%d-%Y %H:%M:%S').strftime(event_time_format)
            if otype == 'file':
                upload_file = request.files["observables_values_{}".format(index)]
                save_path = os.path.join(SAQ_HOME, alert.storage_dir, os.path.basename(upload_file.filename))

                try:
                    upload_file.save(save_path)
                except Exception as e:
                    flash("unable to save {}: {}".format(save_path, str(e)))
                    report_exception()
                    return redirect(url_for('analysis.manage'))

                alert.add_observable(F_FILE, os.path.relpath(save_path, start=os.path.join(SAQ_HOME, alert.storage_dir)), o_time=otime)
            else:
                ovalue = request.form.get("observables_values_{}".format(index))
                alert.add_observable(otype, ovalue, o_time=otime)

    alert.save()

    target_company = None
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT `name` FROM company WHERE `id` = %s", (alert.company_id,))
        result = c.fetchone()
        if not result:
            flash("unknown company_id {}".format(alert.company_id))
            return redirect(url_for('analysis.manage'))

        target_company = result[0]

    # what host we select here depends on what company we are targeting the analysis for
    target_section = 'network_client_ace_{}'.format(target_company)
    if target_section not in saq.CONFIG:
        flash("company {} does not have a network_client_ace section in the configuratiuon".format(target_company))
        return redirect(url_for('analysis.manage'))
    
    remote_host = saq.CONFIG[target_section]['remote_host']
    remote_port = saq.CONFIG[target_section].getint('remote_port')
    ssl_hostname = saq.CONFIG[target_section]['ssl_hostname']
    ssl_cert = os.path.join(saq.SAQ_HOME, saq.CONFIG[target_section]['ssl_cert'])
    ssl_key = os.path.join(saq.SAQ_HOME, saq.CONFIG[target_section]['ssl_key'])
    ca_path = os.path.join(saq.SAQ_HOME, saq.CONFIG[target_section]['ca_path'])

    try:
        submit_alerts(remote_host, remote_port, ssl_cert, ssl_hostname, ssl_key, ca_path, os.path.join(SAQ_HOME, alert.storage_dir))
    except Exception as e:
        logging.error("unable to submit alert: {}".format(e))
        flash("unable to submit alert: {}".format(e))
        report_exception()

    shutil.rmtree(os.path.join(SAQ_HOME, alert.storage_dir))

    return redirect(url_for('analysis.manage'))

@analysis.route('/new_malware_option', methods=['POST', 'GET'])
@login_required
def new_malware_option():
    index = request.args['index']
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    return render_template('analysis/new_malware_option.html', malware=malware, index=index)

@analysis.route('/new_alert_observable', methods=['POST', 'GET'])
@login_required
def new_alert_observable():
    index = request.args['index']
    return render_template('analysis/new_alert_observable.html', observable_types=VALID_OBSERVABLE_TYPES, index=index)

@analysis.route('/add_to_event', methods=['POST'])
@login_required
def add_to_event():
    analysis_page = False
    event_id = request.form.get('event', None)
    event_name = request.form.get('event_name', None).strip()
    event_type = request.form.get('event_type', None)
    event_vector = request.form.get('event_vector', None)
    event_prevention = request.form.get('event_prevention', None)
    event_comment = request.form.get('event_comment', None)
    event_status = request.form.get('event_status', None)
    event_remediation = request.form.get('event_remediation', None)
    event_disposition = request.form.get('event_disposition', None)
    campaign_id = request.form.get('campaign_id', None)
    new_campaign = request.form.get('new_campaign', None)
    company_ids = request.form.getlist('company', None)
    alert_uuids = []
    if ("alert_uuids" in request.form):
        alert_uuids = request.form['alert_uuids'].split(',')
    new_event = False

    with get_db_connection() as dbm:
        c = dbm.cursor()

        if event_id == "NEW":
            new_event = True
            if (campaign_id == "NEW"):
                c.execute("""SELECT id FROM campaign WHERE name = %s""", (new_campaign))
                if c.rowcount > 0:
                    result = c.fetchone()
                    campaign_id = result[0]
                else:
                    c.execute("""INSERT INTO campaign (name) VALUES (%s)""", (new_campaign))
                    dbm.commit()
                    c.execute("""SELECT LAST_INSERT_ID()""")
                    result = c.fetchone()
                    campaign_id = result[0]

            creation_date = datetime.datetime.now().strftime("%Y-%m-%d")
            if (len(alert_uuids) > 0):
                sql='SELECT insert_date FROM alerts WHERE uuid IN (%s) order by insert_date' 
                in_p=', '.join(list(map(lambda x: '%s', alert_uuids)))
                sql = sql % in_p
                c.execute(sql, alert_uuids)
                result = c.fetchone()
                creation_date = result[0].strftime("%Y-%m-%d")

            c.execute("""SELECT id FROM events WHERE creation_date = %s AND name = %s""", (creation_date, event_name))
            if c.rowcount > 0:
                result = c.fetchone()
                event_id = result[0]
            else:
                c.execute("""INSERT INTO events (creation_date, name, status, remediation, campaign_id, type, vector, prevention_tool, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (creation_date, event_name, event_status, event_remediation, campaign_id, event_type, event_vector, event_prevention, event_comment))
                dbm.commit()
                c.execute("""SELECT LAST_INSERT_ID()""")
                result = c.fetchone()
                event_id = result[0]

            mal_assigned = False
            for key in request.form.keys():
                if key.startswith("malware_selection_"):
                    mal_assigned = True
                    index = key[18:]
                    mal_id = request.form.get("malware_selection_{}".format(index))

                    if mal_id == "NEW":
                        mal_name = request.form.get("mal_name_{}".format(index))
                        c.execute("""SELECT id FROM malware WHERE name = %s""", (mal_name))
                        if c.rowcount > 0:
                            result = c.fetchone()
                            mal_id = result[0]
                        else:
                            c.execute("""INSERT INTO malware (name) VALUES (%s)""", (mal_name))
                            dbm.commit()
                            c.execute("""SELECT LAST_INSERT_ID()""")
                            result = c.fetchone()
                            mal_id = result[0]

                        threats = request.form.getlist("threats_{}".format(index), None)
                        for threat in threats:
                            c.execute("""INSERT IGNORE INTO malware_threat_mapping (malware_id,type) VALUES (%s,%s)""", (mal_id, threat))
                        dbm.commit()

                    c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""", (event_id, mal_id))
                    dbm.commit()

            if not mal_assigned:
                c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""", (event_id, 5))
                dbm.commit()

        for uuid in alert_uuids:
            c.execute("""SELECT id, company_id FROM alerts WHERE uuid = %s""", (uuid))
            result = c.fetchone()
            alert_id = result[0]
            company_id = result[1]
            c.execute("""INSERT IGNORE INTO event_mapping (event_id, alert_id) VALUES (%s, %s)""", (event_id, alert_id))
            c.execute("""INSERT IGNORE INTO company_mapping (event_id, company_id) VALUES (%s, %s)""", (event_id, company_id))
        dbm.commit()

        # generate wiki
        c.execute("""SELECT creation_date, name FROM events WHERE id = %s""", (event_id))
        result = c.fetchone()
        creation_date = result[0]
        event_name = result[1]
        c.execute("""SELECT uuid, storage_dir FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s""", (event_id))
        rows = c.fetchall()

        alert_uuids = []
        alert_paths = []
        for row in rows:
            alert_uuids.append(row[0])
            alert_paths.append(row[1])

        if not new_event: 
            c.execute("""SELECT disposition FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s ORDER BY disposition DESC""", (event_id))
            result = c.fetchone()
            event_disposition = result[0]

        if len(alert_uuids) > 0:
            try:
                set_dispositions(alert_uuids, event_disposition)
            except Exception as e:
                flash("unable to set disposition (review error logs)")
                logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
                report_exception()

        wiki_name = "{} {}".format(creation_date.strftime("%Y%m%d"), event_name)
        data = { "name": wiki_name, "alerts": alert_paths, "id": event_id }

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))

def set_dispositions(alert_uuids, disposition, user_comment=None):
    with get_db_connection() as db:
        c = db.cursor()
        # update dispositions
        uuid_where_clause = ' , '.join(["'{}'".format(u) for u in alert_uuids])
        c.execute("""
                  UPDATE alerts 
                  SET disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                  owner_id = %s, owner_time = NOW()
                  WHERE uuid IN ( {} ) and (disposition is NULL or disposition != %s)""".format(uuid_where_clause),
                  (disposition, current_user.id, current_user.id, disposition))
        
        # add the comment if it exists
        if user_comment:
            for uuid in alert_uuids:
                c.execute("""
                          INSERT INTO comments ( user_id, uuid, comment ) 
                          VALUES ( %s, %s, %s )""", ( current_user.id, uuid, user_comment))

        # and insert these alerts back into the workstream
        c.execute("""
                  INSERT INTO workload ( alert_id ) 
                  SELECT id FROM alerts WHERE uuid IN ( {} )""".format(uuid_where_clause))
        db.commit()

@analysis.route('/set_disposition', methods=['POST'])
@login_required
def set_disposition():
    alert_uuids = []
    analysis_page = False
    alert = None
    existing_disposition = False
    total_crits_indicators_updated = 0

    # get disposition and user comment
    disposition = request.form.get('disposition', None)
    user_comment = request.form.get('comment', None)

    # format user comment
    if user_comment is not None:
        user_comment = user_comment.strip()

    # check if disposition is valid
    if disposition not in VALID_ALERT_DISPOSITIONS:
        flash("invalid alert disposition: {0}".format(disposition))
        return redirect(url_for('analysis.index'))

    # get uuids
    # we will either get one uuid from the analysis page or multiple uuids from the management page
    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        alert_uuids = request.form['alert_uuids'].split(',')
    else:
        logging.error("neither of the expected request fields were present")
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # update the database
    logging.debug("user {} updating {} alerts to {}".format(current_user.username, len(alert_uuids), disposition))
    try:
        set_dispositions(alert_uuids, disposition, user_comment=user_comment)
        flash("disposition set for {} alerts".format(len(alert_uuids)))
    except Exception as e:
        flash("unable to set disposition (review error logs)")
        logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
        report_exception()

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))

@analysis.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'GET':
        return render_template('analysis/search.html', observable_types=VALID_OBSERVABLE_TYPES)

    query = request.form.get('search', None)
    if query is None:
        flash("missing search field")
        return render_template('analysis/search.html', observable_types=VALID_OBSERVABLE_TYPES)

    search_comments = request.form.get('search_comments', False)
    search_details = request.form.get('search_details', False)
    search_all = request.form.get('search_all', False)
    search_daterange = request.form.get('daterange', '')

    uuids = []
    cache_lookup = False

    # does the search start with "indicator_type:"?
    for o_type in VALID_OBSERVABLE_TYPES:
        if query.lower().startswith('{0}:'.format(o_type.lower())):
            # search the cache
            cache_lookup = True
            try:
                with open(saq.CONFIG.get('global', 'cache'), 'r') as fp:
                    try:
                        cache = json.load(fp)
                    except Exception as e:
                        flash("failed to load cache: {0}".format(str(e)))
                        raise e

                (o_type, o_value) = query.split(':', 2)
                if o_type in cache:
                    if o_value in cache[o_type]:
                        logging.debug("found cached alert uuids for type {0} value {1}".format(o_type, o_value))
                        uuids.extend(cache[o_type][o_value])  # XXX case issues here

            except Exception as e:
                flash(str(e))
                return render_template('analysis/search.html')

    if not cache_lookup:
        # generate a list of files to look through
        # we use the date range to query the database for alerts that were generated during that time
        try:
            daterange_start, daterange_end = search_daterange.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)

        for alert in db.session.query(GUIAlert).filter(GUIAlert.insert_date.between(daterange_start, daterange_end)):
            args = [
                'find', '-L',
                alert.storage_dir,
                # saq.CONFIG.get('global', 'data_dir'),
                '-name', 'data.json']

            if search_details:
                args.extend(['-o', '-name', '*.json'])

            if search_all:
                args.extend(['-o', '-type', 'f'])

            logging.debug("executing {0}".format(' '.join(args)))

            p = Popen(args, stdout=PIPE)
            for file_path in p.stdout:
                file_path = file_path.decode(saq.DEFAULT_ENCODING).strip()
                grep = Popen(['grep', '-l', query, file_path], stdout=PIPE)
                logging.debug("searching {0} for {1}".format(file_path, query))
                for result in grep.stdout:
                    result = result.decode(saq.DEFAULT_ENCODING).strip()
                    logging.debug("result in {0} for {1}".format(result, query))
                    result = result[len(saq.CONFIG.get('global', 'data_dir')) + 1:]
                    result = result.split('/')
                    result = result[1]
                    uuids.append(result)

    if search_comments:
        for disposition in db.session.query(Disposition).filter(Disposition.comment.like('%{0}%'.format(query))):
            uuids.append(disposition.alert.uuid)

    alerts = []
    for uuid in list(set(uuids)):
        try:
            alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
            alert.load()
            alerts.append(alert)
        except Exception as e:
            logging.error("unable to load alert uuid {0}: {1}".format(uuid, str(e)))
            traceback.print_exc()
            continue

    return render_template('analysis/search.html',
                           query=query,
                           results=alerts,
                           search_comments_checked='CHECKED' if search_comments else '',
                           search_details_checked='CHECKED' if search_details else '',
                           search_all_checked='CHECKED' if search_all else '',
                           search_daterange=search_daterange)

# the types of filters we currently support
FILTER_TYPE_CHECKBOX = 'checkbox'
FILTER_TYPE_TEXT = 'text'
FILTER_TYPE_SELECT = 'select'

class SearchFilter(object):
    def __init__(self, name, type, default_value, verification_function=None):
        self.name = name  # the "name" property of the <input> element in the <form>
        self.type = type  # the type (see above)
        self.default_value = default_value  # the value to return if the filter is reset to default state
        self._reset = False  # set to True to return default values
        # used to verify the current value when the value property is accessed
        # if this function returns False then the default value is used
        # a single parameter is passed which is the value to be verified
        self.verification_function = verification_function
        # if we need to force the value 
        self._modified_value = None

    @property
    def form_value(self):
        """Returns the form value of the filter.  Returns None if the form value is unavailable."""
        # did we set it ourselves?
        if self._reset:
            return None
        # if the current request is a POST then we load the filter from that
        elif request.method == 'POST':
            return request.form.get(self.name, '')
        # if that's not the case then we try to load our last filter from the user's session
        elif self.name in session:
            return session[self.name]
        # otherwise we return None to indicate nothing is available
        else:
            return None

    @property
    def value(self):
        """Returns the logical value of the filter to be used by the program.  For example, a checkbox would be True or False."""
        if self._modified_value is not None:
            return self._modified_value
        elif self._reset:
            # logging.debug("reset flag is set for {0} user {1}".format(self.name, current_user))
            return self.default_value
        # if the current request is a POST then we load the filter from that
        elif request.method == 'POST':
            value = request.form.get(self.name, '')
            # logging.debug("loaded filter {0} value {1} from POST for user {2}".format(
            # self.name, value, current_user))
        # if that's not the case then we try to load our last filter from the user's session
        elif self.name in session:
            value = session[self.name]
            # logging.debug("loaded filter {0} value {1} from session for user {2}".format(
            # self.name, value, current_user))
        # otherwise we return the default value
        else:
            # logging.debug("using default value for filter {0} for user {1}".format(
            # self.name, current_user))
            return self.default_value

        if self.verification_function is not None:
            if not self.verification_function(value):
                logging.debug("filter item {0} failed verification with value {1} for user {2}".format(
                    self.name, value, current_user))
                return self.default_value

        # the result we return depends on the type of the filter
        # checkboxes return True or False
        if self.type == FILTER_TYPE_CHECKBOX:
            return value == 'on'

        # otherwise we just return the value
        return value

    @value.setter
    def value(self, value):
        self._modified_value = value

    @property
    def state(self):
        """Returns the state value, which is what is added to the HTML so that the <form> is recreated with all the filters set."""
        if self.type == FILTER_TYPE_CHECKBOX:
            return ' CHECKED ' if self.value else ''

        return self.value

    def reset(self):
        """Call to reset this filter item to it's default, which changes what the value and state properties return."""
        self._reset = True

def verify_integer(filter_value):
    """Used to verify that <input> type textboxes that should be integers actually are."""
    try:
        int(filter_value)
        return True
    except:
        return False

# the list of available filters that are hard coded into the filter dialog
# add new filters here
# NOTE that these do NOT include the dynamically generated filter fields
# NOTE these values ARE EQUAL TO the "name" field in the <form> of the filter dialog
FILTER_CB_OPEN = 'filter_open'
FILTER_CB_UNOWNED = 'filter_unowned'
FILTER_CB_ONLY_SLA = 'filter_sla'
FILTER_CB_ONLY_REMEDIATED = 'filter_only_remediated'
FILTER_CB_REMEDIATE_DATE = 'remediate_date'
FILTER_TXT_REMEDIATE_DATERANGE = 'remediate_daterange'
FILTER_CB_ONLY_UNREMEDIATED = 'filter_only_unremediated'
FILTER_CB_USE_DATERANGE = 'use_daterange'
FILTER_TXT_DATERANGE = 'daterange'
FILTER_CB_USE_SEARCH_OBSERVABLE = 'use_search_observable'
FILTER_S_SEARCH_OBSERVABLE_TYPE = 'search_observable_type'
FILTER_TXT_SEARCH_OBSERVABLE_VALUE = 'search_observable_value'
FILTER_CB_USE_DISPLAY_TEXT = 'use_display_text'
FILTER_TXT_DISPLAY_TEXT = 'display_text'
FILTER_CB_DIS_NONE = 'dis_none'
FILTER_CB_DIS_FALSE_POSITIVE = 'dis_false_positive'
FILTER_CB_DIS_UNKNOWN = 'dis_unknown'
FILTER_CB_DIS_POLICY_VIOLATION = 'dis_policy_violation'
FILTER_CB_DIS_RECONNAISSANCE = 'dis_reconnaissance'
FILTER_CB_DIS_WEAPONIZATION = 'dis_weaponization'
FILTER_CB_DIS_DELIVERY = 'dis_delivery'
FILTER_CB_DIS_EXPLOITATION = 'dis_exploitation'
FILTER_CB_DIS_INSTALLATION = 'dis_installation'
FILTER_CB_DIS_COMMAND_AND_CONTROL = 'dis_command_and_control'
FILTER_CB_DIS_EXFIL = 'dis_exfil'
FILTER_CB_DIS_DAMAGE = 'dis_damage'
FILTER_CB_USE_DIS_DATERANGE = 'use_disposition_daterange'
FILTER_TXT_DIS_DATERANGE = 'disposition_daterange'
FILTER_CB_USE_SEARCH_COMPANY = 'use_search_company'
FILTER_S_SEARCH_COMPANY = 'search_company'
FILTER_TXT_MIN_PRIORITY = 'min_priority'
FILTER_TXT_MAX_PRIORITY = 'max_priority'

# valid fields to sort on
SORT_FIELD_DATE = 'date'
SORT_FIELD_COMPANY_ID = 'company_id'
SORT_FIELD_PRIORITY = 'priority'
SORT_FIELD_ALERT = 'alert'
SORT_FIELD_OWNER = 'owner'
SORT_FIELD_DISPOSITION = 'disposition'
VALID_SORT_FIELDS = [
    SORT_FIELD_DATE,
    SORT_FIELD_COMPANY_ID,
    SORT_FIELD_PRIORITY,
    SORT_FIELD_ALERT,
    SORT_FIELD_OWNER,
    SORT_FIELD_DISPOSITION]

# valid directions to sort
SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

# the default sort direction
SORT_DIRECTION_DEFAULT = SORT_DIRECTION_DESC

# utility functions
def is_valid_sort_field(field_name):
    return field_name in VALID_SORT_FIELDS

def is_valid_sort_direction(sort_direction):
    return sort_direction in [SORT_DIRECTION_ASC, SORT_DIRECTION_DESC]

def make_sort_instruction(sort_field, sort_direction):
    return '{0}:{1}'.format(sort_field, sort_direction)


@analysis.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():

    # we'll need all these things to display
    open_events = db.session.query(Event).filter(Event.status == 'OPEN').order_by(Event.creation_date.desc()).all()
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    companies = db.session.query(Company).order_by(Company.name.asc()).all()
    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()

    # we want to display alerts that are either approaching or exceeding SLA
    sla_ids = [] # list of alert IDs that need to be displayed
    if saq.GLOBAL_SLA_SETTINGS.enabled or any([s.enabled for s in saq.OTHER_SLA_SETTINGS]):
        _query = db.session.query(GUIAlert).filter(GUIAlert.disposition == None)
        for alert_type in saq.EXCLUDED_SLA_ALERT_TYPES:
            _query = _query.filter(GUIAlert.alert_type != alert_type)
        for alert in _query:
            if alert.is_over_sla or alert.is_approaching_sla:
                sla_ids.append(alert.id)

    logging.debug("{} alerts in breach of SLA".format(len(sla_ids)))

    # object representations of the filters to define types and value verification routines
    # this later gets augmented with the dynamic filters
    filters = {
        FILTER_CB_OPEN: SearchFilter('filter_open', FILTER_TYPE_CHECKBOX, True),
        FILTER_CB_UNOWNED: SearchFilter('filter_unowned', FILTER_TYPE_CHECKBOX, True),
        FILTER_CB_ONLY_SLA: SearchFilter('filter_sla', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_ONLY_REMEDIATED: SearchFilter('filter_only_remediated', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_REMEDIATE_DATE: SearchFilter('remediate_date', FILTER_TYPE_CHECKBOX, False),
        FILTER_TXT_REMEDIATE_DATERANGE: SearchFilter('remediate_daterange', FILTER_TYPE_TEXT, ''),
        FILTER_CB_ONLY_UNREMEDIATED: SearchFilter('filter_only_unremediated', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_USE_DATERANGE: SearchFilter('use_daterange', FILTER_TYPE_CHECKBOX, False),
        FILTER_TXT_DATERANGE: SearchFilter('daterange', FILTER_TYPE_TEXT, ''),
        FILTER_CB_USE_SEARCH_OBSERVABLE: SearchFilter('use_search_observable', FILTER_TYPE_CHECKBOX, False),
        FILTER_S_SEARCH_OBSERVABLE_TYPE: SearchFilter('search_observable_type', FILTER_TYPE_SELECT, False),
        FILTER_TXT_SEARCH_OBSERVABLE_VALUE: SearchFilter('search_observable_value', FILTER_TYPE_TEXT, ''),
        FILTER_CB_USE_DISPLAY_TEXT: SearchFilter('use_display_text', FILTER_TYPE_CHECKBOX, False),
        FILTER_TXT_DISPLAY_TEXT: SearchFilter('display_text', FILTER_TYPE_TEXT, ''),
        FILTER_CB_DIS_NONE: SearchFilter('dis_none', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_FALSE_POSITIVE: SearchFilter('dis_false_positive', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_UNKNOWN: SearchFilter('dis_unknown', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_POLICY_VIOLATION: SearchFilter('dis_policy_violation', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_RECONNAISSANCE: SearchFilter('dis_reconnaissance', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_WEAPONIZATION: SearchFilter('dis_weaponization', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_DELIVERY: SearchFilter('dis_delivery', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_EXPLOITATION: SearchFilter('dis_exploitation', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_INSTALLATION: SearchFilter('dis_installation', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_COMMAND_AND_CONTROL: SearchFilter('dis_command_and_control', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_EXFIL: SearchFilter('dis_exfil', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_DIS_DAMAGE: SearchFilter('dis_damage', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_USE_DIS_DATERANGE: SearchFilter('use_disposition_daterange', FILTER_TYPE_CHECKBOX, False),
        FILTER_CB_USE_SEARCH_COMPANY: SearchFilter('use_search_company', FILTER_TYPE_CHECKBOX, False),
        FILTER_S_SEARCH_COMPANY: SearchFilter('search_company', FILTER_TYPE_SELECT, False),
        FILTER_TXT_DIS_DATERANGE: SearchFilter('disposition_daterange', FILTER_TYPE_TEXT, ''),
        FILTER_TXT_MIN_PRIORITY: SearchFilter('min_priority', FILTER_TYPE_TEXT, '',
                                              verification_function=verify_integer),
        FILTER_TXT_MAX_PRIORITY: SearchFilter('max_priority', FILTER_TYPE_TEXT, '',
                                              verification_function=verify_integer)
    }

    # are we resetting the filter?
    reset_filter = ('reset-filters' in request.form) or ('reset-filters' in request.args)

    if reset_filter:
        #logging.debug("user {0} reset filter".format(current_user))
        if 'sort_fields' in session:
            del session['sort_fields']

        if 'checked' in session:
            del session['checked']

        if 'offset' in session:
            del session['offset']
    
        if 'limit' in session:
            del session['limit']

    checked = []
    if 'checked' in session:
        checked = session['checked']

    # go ahead and get the list of all the users, we'll end up using it
    all_users = db.session.query(User).order_by('username').all()

    # by default we sort by date desc
    # key = sort_field, value = direction to sort
    sort_instructions = {SORT_FIELD_DATE: SORT_DIRECTION_DEFAULT}

    # the current sort fields are stored in the session
    if not reset_filter:
        if 'sort_fields' in session:
            # the fields are stored field_1:direction,field_2:direction,...
            # where field_1 is a valid SORT_FIELD_ constant
            # and direction is a valid SORT_DIRECTION constant
            sort_instructions = {}
            for sort_spec in session['sort_fields'].split(','):
                sort_field, sort_direction = sort_spec.split(':')
                sort_instructions[sort_field] = sort_direction
                #logging.debug("loaded sort field {0} direction {1} from session for user {2}".format(
                    #sort_field, sort_direction, current_user))

        # new sort fields and direction can be submitted by the form
        if request.method == 'POST':
            if 'sort_field' in request.form:
                sort_field = request.form['sort_field']  # this is the field we're either changing or adding
                if 'sort_field_add' in request.form:  # this is set to 1 if the user held in SHIFT when clicking on the link
                    # this causes a field to get ADDED to the sort or REMOVED if we have multiple fields selected
                    if sort_field in sort_instructions:
                        del sort_instructions[sort_field]
                        logging.debug("removed sort field {0} for user {1}".format(sort_field, current_user))
                    else:
                        sort_instructions[sort_field] = SORT_DIRECTION_DEFAULT
                        logging.debug("added sort field {0} for user {1}".format(sort_field, current_user))
                else:
                    # otherwise we only use the field that was clicked on
                    # does this sort field already exist?
                    if sort_field in sort_instructions:
                        # invert the direction of the sort
                        sort_instructions[sort_field] = SORT_DIRECTION_ASC if sort_instructions[
                                                                                  sort_field] == SORT_DIRECTION_DESC else SORT_DIRECTION_DESC
                        logging.debug("inverted sort direction on field {0} for user {1}".format(
                            sort_field, current_user))
                    else:
                        # otherwise we just use the default sort direction
                        sort_instructions = {sort_field: SORT_DIRECTION_DEFAULT}
                        logging.debug("set sort field to {0} for user {1}".format(sort_field, current_user))

    # load any dynamic filters available
    # dynamic filters are ones that are generated from data instead of hard coded

    # load analyst and owner filters
    # these are treated more like static values on the form even though they are dynamically generated
    analyst_filter_items = []
    owner_filter_items = []
    for user in all_users:
        key = 'analyst_{0}'.format(user.id)
        filter_item = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)
        analyst_filter_items.append(filter_item)
        filters[key] = filter_item

        key = 'owner_{0}'.format(user.id)
        filter_item = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)
        owner_filter_items.append(filter_item)
        filters[key] = filter_item

    filter_item = SearchFilter('analyst_none', FILTER_TYPE_CHECKBOX, False)
    filters['analyst_none'] = filter_item
    analyst_filter_items.append(filter_item)

    filter_item = SearchFilter('owner_none', FILTER_TYPE_CHECKBOX, False)
    filters['owner_none'] = filter_item
    owner_filter_items.append(filter_item)

    # load observable filters
    observable_filter_items = []
    if not reset_filter:
        for key in request.form.keys():
            if key.startswith('observable_'):
                filter_item = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)
                filters[key] = filter_item
                observable_filter_items.append(filter_item)

    # these can also come from the session
    deleted_keys = []
    for key in session:
        if key.startswith('observable_'):
            # if we are resetting the filter then we need to completely remove these dynamic values
            if reset_filter:
                deleted_keys.append(key)
                continue

            if key not in filters:
                logging.debug("loading filter {0} from session for user {1}".format(key, current_user))
                filter_item = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)
                filters[key] = filter_item
                observable_filter_items.append(filter_item)

    # load tag filters
    tag_filter_items = []
    if not reset_filter:
        for key in request.form.keys():
            if key.startswith('tag_'):
                filter_item = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)
                filters[key] = filter_item
                tag_filter_items.append(filter_item)

    # these can also come from the session
    for key in session:
        if key.startswith('tag_'):
            # if we are resetting the filter then we need to completely remove these dynamic values
            if reset_filter:
                deleted_keys.append(key)
                continue

            if key not in filters:
                logging.debug("loading filter {0} from session for user {1}".format(key, current_user))
                filter_item = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)
                filters[key] = filter_item
                tag_filter_items.append(filter_item)

    for key in deleted_keys:
        logging.debug("deleting session key {0} for user {1}".format(key, current_user))
        del session[key]

    # are we resetting the filter to the default?
    if reset_filter:
        #logging.debug("resetting filters for {}".format(current_user))
        for filter_item in filters.values():
            filter_item.reset()

        # if there are alerts in SLA then a reset defaults to only showing core alerts past sla
        if sla_ids:
            filters[FILTER_CB_ONLY_SLA].value = True
            filters[FILTER_S_SEARCH_COMPANY].value = 'Core'
            filters[FILTER_CB_USE_SEARCH_COMPANY].value = True

    # initialize filter state (passed to the view to set up the form controls)
    filter_state = {filters[f].name: filters[f].state for f in filters}

    # as we build the filter we also build a string to display to the user
    # that describes the current filter in english
    filter_english = []

    # to keep the page more aesthetically pleaseing, we will only display the disposition column if disposition is not None
    display_disposition = True

    # build the SQL query based on the filter settings
    query = db.session.query(GUIAlert)

    if filters[FILTER_CB_OPEN].value:
        # query = query.join(UserWorkload, GUIAlert.id == UserWorkload.alert_id).filter(UserWorkload.user_id == current_user.id)
        query = query.filter(GUIAlert.disposition == None)
        filter_english.append("open alerts")
        display_disposition = False

    if filters[FILTER_CB_ONLY_SLA].value:
        query = query.filter(GUIAlert.id.in_(sla_ids))
        filter_english.append("only alerts past SLA")
        filters[FILTER_CB_UNOWNED].value = False

    if filters[FILTER_CB_UNOWNED].value:
        query = query.filter(or_(GUIAlert.owner_id == current_user.id, GUIAlert.owner_id == None))
        filter_english.append("not owned by others")


    if filters[FILTER_CB_ONLY_REMEDIATED].value and filters[FILTER_CB_ONLY_UNREMEDIATED].value:
        flash("You cannot select both 'Only Remediated GUIAlerts' and 'Only Unremediated GUIAlerts'")
    else:
        if filters[FILTER_CB_ONLY_REMEDIATED].value:
            query = query.filter(and_(GUIAlert.removal_user_id != None))
            filter_english.append("remediated alerts")
            if filters[FILTER_CB_REMEDIATE_DATE].value and filters[FILTER_TXT_REMEDIATE_DATERANGE].value.strip() != '':
                try:
                    daterange_start, daterange_end = filters[FILTER_TXT_REMEDIATE_DATERANGE].value.split(' - ')
                    daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
                    daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
                except Exception as error:
                    flash("error parsing date range, using default 7 days: {0}".format(str(error)))
                    daterange_end = datetime.datetime.now()
                    daterange_start = daterange_end - datetime.timedelta(days=7)

                query = query.filter(and_(GUIAlert.insert_date >= daterange_start, GUIAlert.insert_date <= daterange_end))
                filter_english.append("alert remediated between {0} and {1}".format(daterange_start, daterange_end))
        if filters[FILTER_CB_ONLY_UNREMEDIATED].value:
            query = query.filter(and_(GUIAlert.removal_user_id == None))
            filter_english.append("unremediated alerts")

    if filters[FILTER_CB_USE_DATERANGE].value and filters[FILTER_TXT_DATERANGE].value != '':
        try:
            daterange_start, daterange_end = filters[FILTER_TXT_DATERANGE].value.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)

        query = query.filter(and_(GUIAlert.insert_date >= daterange_start, GUIAlert.insert_date <= daterange_end))
        filter_english.append("alert received between {0} and {1}".format(daterange_start, daterange_end))

    if filters[FILTER_CB_USE_SEARCH_OBSERVABLE].value and filters[FILTER_S_SEARCH_OBSERVABLE_TYPE].value != '' and \
                    filters[FILTER_TXT_SEARCH_OBSERVABLE_VALUE].value != '':
        
        query = query.join(ObservableMapping, GUIAlert.id == ObservableMapping.alert_id)\
                     .join(saq.database.Observable, ObservableMapping.observable_id == saq.database.Observable.id)\
                     .filter(and_(True if filters[FILTER_S_SEARCH_OBSERVABLE_TYPE].value == 'ANY' 
                                       else saq.database.Observable.type == filters[FILTER_S_SEARCH_OBSERVABLE_TYPE].value,
                                  saq.database.Observable.value.like('%{}%'.format(filters[FILTER_TXT_SEARCH_OBSERVABLE_VALUE].value))))
        #query = query.filter(
            #GUIAlert.id.in_(
                #db.session.query(GUIAlert.id)
                    #.join(ObservableMapping, GUIAlert.id == ObservableMapping.alert_id)
                    #.join(saq.database.Observable, ObservableMapping.observable_id == saq.database.Observable.id)
                    #.filter(and_(
                    #True if filters[FILTER_S_SEARCH_OBSERVABLE_TYPE].value == 'ANY' else saq.database.Observable.type ==
                                                                                         #filters[
                                                                                             #FILTER_S_SEARCH_OBSERVABLE_TYPE].value,
                    #saq.database.Observable.value.like(
                        #'%{}%'.format(filters[FILTER_TXT_SEARCH_OBSERVABLE_VALUE].value)))).subquery()
            #)
        #)

        filter_english.append("has observable of type {0} with value {1}".format(
            filters[FILTER_S_SEARCH_OBSERVABLE_TYPE].value,
            filters[FILTER_TXT_SEARCH_OBSERVABLE_VALUE].value))

    if filters[FILTER_CB_USE_DISPLAY_TEXT].value and filters[FILTER_TXT_DISPLAY_TEXT].value != '':
        query = query.filter(GUIAlert.description.ilike("%{0}%".format(filters[FILTER_TXT_DISPLAY_TEXT].value)))
        filter_english.append("matching {0}".format(filters[FILTER_TXT_DISPLAY_TEXT].value))

    dis_filters = []
    dis_filter_english = []
    if filters[FILTER_CB_DIS_NONE].value:
        dis_filters.append(GUIAlert.disposition == None)
        dis_filter_english.append("no disposition")
    if filters[FILTER_CB_DIS_FALSE_POSITIVE].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_FALSE_POSITIVE)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_FALSE_POSITIVE))
    if filters[FILTER_CB_DIS_UNKNOWN].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_UNKNOWN)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_UNKNOWN))
    if filters[FILTER_CB_DIS_POLICY_VIOLATION].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_POLICY_VIOLATION)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_POLICY_VIOLATION))
    if filters[FILTER_CB_DIS_RECONNAISSANCE].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_RECONNAISSANCE)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_RECONNAISSANCE))
    if filters[FILTER_CB_DIS_WEAPONIZATION].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_WEAPONIZATION)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_WEAPONIZATION))
    if filters[FILTER_CB_DIS_DELIVERY].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_DELIVERY)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_DELIVERY))
    if filters[FILTER_CB_DIS_EXPLOITATION].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_EXPLOITATION)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_EXPLOITATION))
    if filters[FILTER_CB_DIS_INSTALLATION].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_INSTALLATION)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_INSTALLATION))
    if filters[FILTER_CB_DIS_COMMAND_AND_CONTROL].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_COMMAND_AND_CONTROL)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_COMMAND_AND_CONTROL))
    if filters[FILTER_CB_DIS_EXFIL].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_EXFIL)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_EXFIL))
    if filters[FILTER_CB_DIS_DAMAGE].value:
        dis_filters.append(GUIAlert.disposition == saq.constants.DISPOSITION_DAMAGE)
        dis_filter_english.append("disposition is {0}".format(saq.constants.DISPOSITION_DAMAGE))

    if len(dis_filters) > 0:
        query = query.filter(or_(*dis_filters))
        filter_english.append(' OR '.join(dis_filter_english))

    # if we have alerts in SLA then we force the filter to only show alerts from core companies
    # (only core companies will have alerts in SLA)
    if filters[FILTER_CB_USE_SEARCH_COMPANY].value and filters[FILTER_S_SEARCH_COMPANY].value != '':
        if filters[FILTER_S_SEARCH_COMPANY].value == 'Core':
            query = query.filter(GUIAlert.company_id.in_(map(int, saq.CONFIG['gui']['core_companies'].split(','))))
            filter_english.append("belongs to a core company")
        else:
            query = query.filter(GUIAlert.company_id == int(filters[FILTER_S_SEARCH_COMPANY].value))
            for company in companies:
                if company.id == int(filters[FILTER_S_SEARCH_COMPANY].value):
                    filter_english.append("belongs to {}".format(company.name))
                    break

    analyst_filters = []
    analyst_filter_english = []

    # XXX there might be a race condition here when new users are added
    for filter_item in analyst_filter_items:
        if filter_item.value:
            if filter_item.name == 'analyst_none':
                analyst_filters.append(GUIAlert.disposition_user_id == None)
                analyst_filter_english.append("analyzed by nobody")
            else:
                analyst_id = int(
                    filter_item.name[len('analyst_'):])  # the user id is encoded in the name of the form element
                analyst_filters.append(GUIAlert.disposition_user_id == analyst_id)
                # find the user with this user ID so we can display the name
                for user in all_users:
                    if user.id == analyst_id:
                        analyst_filter_english.append("analyzed by {0}".format(user.username))

    if len(analyst_filters) > 0:
        query = query.filter(or_(*analyst_filters))
        filter_english.append(" OR ".join(analyst_filter_english))

    owner_filters = []
    owner_filter_english = []

    # XXX there might be a race condition here when new users are added
    for filter_item in owner_filter_items:
        if filter_item.value:
            if filter_item.name == 'owner_none':
                owner_filters.append(GUIAlert.owner_id == None)
                owner_filter_english.append("owned by nobody")
            else:
                owner_id = int(
                    filter_item.name[len('owner_'):])  # the user id is encoded in the name of the form element
                owner_filters.append(GUIAlert.owner_id == owner_id)
                # find the user with this user ID so we can display the name
                for user in all_users:
                    if user.id == owner_id:
                        owner_filter_english.append("owned by {0}".format(user.username))

    if len(owner_filters) > 0:
        query = query.filter(or_(*owner_filters))
        filter_english.append(" OR ".join(owner_filter_english))

    if filters[FILTER_CB_USE_DIS_DATERANGE].value and filters[FILTER_TXT_DIS_DATERANGE].value != '':
        try:
            daterange_start, daterange_end = filters[FILTER_TXT_DIS_DATERANGE].value.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing disposition date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)

        query = query.filter(and_(GUIAlert.disposition_time >= daterange_start, GUIAlert.disposition_time <= daterange_end))
        filter_english.append("alert reviewed between {0} and {1}".format(daterange_start, daterange_end))

    if filters[FILTER_TXT_MIN_PRIORITY].value != '':
        query = query.filter(GUIAlert.priority > filters[FILTER_TXT_MIN_PRIORITY].value)
        filter_english.append("minimum priority of {0}".format(filters[FILTER_TXT_MIN_PRIORITY].value))

    if filters[FILTER_TXT_MAX_PRIORITY].value != '':
        query = query.filter(GUIAlert.priority > filters[FILTER_TXT_MAX_PRIORITY].value)
        filter_english.append("maximum priority of {0}".format(filters[FILTER_TXT_MAX_PRIORITY].value))

    # iterate over the list of observables we're filtering on
    observables = []
    observable_filters_english = []

    for filter_item in observable_filter_items:
        if filter_item.value:
            observable_id = filter_item.name[len(
                'observable_'):]  # the observable_id is encoded in the name property of the form element
            try:
                observable = db.session.query(Observable).filter(Observable.id == observable_id).one()
            except NoResultFound:
                logging.warning("cannot find observable {0}".format(observable_id))
                continue

            observable_filters_english.append(
                "with observable type {0} value {1}".format(observable.type, observable.value))
            observables.append(observable)

    if len(observables) > 0:
        query = query.join(ObservableMapping, GUIAlert.id == ObservableMapping.alert_id)\
                     .join(saq.database.Observable, ObservableMapping.observable_id == saq.database.Observable.id)\
                     .filter(ObservableMapping.observable_id.in_([o.id for o in observables]))
        #query = query.filter(GUIAlert.id.in_(
            #db.session.query(GUIAlert.id).join(ObservableMapping, GUIAlert.id == ObservableMapping.alert_id).filter(
                #ObservableMapping.observable_id.in_([o.id for o in observables])).subquery()))
        filter_english.extend(observable_filters_english)

    # iterate over the list of tags we're filtering on
    tags = []
    tag_filters_english = []

    for filter_item in tag_filter_items:
        if filter_item.value:
            tag_id = filter_item.name[len('tag_'):]  # the tag_id is encoded in the name property of the form element
            try:
                tag = db.session.query(Tag).filter(Tag.id == tag_id).one()
            except NoResultFound:
                continue

            tag_filters_english.append("with tag {}".format(tag.name))
            tags.append(tag)

    if len(tags) > 0:
        query = query.join(TagMapping, GUIAlert.id == TagMapping.alert_id)\
                     .join(Tag, Tag.id == TagMapping.tag_id)\
                     .filter(Tag.id.in_([t.id for t in tags]))

        #query = query.filter(
            #GUIAlert.id.in_(db.session.query(GUIAlert.id).join(TagMapping, GUIAlert.id == TagMapping.alert_id).filter(
                #TagMapping.tag_id.in_([t.id for t in tags])).subquery()))
        filter_english.extend(tag_filters_english)

    query = query.options(joinedload('workload_item'))
    query = query.options(joinedload('delayed_analysis'))
    query = query.options(joinedload('observable_mappings'))
    query = query.options(joinedload('event_mapping'))

    count_query = query.statement.with_only_columns([func.count(distinct(saq.database.Alert.id))]).order_by(None)
    total_alerts = db.session.execute(count_query).scalar()

    # if alerts are in breach of SLA then we sort by date ascending
    if reset_filter and sla_ids:
        sort_instructions = {SORT_FIELD_DATE: SORT_DIRECTION_ASC}

    # finally sort the results
    order_by_clause = []
    for sort_field in sort_instructions.keys():
        if sort_field == SORT_FIELD_DATE:
            order_by_clause.append(GUIAlert.insert_date.desc() if sort_instructions[
                                                                   sort_field] == SORT_DIRECTION_DESC else GUIAlert.insert_date.asc())
        elif sort_field == SORT_FIELD_PRIORITY:
            order_by_clause.append(
                GUIAlert.priority.desc() if sort_instructions[sort_field] == SORT_DIRECTION_DESC else GUIAlert.priority.asc())
        elif sort_field == SORT_FIELD_ALERT:
            order_by_clause.append(GUIAlert.description.desc() if sort_instructions[
                                                                   sort_field] == SORT_DIRECTION_DESC else GUIAlert.description.asc())
        elif sort_field == SORT_FIELD_OWNER:
            order_by_clause.append(
                GUIAlert.owner_id.desc() if sort_instructions[sort_field] == SORT_DIRECTION_DESC else GUIAlert.owner_id.asc())
        elif sort_field == SORT_FIELD_DISPOSITION:
            order_by_clause.append(GUIAlert.disposition.desc() if sort_instructions[
                                                                   sort_field] == SORT_DIRECTION_DESC else GUIAlert.disposition.asc())

    query = query.order_by(*order_by_clause)

    # pagination calculation
    alert_offset = 0
    alert_limit = 227

    # did the user modify the view limit?
    if 'modify_limit' in request.values:
        try:
            value = int(request.values['modify_limit'])
            if value < 1 or value > 1000:
                raise ValueError("limit must be between 1 and 1000")
            session['limit'] = value
        except Exception as e:
            logging.error("invalid limit: {}".format(e))

    if 'limit' in session:
        try:
            user_limit = alert_limit = int(session['limit'])
        except Exception as e:
            logging.warning("invalid alert limit in session: {}".format(e))

    # where are we starting from?
    try:
        if 'offset' in session:
            alert_offset = int(session['offset'])

        if 'navigate' in request.values:
            if request.values['navigate'] == 'start':
                alert_offset = 0
            elif request.values['navigate'] == 'prev':
                alert_offset -= alert_limit
                if alert_offset < 0:
                    alert_offset = 0
            elif request.values['navigate'] == 'next':
                alert_offset += alert_limit
                if alert_offset + alert_limit > total_alerts:
                    alert_offset = total_alerts - alert_limit
                    if alert_offset < 0:
                        alert_offset = 0
            elif request.values['navigate'] == 'last':
                alert_offset = total_alerts - alert_limit
                if alert_offset < 0:
                    alert_offset = 0

            session['offset'] = alert_offset

    except Exception as e:
        logging.error("navigation failed: {}".format(e))
        alert_offset = 0

    if alert_limit > total_alerts:
        alert_limit = total_alerts

    query = query.limit(alert_limit)
    query = query.offset(alert_offset)

    # load all the alerts into memory
    alerts = query.all()

    # if we have alerts in breach of SLA then we need to modify our main query to include those
    #if sla_ids:
        #query = db.session.query(GUIAlert).filter(or_(query.whereclause, GUIAlert.id.in_(sla_ids)))

    comments = {}
    if alerts:
        for comment in db.session.query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    alert_tags = {}
    # we don't show "special" or "hidden" tags in the display
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] in ['special', 'hidden' ]]
    if alerts:
        for tag, alert_uuid in db.session.query(Tag, GUIAlert.uuid).\
                                                   join(TagMapping, Tag.id == TagMapping.tag_id).\
                                                   join(GUIAlert, GUIAlert.id == TagMapping.alert_id).\
                                                   filter(GUIAlert.id.in_([a.id for a in alerts])):
            if tag.name in special_tag_names:
                continue

            if alert_uuid not in alert_tags:
                alert_tags[alert_uuid] = []

            alert_tags[alert_uuid].append(tag)

    for alert_uuid in alert_tags.keys():
        alert_tags[alert_uuid] = sorted(alert_tags[alert_uuid], key=lambda x: (-x.score, x.name.lower()))
        #alert_tags[item.uuid] = [tag_mapping for tag_mapping in alert_tags[item.uuid] if tag_mapping.tag.name not in special_tag_names]

    # get the total scores for all profiles
    #profile_point_counts = get_profile_point_counts()

    # determine profile point scores
    profile_point_scores = {} # key = alert_uuid, value = list[tuple(tag_name, score (0 to 100))]

    # need to sort...
    #for alert_uuid, tag_name, pp_score in db.session.query(GUIAlert.uuid, Tag.name, func.count('*')).\
                         #join(ProfilePointAlertMapping).\
                         #join(ProfilePoint).\
                         #join(ProfilePointTagMapping).\
                         #join(Tag).\
                         #filter(GUIAlert.id.in_(sub_query)).\
                         #group_by(GUIAlert.uuid, Tag):
        #if alert_uuid not in profile_point_scores:
            #profile_point_scores[alert_uuid] = []

        #score = int(math.floor(pp_score / profile_point_counts[tag_name] * 100.0))
        #if score >= saq.CONFIG['profile_points'].getint('display_threshold'):
            #profile_point_scores[alert_uuid].append((tag_name, score))
            ##profile_point_scores[alert_uuid][tag_name] = int(math.floor(pp_score / profile_point_counts[tag_name] * 100.0))

    #for alert_uuid in profile_point_scores.keys():
        # sort these by score (best to worst) followed by name if they are equal
        # TODO the second sort (for equal scores) is backwards
        #profile_point_scores[alert_uuid] = sorted(profile_point_scores[alert_uuid], key=lambda x: (x[1], x[0]), reverse=True)


    # for each observable we want to show how many there are (in all) and (in all open alerts)
    open_observable_count = defaultdict(lambda: 0)
    all_observable_count = defaultdict(lambda: 0)

    # save the current filter to the session
    for filter_name in filters.keys():
        form_value = filters[filter_name].form_value
        if form_value is not None:
            session[filter_name] = form_value
        else:
            if filter_name in session:
                del session[filter_name]

    # and also save the current sort
    sort_specs = []
    for sort_field in sort_instructions:
        sort_specs.append(make_sort_instruction(sort_field, sort_instructions[sort_field]))

    session['sort_fields'] = ','.join(sort_specs)

    # we pass a dictionary of key = sort_field, value = html to use for the arrow up or down
    # depending on how the user is currently sorting things
    sort_arrow_html = {}
    for sort_field in VALID_SORT_FIELDS:
        sort_arrow_html[sort_field] = ''
        if sort_field in sort_instructions:
            sort_arrow_html[sort_field] = '&darr;' if sort_instructions[sort_field] == SORT_DIRECTION_ASC else '&uarr;'

    return render_template(
        'analysis/manage.html',
        alerts=alerts,
        checked=checked,
        comments=comments,
        alert_tags=alert_tags,
        filter_state=filter_state,
        all_users=all_users,
        open_events=open_events,
        malware=malware,
        companies=companies,
        campaigns=campaigns,
        open_observable_count=open_observable_count,
        all_observable_count=all_observable_count,
        observables=observables,
        tags=tags,
        sort_arrow_html=sort_arrow_html,
        filter_english=' AND '.join(filter_english),
        observable_types=VALID_OBSERVABLE_TYPES,
        has_sla=len(sla_ids) > 0,
        display_disposition=display_disposition,
        profile_point_scores=profile_point_scores,
        total_alerts=total_alerts,
        alert_limit=alert_limit,
        user_limit=session['limit'] if 'limit' in session else "50",
        alert_offset=alert_offset)


# begin helper functions for metrics
def businessHourCycleTimes(df):
    # return pd.Series(timedelta) of alert cycle times in business hours
    business_hours = (datetime.time(6), datetime.time(18))
    _bt = businesstime.BusinessTime(business_hours=business_hours)
    
    bh_cycle_time = []
    for alert in df.itertuples():
        open_hours = _bt.open_hours.seconds / 3600
        btd = _bt.businesstimedelta(alert.insert_date, alert.disposition_time)
        btd_hours = btd.seconds / 3600
        bh_cycle_time.append(datetime.timedelta(hours=(btd.days * open_hours + btd_hours)))
        
    return pd.Series(data=bh_cycle_time)


def alert_stats_for_month(df, business_hours=False):
    # df = dataframe of all alerts during one month
    # output: dataframe of alert cycle_time & quantity stats by disposition

    df.set_index('disposition', inplace=True)
    dispositions = df.index.get_level_values('disposition').unique()

    dispo_data = {}
    for dispo in dispositions:
        if business_hours: # could just pass df or a copy of df - here a copy with just data needed
            alert_cycle_times = businessHourCycleTimes(df.loc[[dispo],['disposition_time', 'insert_date']])
        else:
            alert_cycle_times = df.loc[dispo, 'disposition_time'] - df.loc[dispo, 'insert_date'] 

        try:
            dispo_data[dispo] = {
                'Total' : alert_cycle_times.sum(),
                'Cycle-Time' : alert_cycle_times.mean(),
                'Min' : alert_cycle_times.min(),
                'Max' : alert_cycle_times.max(),
                'Stdev' : alert_cycle_times.std(),
                'Quantity' : len(df.loc[dispo])
            }
        except AttributeError: # this occures when there was only ONE alert of this dispo type
            dispo_data[dispo] = {
                'Total' : alert_cycle_times,
                'Cycle-Time' : alert_cycle_times,
                'Min' : alert_cycle_times,
                'Max' : alert_cycle_times,
                'Stdev' : pd.Timedelta(datetime.timedelta()),
                'Quantity' : 1
            }

    dispo_df = pd.DataFrame(data=dispo_data, columns=dispositions)
        
    return dispo_df


def statistic_by_dispo(df, stat, business_hours=False):
    # Input: 
    #    df - dataframe of alerts with these columns: 
    #        ['month', 'insert_date', 'disposition', 'disposition_time', 'owner_id', 'owner_time']
    #    stat - a specific statistic we're interested in (Cycle-Time    Max Min Quantity    Stdev   Total)
    #   business_hours - bool to tell us if we're calculating in Business hours or real time
    # Output: List of dataframes, indexed by disposition, where each dataframe contains the
    #         alert 'stat' statisics for each month
    
    months = df.index.get_level_values('month').unique()
    #dispositions = list(df['disposition'].unique())
    dispositions = [ 'FALSE_POSITIVE','GRAYWARE','POLICY_VIOLATION','RECONNAISSANCE','WEAPONIZATION','DELIVERY','EXPLOITATION','INSTALLATION','COMMAND_AND_CONTROL','EXFIL','DAMAGE' ]

    stat_data = {}
    for dispo in dispositions:
        
        #have to handle months where a specific disposition never happend
        #converting timedelta objects to minutes for astetic and graphing purposes
        fp = deliv = exp = c2 = damage = exfil = recon = wepon = gray = pv = instal = 0
        month_data = {}

        for month in months:
            month_df = df.loc[month] # <- select the month
            # 1 dispo type during month means DataFrame selection gives a Series
            # alert_stats_for_month expects a DataFrame
            if isinstance(month_df, pd.Series):
                month_df = pd.DataFrame([month_df])

            month_df = alert_stats_for_month(month_df, business_hours)

            try:
                value = month_df.at[stat, dispo]
            except KeyError: # dispo didn't happen during the given month
                value = None
            if isinstance(value, datetime.timedelta): # convert to hours
                value = value.total_seconds() / 60 / 60
            month_data[month] = value
            
        stat_data[dispo] = month_data

    stat_data_df = pd.DataFrame(data=stat_data)
    if stat == 'Quantity':
        stat_data_df.fillna(0, inplace=True)
        stat_data_df = stat_data_df.astype(int)
        stat_data_df.name = "Alert Quantities" 
    else:
        stat_data_df.fillna(0, inplace=True)
        if business_hours:
            stat_data_df.name = "Business Hour Alert " + stat
        else:
            stat_data_df.name = "Real Hour Alert " + stat

    return stat_data_df


def SliceAlertsByTimeCategory(df):
    # this function evaluates the alerts in the given dataframe and then 
    # places those alerts in new dataframes based on when the alert was created
    # i.e., weekend, business hours, and week nights
    
    df.reset_index(0, inplace=True) # unsetting to better intertuple
    # Cycle-Time Max Min Quantity Stdev Total
     
    weekend_indexes = []
    bday_indexes = []
    night_indexes = []
    i=0
    # month->insert_date    disposition disposition_time    owner_id    owner_time
    for row in df.itertuples():

        if row.insert_date.weekday() == 5: # Sat
            # put into weekend bucket
            weekend_indexes.append(i) 
            
        elif row.insert_date.weekday() == 6: # Sunday
            # put into weekend bucket
            weekend_indexes.append(i)
            
        elif row.insert_date.weekday() == 0: # Monday
            #either weekend or weeknight bucket
            if row.insert_date.time() < datetime.time(hour=6, minute=0, second=0):
                night_indexes.append(i)
            elif row.insert_date.time() >= datetime.time(hour=18, minute=0, second=0):
                night_indexes.append(i)
            else: #put into Buisness hours bucket
                bday_indexes.append(i)
                
        elif row.insert_date.weekday() == 1: #'Tue':
            if ( row.insert_date.time() < datetime.time(hour=6, minute=0, second=0)
                 or row.insert_date.time() >= datetime.time(hour=18, minute=0, second=0) ):
                night_indexes.append(i)
            else: # put into buisness hour bucket
                bday_indexes.append(i)
                
        elif row.insert_date.weekday() == 2: #'Wed':
            if ( row.insert_date.time() < datetime.time(hour=6, minute=0, second=0)
                 or row.insert_date.time() >= datetime.time(hour=18, minute=0, second=0) ):
                # put into weeknight bucket
                night_indexes.append(i)
            else: # put into buisness hour bucket
                bday_indexes.append(i)
                
        elif row.insert_date.weekday() == 3: # Thurs
            if ( row.insert_date.time() < datetime.time(hour=6, minute=0, second=0)
                 or row.insert_date.time() >= datetime.time(hour=18, minute=0, second=0) ):
                # put into weeknight bucket
                night_indexes.append(i)
            else: # put into buisness hour bucket
                bday_indexes.append(i)
                
        elif row.insert_date.weekday() == 4: #'Fri':
            if row.insert_date.time() < datetime.time(hour=6, minute=0, second=0):
                # put into weeknight bucket
                night_indexes.append(i)
            elif row.insert_date.time() >= datetime.time(hour=18, minute=0, second=0):
                # put into weeknight or weekend bucket?
                weekend_indexes.append(i)
            else: # buisness hours - get first day remainder 
                # buisness hour bucket
                bday_indexes.append(i)
        i+=1
    weekend_df = df[df.index.isin(weekend_indexes)]
    bday_df = df[df.index.isin(bday_indexes)]
    nights_df = df[df.index.isin(night_indexes)]
    if((len(weekend_df) + len(nights_df) + len(bday_df)) != len(df) ):
        logging.error("Incorrect Alert count/Missing Alerts")
    return weekend_df, nights_df, bday_df


def Hours_of_Operation(df):
    # df = dataframe of alerts -> SliceAlertsByTimeCategory
    # output = df of alert-cycle-time averages and quantities,
    #          for each month (across all dispositions), and respective to the hours
    #          of operation by which alerts where created in
    
    months = df.index.get_level_values('month').unique()
    
    weekend, nights, bday = SliceAlertsByTimeCategory(df)
    weekend.set_index('month', inplace=True)
    nights.set_index('month', inplace=True)
    bday.set_index('month', inplace=True)

    bday_averages = []
    weekend_averages = []
    nights_averages = []
    bday_quantities = []
    weekend_quantities = []
    nights_quantities = []
    for month in months:
        try:
            bday_ct = bday.loc[month, 'disposition_time'] - bday.loc[month, 'insert_date']
        except KeyError: # month not in index, or only one alert
            bday_ct = pd.Series(data=pd.Timedelta(0))
        try:
            nights_ct = nights.loc[month, 'disposition_time'] - nights.loc[month, 'insert_date']
        except KeyError: # month not in index 
            nights_ct = pd.Series(data=pd.Timedelta(0))
        try: 
            weekend_ct = weekend.loc[month, 'disposition_time'] - weekend.loc[month, 'insert_date']
        except KeyError:
            weekend_ct = pd.Series(data=pd.Timedelta(0))

        # handle case of single alert in a bucket for the month
        if isinstance(bday_ct, pd.Timedelta):
            bday_ct = pd.Series(data=bday_ct)
        if isinstance(nights_ct, pd.Timedelta):
            nights_ct = pd.Series(data=nights_ct)
        if isinstance(weekend_ct, pd.Timedelta):
            weekend_ct = pd.Series(data=weekend_ct)

        bday_averages.append((bday_ct.mean().total_seconds() / 60) / 60)
        nights_averages.append((nights_ct.mean().total_seconds() / 60) / 60)
        weekend_averages.append((weekend_ct.mean().total_seconds() / 60) / 60)
        
        bday_quantities.append(len(bday_ct))
        nights_quantities.append(len(nights_ct))
        weekend_quantities.append(len(weekend_ct))
        
    data = {
             ('Cycle-Time Averages', 'Bus Hrs'): bday_averages,
             ('Cycle-Time Averages', 'Nights'): nights_averages,
             ('Cycle-Time Averages', 'Weekend'): weekend_averages,
             ('Quantities', 'Bus Hrs'): bday_quantities,
             ('Quantities', 'Nights'): nights_quantities,
             ('Quantities', 'Weekend'): weekend_quantities
            }
        
    
    new_df = pd.DataFrame(data, index=months)
    new_df.name = "Hours of Operation"
    return new_df


def monthly_alert_SLAs(alerts):
    # input - dataframe of alerts
    
    months = alerts.index.get_level_values('month').unique()
    
    quantities = []
    bh_cycletime = []
    total_cycletime = []
    for month in months:
        bh_alert_ct = businessHourCycleTimes(alerts.loc[[month],['disposition_time', 'insert_date']]) #alerts_BH.loc[month, 'disposition_time'] - alerts_BH.loc[month, 'insert_date']
        alert_ct = alerts.loc[month, 'disposition_time'] - alerts.loc[month, 'insert_date'] 
        quantities.append(len(alerts.loc[month]))
        
        if isinstance(bh_alert_ct, pd.Timedelta):
            bh_alert_ct = pd.Series(data=bh_alert_ct)
        if isinstance(alert_ct, pd.Timedelta):
            alert_ct = pd.Series(data=alert_ct)
        bh_cycletime.append(((bh_alert_ct.mean()).total_seconds() /60 ) /60)
        total_cycletime.append(((alert_ct.mean()).total_seconds() /60 ) /60)
    
    data = {
             'Business Hour cycle time': bh_cycletime,
             'Total Cycle time': total_cycletime,
             'Quantity': quantities
           }

    result = pd.DataFrame(data, index=months)
    result.name = "Average Alert Cycle Times"
    return result


def add_email_alert_counts_per_event(events):

    # given event id and company name ~ get alert count per company
    alrt_cnt_company = """SELECT 
        COUNT(DISTINCT event_mapping.alert_id) as 'alert_count' 
        FROM event_mapping 
        JOIN alerts 
            ON alerts.id=event_mapping.alert_id 
        LEFT JOIN company 
            ON company.id=alerts.company_id 
        WHERE 
        event_mapping.event_id={} AND company.name='{}'"""

    # given event id and company name ~ get count of emails based on 
    # alerts with message_id observables and smart counting
    msg_id_query = """SELECT
                a.id, a.alert_type, o.value 
            FROM
                observables o
                JOIN observable_mapping om ON om.observable_id = o.id
                JOIN alerts a ON a.id = om.alert_id
                JOIN event_mapping em ON em.alert_id=a.id
                JOIN company c ON c.id = a.company_id
            WHERE
                o.type = 'message_id'
                AND em.event_id={}
                AND a.alert_type!='o365'
                AND c.name = '{}'"""


    email_counts = []
    for event in events.itertuples():
        if ',' in event.Company:
            companies = event.Company.split(', ')
            new_AlertCnt = emailCount = ""
            for company in companies:
                with get_db_connection() as db:
                    companyAlerts = pd.read_sql_query(alrt_cnt_company.format(event.id, company),db)
                    emailAlerts = pd.read_sql_query(msg_id_query.format(event.id, company),db)
                new_AlertCnt += str(int(companyAlerts.alert_count.values))+","

                # all mailbox alerts will be unique phish
                mailbox_phish = emailAlerts.loc[emailAlerts.alert_type=='mailbox']
                mailbox_phish_count = len(mailbox_phish)
                unique_phish = list(set(mailbox_phish.value.values))
                # remove mailbox alerts and leave any other alerts with a message_id observable
                emailAlerts = emailAlerts[emailAlerts.alert_type!='mailbox']
                for alert in emailAlerts.itertuples():
                    if alert.value not in unique_phish:
                        unique_phish.append(alert.value)
                        mailbox_phish_count += 1
                emailCount += str(mailbox_phish_count)+","

            events.loc[events.id == event.id, '# Alerts'] = new_AlertCnt[:-1]
            email_counts.append(emailCount[:-1])
        else:
            with get_db_connection() as db:
                emailAlerts = pd.read_sql_query(msg_id_query.format(event.id, event.Company),db)
                companyAlerts = pd.read_sql_query(alrt_cnt_company.format(event.id, event.Company),db)

            alertCnt = int(companyAlerts.alert_count.values)
            total_alerts = int(events.loc[events.id == event.id, '# Alerts'].values)
            if alertCnt != total_alerts: # multi-company event, but user filtered by company
                # update alert column to only alerts associated to the company
                events.loc[events.id == event.id, '# Alerts'] = alertCnt

            # all mailbox alerts will be unique phish
            mailbox_phish = emailAlerts.loc[emailAlerts.alert_type=='mailbox']
            mailbox_phish_count = len(mailbox_phish)
            unique_phish = list(set(mailbox_phish.value.values))
            # remove mailbox alerts and leave any other alerts with a message_id observable
            emailAlerts = emailAlerts[emailAlerts.alert_type!='mailbox'] 
            for alert in emailAlerts.itertuples():
                if alert.value not in unique_phish:
                    unique_phish.append(alert.value)
                    mailbox_phish_count += 1
            email_counts.append(mailbox_phish_count)
            
    events['# Emails'] = email_counts


def generate_intel_tables():
    mongo_uri = saq.CONFIG.get("crits", "mongodb_uri")
    mongo_host = mongo_uri[mongo_uri.find('crits'):mongo_uri.rfind(':')]
    mongo_port = int(mongo_uri[mongo_uri.rfind(':')+1:])
    client = MongoClient(mongo_host, mongo_port)
    crits = client.crits

    #+ amount of indicators per source
    intel_sources = crits.source_access.distinct("name")
    source_counts = {}
    for source in intel_sources:
        source_counts[source] = crits.indicators.find( { 'source.name': source }).count()
    source_cnt_df = pd.DataFrame.from_dict(source_counts, orient='index')
    source_cnt_df.columns = ['count']
    source_cnt_df.name = "Count of Indicators by Intel Sources"
    source_cnt_df.sort_index(inplace=True)

    # amount of indicators per status
    indicator_statuses = crits.indicators.distinct("status")
    status_counts = []
    test = {}
    for status in indicator_statuses:
        test[status] = crits.indicators.find( { 'status': status }).count()
        status_counts.append( test[status] )
    lookscount = pd.DataFrame.from_dict(test, orient='index')
    lookscount.columns = ['count']
    # put results in dataframe row
    status_cnt_df = pd.DataFrame(data=[status_counts], columns=indicator_statuses)
    status_cnt_df.name = "Count of Indicators by Status"
    status_cnt_df.rename(index={0: "Count"}, inplace=True)

    client.close()
    return source_cnt_df, status_cnt_df 

@analysis.route('/metrics', methods=['GET', 'POST'])
@login_required
def metrics():

    # object representations of the filters to define types and value verification routines
    # this later gets augmented with the dynamic filters
    filters = {
        FILTER_TXT_DATERANGE: SearchFilter('daterange', FILTER_TYPE_TEXT, '')
    }

    # initialize filter state (passed to the view to set up the form controls)
    filter_state = {filters[f].name: filters[f].state for f in filters}

    target_companies = [] # of tuple(id, name)
    with get_db_connection() as dbcon:
        c = dbcon.cursor()
        c.execute("SELECT `id`, `name` FROM company WHERE `name` != 'legacy' ORDER BY name")
        for row in c:
            target_companies.append(row)

    alert_df = dispo_stats_df = HOP_df = sla_df = incidents = events = pd.DataFrame()
    months = query = company_id = daterange = post_bool = download_results = None
    selected_companies = [] 
    metric_actions = tables = []
    if request.method == "POST" and request.form['daterange']:
        post_bool = True
        daterange = request.form['daterange']
        metric_actions = request.form.getlist('metric_actions')

        company_ids = request.form.getlist('companies')
        company_ids = [ int(x) for x in company_ids ]
        company_dict = dict(target_companies)
        selected_companies = [company_dict[int(cid)] for cid in company_ids ]

        if 'download_results' in request.form:
           download_results = True

        try:
            daterange_start, daterange_end = daterange.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M:%S')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M:%S')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)
            
        query = """SELECT DATE_FORMAT(insert_date, '%%Y%%m') AS month, insert_date, disposition,
            disposition_time, owner_id, owner_time FROM alerts
            WHERE insert_date BETWEEN %s AND %s AND alert_type!='faqueue'
            AND alert_type!='dlp - internal threat' AND alert_type!='dlp-exit-alert' 
            AND disposition IS NOT NULL {}{}"""

        query = query.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company_id=%s' for x in company_ids]) +')' if company_ids else '')

        with get_db_connection() as db:
            params = [daterange_start.strftime('%Y-%m-%d %H:%M:%S'),
                      daterange_end.strftime('%Y-%m-%d %H:%M:%S')]
            params.extend(company_ids)
            alert_df = pd.read_sql_query(query, db, params=params)

        # go ahead and drop the dispositions we don't care about
        alert_df = alert_df[alert_df.disposition != 'UNKNOWN']
        alert_df = alert_df[alert_df.disposition != 'IGNORE']
        alert_df = alert_df[alert_df.disposition != 'REVIEWED']

        # First, alert quantities by disposition per month
        alert_df.set_index('month', inplace=True)
        months = alert_df.index.get_level_values('month').unique()
        
        # if March 2015 alerts in our results then manually insert alert 
        # for https://wiki.local/display/integral/20150309+ctbCryptoLocker
        # No alert was ever put into ACE for this event
        if '201503' in months:
            insert_date = datetime.datetime(year=2015, month=3, day=9, hour=10, minute=12, second=8)
            #Alert Dwell Time was 4hr, 15mins according to wiki
            disposition_time = insert_date + datetime.timedelta(hours=4, minutes=15)
            ctbCryptoLocker = pd.DataFrame({ 'insert_date' : insert_date,
                                             'disposition' : 'DAMAGE',
                                             'disposition_time' : disposition_time,
                                             'owner_id' : 4.0,
                                             'owner_time' : insert_date},
                                             index=['201503'])
            alert_df = pd.concat([alert_df, ctbCryptoLocker])

        # generate and store our tables
        if 'alert_quan' in metric_actions:
            dispo_stats_df = statistic_by_dispo(alert_df, 'Quantity', False)
            if not dispo_stats_df.empty:
                tables.append(dispo_stats_df)
            # leaving this table here, for now
            CT_stats_df = statistic_by_dispo(alert_df, 'Cycle-Time', True)
            if not CT_stats_df.empty:
                tables.append(CT_stats_df)

        if 'HoP' in metric_actions:
            HOP_df = Hours_of_Operation(alert_df.copy())
            if not HOP_df.empty:
                tables.append(HOP_df)

        if 'cycle_time' in metric_actions:
            sla_df = monthly_alert_SLAs(alert_df.copy())
            if not sla_df.empty:
                tables.append(sla_df)

        # Make incident and email event tables
        event_query = """SELECT 
                events.id, 
                events.creation_date as 'Date', events.name as 'Event', 
                GROUP_CONCAT(DISTINCT malware.name SEPARATOR ', ') as 'Malware', 
                GROUP_CONCAT(DISTINCT IFNULL(malware_threat_mapping.type, 'UNKNOWN') SEPARATOR ', ') 
                    as 'Threat', alerts.disposition as 'Disposition', 
                events.vector as 'Delivery Vector', 
                events.prevention_tool as 'Prevention', 
                GROUP_CONCAT(DISTINCT company.name SEPARATOR ', ') as 'Company', 
                count(DISTINCT event_mapping.alert_id) as '# Alerts' 
            FROM events 
                JOIN event_mapping 
                    ON events.id=event_mapping.event_id 
                JOIN malware_mapping 
                    ON events.id=malware_mapping.event_id 
                JOIN malware 
                    ON malware.id=malware_mapping.malware_id 
                JOIN company_mapping 
                    ON events.id=company_mapping.event_id 
                JOIN company 
                    ON company.id=company_mapping.company_id 
                LEFT JOIN malware_threat_mapping 
                    ON malware.id=malware_threat_mapping.malware_id 
                JOIN alerts 
                    ON alerts.id=event_mapping.alert_id 
            WHERE 
                events.status='CLOSED' AND events.creation_date 
                BETWEEN %s AND %s {}{}
            GROUP BY events.name, events.creation_date, event_mapping.event_id 
            ORDER BY events.creation_date"""

        event_query = event_query.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company.name=%s' for company in selected_companies]) +') ' if company_ids else '')

        with get_db_connection() as db:
            params = [daterange_start.strftime('%Y-%m-%d %H:%M:%S'),
                      daterange_end.strftime('%Y-%m-%d %H:%M:%S')]
            params.extend(selected_companies)
            events = pd.read_sql_query(event_query, db, params=params)

        events.set_index('Date', inplace=True)

        # make incident table from events
        if 'incidents' in metric_actions:
            incidents = events[
                (events.Disposition == 'INSTALLATION') | ( events.Disposition == 'EXPLOITATION') |
                (events.Disposition == 'COMMAND_AND_CONTROL') | (events.Disposition == 'EXFIL') |
                (events.Disposition == 'DAMAGE')]
            incidents.drop(columns=['id'], inplace=True)
            incidents.name = "Incidents"
            if not incidents.empty:
                tables.append(incidents)
 
        # make email event table
        if 'events' in metric_actions:
            add_email_alert_counts_per_event(events) # events df  altered inplace
            events.drop(columns=['id'], inplace=True)
            # email_events = events[(events['Delivery Vector'] == 'corporate email')] 
            # email_events.name = "Email Events"
            events.name = "Events"
            if not events.empty:
                tables.append(events)

        # generate CRITS indicator intel tables
        if 'indicator_intel' in metric_actions:
            indicator_source_table, indicator_status_table = generate_intel_tables()
            tables.append(indicator_source_table)
            tables.append(indicator_status_table) 

    if download_results:
        outBytes = io.BytesIO()
        writer = pd.ExcelWriter(outBytes)
        for table in tables:
            table.to_excel(writer, table.name)
        writer.close()
        filename = company_name+"metrics.xlsx" if company_name else "metrics.xlsx"
        output = make_response(outBytes.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename="+filename
        output.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return output

    return render_template(
        'analysis/metrics.html',
        filter_state=filter_state,
        target_companies=target_companies,
        selected_companies=selected_companies,
        tables=tables,
        post_bool=post_bool,
        metric_actions=metric_actions,
        daterange=daterange)


@analysis.route('/events', methods=['GET', 'POST'])
@login_required
def events():
    filters = {
        'filter_event_open': SearchFilter('filter_event_open', FILTER_TYPE_CHECKBOX, True),
        'event_daterange': SearchFilter('event_daterange', FILTER_TYPE_TEXT, ''),
        'filter_event_type': SearchFilter('filter_event_type', FILTER_TYPE_SELECT, 'ANY'),
        'filter_event_vector': SearchFilter('filter_event_vector', FILTER_TYPE_SELECT, 'ANY'),
        'filter_event_prevention_tool': SearchFilter('filter_event_prevention_tool', FILTER_TYPE_SELECT, 'ANY'),
    }

    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    for mal in malware:
        key = 'malz_{}'.format(mal.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    companies = db.session.query(Company).order_by(Company.name.asc()).all()
    for company in companies:
        key = 'company_{}'.format(company.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()
    for campaign in campaigns:
        key = 'campaign_{}'.format(campaign.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    reset_filter = ('reset-filters' in request.form) or ('reset-filters' in request.args)
    if reset_filter:
        for filter_item in filters.values():
            filter_item.reset()

    filter_state = {filters[f].name: filters[f].state for f in filters}

    for filter_name in filters.keys():
        form_value = filters[filter_name].form_value
        if form_value is not None:
            session[filter_name] = form_value
        elif filter_name in session:
            del session[filter_name]

    query = db.session.query(Event)
    if filters['filter_event_open'].value:
        query = query.filter(Event.status == 'OPEN')
    if filters['event_daterange'].value != '':
        try:
            daterange_start, daterange_end = filters['event_daterange'].value.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)
        query = query.filter(and_(Event.creation_date >= daterange_start, Event.creation_date <= daterange_end))
    if filters['filter_event_type'].value != 'ANY':
        query = query.filter(Event.type == filters['filter_event_type'].value)
    if filters['filter_event_vector'].value != 'ANY':
        query = query.filter(Event.vector == filters['filter_event_vector'].value)
    if filters['filter_event_prevention_tool'].value != 'ANY':
        query = query.filter(Event.prevention_tool == filters['filter_event_prevention_tool'].value)

    mal_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('malz_') and filters[filter_name].value:
            mal_id = int(filter_name[len('malz_'):])
            mal_filters.append(MalwareMapping.malware_id == mal_id)
    if len(mal_filters) > 0:
        query = query.filter(Event.malware.any(or_(*mal_filters)))

    company_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('company_') and filters[filter_name].value:
            company_id = int(filter_name[len('company_'):])
            company_filters.append(CompanyMapping.company_id == company_id)
    if len(company_filters) > 0:
        query = query.filter(Event.companies.any(or_(*company_filters)))

    campaign_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('campaign_') and filters[filter_name].value:
            campaign_id = int(filter_name[len('campaign_'):])
            campaign_filters.append(Event.campaign_id == campaign_id)
    if len(campaign_filters) > 0:
        query = query.filter(or_(*campaign_filters))

    if 'event_sort_by' not in session:
        session['event_sort_by'] = 'date'
        session['event_sort_dir'] = True

    sort_field = request.form.get('sort_field', None)
    if sort_field is not None:
        if session['event_sort_by'] == sort_field:
            session['event_sort_dir'] = not session['event_sort_dir']
        else:
            session['event_sort_by'] = sort_field
            session['event_sort_dir'] = True

    if session['event_sort_by'] == 'date':
        if session['event_sort_dir']:
            query = query.order_by(Event.creation_date.desc())
        else:
            query = query.order_by(Event.creation_date.asc())
    elif session['event_sort_by'] == 'event':
        if session['event_sort_dir']:
            query = query.order_by(Event.type.desc(), Event.vector.desc(), Event.name.desc())
        else:
            query = query.order_by(Event.type.asc(), Event.vector.asc(), Event.name.asc())
    elif session['event_sort_by'] == 'campaign':
        if session['event_sort_dir']:
            query = query.order_by(Event.campaign.desc())
        else:
            query = query.order_by(Event.campaign.asc())
    elif session['event_sort_by'] == 'prevention':
        if session['event_sort_dir']:
            query = query.order_by(Event.prevention_tool.desc())
        else:
            query = query.order_by(Event.prevention_tool.asc())
    elif session['event_sort_by'] == 'remediation':
        if session['event_sort_dir']:
            query = query.order_by(Event.remediation.desc())
        else:
            query = query.order_by(Event.remediation.asc())
    elif session['event_sort_by'] == 'status':
        if session['event_sort_dir']:
            query = query.order_by(Event.status.desc())
        else:
            query = query.order_by(Event.status.asc())

    events = query.all()

    if session['event_sort_by'] == 'disposition':
        events = sorted(events, key=lambda event: event.disposition_rank, reverse=session['event_sort_dir'])

    return render_template('analysis/events.html', events=events, filter_state=filter_state, malware=malware, companies=companies, campaigns=campaigns, sort_by=session['event_sort_by'], sort_dir=session['event_sort_dir'])

@analysis.route('/event_alerts', methods=['GET'])
@login_required
def event_alerts():
    event_id = request.args['event_id']
    events = db.session.query(Event).filter(Event.id == event_id).all()
    event = events[0]
    event_mappings = db.session.query(EventMapping).filter(EventMapping.event_id == event_id).all()
    return render_template('analysis/event_alerts.html', event_mappings=event_mappings, event=event)

@analysis.route('/remove_alerts', methods=['POST'])
@login_required
def remove_alerts():
    # get list of event mappings to delete
    mappings = request.form['event_mappings'].split(',')

    # connect to db
    with get_db_connection() as db:
        c = db.cursor()

        # delete all mappings
        for mapping in mappings:
            event_id, alert_id = mapping.split("_")
            c.execute("""DELETE FROM event_mapping WHERE event_id=%s AND alert_id=%s""", (event_id, alert_id))

        # commit changes to databse
        db.commit()

    # return to events page
    return redirect(url_for('analysis.events'))

@analysis.route('/edit_event_modal', methods=['GET'])
@login_required
def edit_event_modal():
    event_id = request.args['event_id']
    events = db.session.query(Event).filter(Event.id == event_id).all()
    event = events[0]
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()
    return render_template('analysis/event_edit.html', event=event, malware=malware, campaigns=campaigns)

@analysis.route('/edit_event', methods=['POST'])
@login_required
def edit_event():
    event_id = request.form.get('event_id', None)
    event_type = request.form.get('event_type', None)
    event_vector = request.form.get('event_vector', None)
    event_prevention = request.form.get('event_prevention', None)
    event_comment = request.form.get('event_comment', None)
    event_status = request.form.get('event_status', None)
    event_remediation = request.form.get('event_remediation', None)
    event_disposition = request.form.get('event_disposition', None)
    threats = request.form.getlist('threats', None)
    campaign_id = request.form.get('campaign_id', None)
    new_campaign = request.form.get('new_campaign', None)

    with get_db_connection() as db:
        c = db.cursor()

        if (campaign_id == "NEW"):
            c.execute("""SELECT id FROM campaign WHERE name = %s""", (new_campaign))
            if c.rowcount > 0:
                result = c.fetchone()
                campaign_id = result[0]
            else:
                c.execute("""INSERT INTO campaign (name) VALUES (%s)""", (new_campaign))
                db.commit()
                c.execute("""SELECT LAST_INSERT_ID()""")
                result = c.fetchone()
                campaign_id = result[0]

        c.execute("""UPDATE events SET status=%s, remediation=%s, type=%s, vector=%s, prevention_tool=%s, comment=%s, campaign_id=%s WHERE id=%s""",
                (event_status, event_remediation, event_type, event_vector, event_prevention, event_comment, campaign_id, event_id))
        db.commit()

        c.execute("""DELETE FROM malware_mapping WHERE event_id=%s""", (event_id))
        db.commit()

        for key in request.form.keys():
            if key.startswith("malware_selection_"):
                index = key[18:]
                mal_id = request.form.get("malware_selection_{}".format(index))

                if mal_id == "NEW":
                    mal_name = request.form.get("mal_name_{}".format(index))
                    c.execute("""SELECT id FROM malware WHERE name = %s""", (mal_name))
                    if c.rowcount > 0:
                        result = c.fetchone()
                        mal_id = result[0]
                    else:
                        c.execute("""INSERT INTO malware (name) VALUES (%s)""", (mal_name))
                        db.commit()
                        c.execute("""SELECT LAST_INSERT_ID()""")
                        result = c.fetchone()
                        mal_id = result[0]

                    threats = request.form.getlist("threats_{}".format(index), None)
                    for threat in threats:
                        c.execute("""INSERT IGNORE INTO malware_threat_mapping (malware_id,type) VALUES (%s,%s)""", (mal_id, threat))
                    db.commit()

                c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""", (event_id, mal_id))
                db.commit()

        c.execute("""SELECT uuid FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s""", (event_id))
        rows = c.fetchall()

        alert_uuids = []
        for row in rows:
            alert_uuids.append(row[0])

        try:
            set_dispositions(alert_uuids, event_disposition)
        except Exception as e:
            flash("unable to set disposition (review error logs)")
            logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
            report_exception()

    return redirect(url_for('analysis.events'))

@analysis.route('/observables', methods=['GET'])
@login_required
def observables():
    # get the alert we're currently looking at
    alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == request.args['alert_uuid']).one()

    # get all the observable IDs for the alerts we currently have to display
    observables = db.session.query(Observable).join(ObservableMapping,
                                                    Observable.id == ObservableMapping.observable_id).filter(
                                                    ObservableMapping.alert_id == alert.id).all()

    # key = Observable.id, value = count
    observable_count = {}

    # for each observable, get a count of the # of times we've seen this observable (ever)
    if len(observables) > 0:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = """
                SELECT 
                    o.id,
                    count(*)
                FROM 
                    observables o JOIN observable_mapping om ON om.observable_id = o.id 
                WHERE 
                    om.observable_id IN ( {0} )
                GROUP BY 
                    o.id""".format(",".join([str(o.id) for o in observables]))

            if saq.CONFIG['global'].getboolean('log_sql'):
                logging.debug("CUSTOM SQL: {0}".format(sql))

            cursor.execute(sql)

            for row in cursor:
                # we record in a dictionary that matches the observable "id" to the count
                observable_count[row[0]] = row[1]
                logging.debug("recorded observable count of {0} for {1}".format(row[1], row[0]))

    data = {}  # key = observable_type
    for observable in observables:
        if observable.type not in data:
            data[observable.type] = []
        data[observable.type].append(observable)
        observable.count = observable_count[observable.id]

    # sort the types
    types = [key for key in data.keys()]
    types.sort()
    # and then sort the observables per type
    for _type in types:
        data[_type].sort(key=attrgetter('value'))

    return render_template(
        'analysis/load_observables.html',
        data=data,
        types=types)

@analysis.route('/toggle_prune', methods=['POST', 'GET'])
@login_required
def toggle_prune():
    if 'prune' not in session:
        session['prune'] = DEFAULT_PRUNE

    session['prune'] = not session['prune']
    logging.debug("prune set to {} for {}".format(session['prune'], current_user))

    alert_uuid = None
    if 'alert_uuid' in request.values:
        alert_uuid = request.values['alert_uuid']

    return redirect(url_for('analysis.index', alert_uuid=alert_uuid))

@analysis.route('/analysis', methods=['GET', 'POST'])
@login_required
def index():
    alert = None

    # the "direct" parameter is used to specify a specific alert to load
    alert = get_current_alert()

    if alert is None:
        return redirect(url_for('analysis.manage'))

    try:
        alert.load()
    except Exception as e:
        flash("unable to load alert {0}: {1}".format(alert, str(e)))
        report_exception()
        return redirect(url_for('main.index'))

    observable_uuid = None
    module_path = None

    # by default we're looking at the initial alert
    # the user can navigate to look at the analysis performed on observables in the alert
    # did the user change their view?
    if 'observable_uuid' in request.values:
        observable_uuid = request.values['observable_uuid']

    if 'module_path' in request.values:
        module_path = request.values['module_path']

    # what observable are we currently looking at?
    observable = None
    if observable_uuid is not None:
        observable = alert.observable_store[observable_uuid]

    # get the analysis to view
    analysis = alert  # by default it's the alert

    if module_path is not None and observable is not None:
        analysis = observable.analysis[module_path]

    # load user comments for the alert
    try:
        alert.comments = db.session.query(Comment).filter(Comment.uuid == alert.uuid).all()
    except Exception as e:
        logging.error("could not load comments for alert: {}".format(e))

    # get all the tags for the alert
    all_tags = alert.all_tags

    # sort the tags by score
    alert_tags = filter_special_tags(sorted(all_tags, key=lambda x: (-x.score, x.name.lower())))
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] == 'special']
    alert_tags = [tag for tag in alert_tags if tag.name not in special_tag_names]

    # compute the display tree
    class TreeNode(object):
        def __init__(self, obj, parent=None):
            # unique ID that can be used in the GUI to track nodes
            self.uuid = str(uuid.uuid4())
            # Analysis or Observable object
            self.obj = obj
            self.parent = parent
            self.children = []
            # points to an already existing TreeNode for the analysis of this Observable
            self.reference_node = None
            # nodes are not visible unless something along the path has a "detection point"
            self.visible = False
            # a list of nodes that refer to this node
            self.referents = []

        def add_child(self, child):
            assert isinstance(child, TreeNode)
            self.children.append(child)
            child.parent = self

        def remove_child(self, child):
            assert isinstance(child, TreeNode)
            self.children.remove(child)
            child.parent = self

        def refer_to(self, node):
            self.reference_node = node
            node.add_referent(self)

        def add_referent(self, node):
            self.referents.append(node)

        def walk(self, callback):
            callback(self)
            for node in self.children:
                node.walk(callback)

        def __str__(self):
            return "TreeNode({}, {}, {})".format(self.obj, self.reference_node, self.visible)

    def _recurse(current_node, node_tracker=None):
        assert isinstance(current_node, TreeNode)
        assert isinstance(current_node.obj, saq.analysis.Analysis)
        assert node_tracker is None or isinstance(node_tracker, dict)

        analysis = current_node.obj
        if node_tracker is None:
            node_tracker = {}

        for observable in analysis.observables:
            child_node = TreeNode(observable)
            current_node.add_child(child_node)

            # if the observable is already in the current tree then we want to display a link to the existing analysis display
            if observable.id in node_tracker:
                child_node.refer_to(node_tracker[observable.id])
                continue

            node_tracker[observable.id] = child_node

            for observable_analysis in [a for a in observable.all_analysis if a]:
                observable_analysis_node = TreeNode(observable_analysis)
                child_node.add_child(observable_analysis_node)
                _recurse(observable_analysis_node, node_tracker)

    def _sort(node):
        assert isinstance(node, TreeNode)

        node.children = sorted(node.children, key=lambda x: x.obj)
        for node in node.children:
            _sort(node)

    def _prune(node, current_path=[]):
        assert isinstance(node, TreeNode)
        current_path.append(node)

        if node.children:
            for child in node.children:
                _prune(child, current_path)
        else:
            # all nodes are visible up to nodes that have "detection points" or tags
            # nodes tagged as "high_fp_frequency" are not visible
            update_index = 0
            index = 0
            while index < len(current_path):
                _has_detection_points = current_path[index].obj.has_detection_points()
                _has_tags = len(current_path[index].obj.tags) > 0
                _always_visible = current_path[index].obj.always_visible()
                _high_fp_freq = current_path[index].obj.has_tag('high_fp_frequency')

                if _has_detection_points or _has_tags or _always_visible:
                    # if we have tags but no detection points and we also have the high_fp_freq tag then we hide that
                    if _high_fp_freq and not ( _has_detection_points or _always_visible ):
                        index += 1
                        continue

                    while update_index <= index:
                        current_path[update_index].visible = True
                        update_index += 1

                index += 1

        current_path.pop()

    def _resolve_references(node):
        # in the case were we have a visible node that is refering to a node that is NOT visible
        # then we need to use the data of the refering node
        def _resolve(node):
            if node.visible and node.reference_node and not node.reference_node.visible:
                node.children = node.reference_node.children
                for referent in node.reference_node.referents:
                    referent.reference_node = node

                node.reference_node = None

        node.walk(_resolve)

    # are we viewing all analysis?
    if 'prune' not in session:
        session['prune'] = True

    # we only display the tree if we're looking at the alert
    display_tree = None
    if alert is analysis:
        display_tree = TreeNode(analysis)
        _recurse(display_tree)
        _sort(display_tree)
        if session['prune']:
            _prune(display_tree)
            # root node is visible
            display_tree.visible = True
            # and all observables in the root node
            for child in display_tree.children:
                child.visible = True
            _resolve_references(display_tree)

    # go ahead and get the list of all the users, we'll end up using it
    all_users = db.session.query(User).order_by('username').all()

    open_events = db.session.query(Event).filter(Event.status == 'OPEN').order_by(Event.creation_date.desc()).all()
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    companies = db.session.query(Company).order_by(Company.name.asc()).all()
    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()

    # all the profile points True for this alert
    profile_points = [ppm.profile_point for ppm in alert.profile_point_mappings]

    # all the tags for all these profile points
    pp_tags = set()
    pp_scores = {} # key = tag name, value = # of times
    for profile_point in profile_points:
        for pptm in profile_point.tag_mappings:
            pp_tags.add(pptm.tag.name)
            if pptm.tag.name not in pp_scores:
                pp_scores[pptm.tag.name] = 0
            pp_scores[pptm.tag.name] += 1
    pp_tags = list(pp_tags)

    # for each profile (tag), we want the full list of all profile points
    pp_full = {} # key = profile (tag name), value = { "yes": [list of profile points], "no": [list of profile points] }
    # where "yes" is the list of profile points that are True for this alert
    # and "no" are the ones that are NOT true

    for pp_tag in pp_tags:
        pp_full[pp_tag] = { 'yes': [], 'no': [] }
        for profile_point in db.session.query(ProfilePoint).\
                                       join(ProfilePointTagMapping).\
                                       join(Tag).\
                                       filter(Tag.name == pp_tag):

            # is this in our list of profile points for this alert?
            if profile_point in profile_points:
                pp_full[pp_tag]['yes'].append(profile_point)
            else:
                pp_full[pp_tag]['no'].append(profile_point)

    # get the remediation history for any message_ids in this alert
    email_remediations = []
    message_ids = [o.value for o in alert.get_observables_by_type(F_MESSAGE_ID)]
    if message_ids:
        for source in get_email_archive_sections():
            email_remediations.extend(search_archive(source, message_ids,
                                      excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(',')).values())

    return render_template('analysis/index.html',
                           alert=alert,
                           alert_tags=alert_tags,
                           observable=observable,
                           analysis=analysis,
                           config=saq.CONFIG,
                           User=User,
                           db=db,
                           current_time=datetime.datetime.now(),
                           observable_types=VALID_OBSERVABLE_TYPES,
                           display_tree=display_tree,
                           prune_display_tree=session['prune'],
                           open_events=open_events,
                           malware=malware,
                           companies=companies,
                           campaigns=campaigns,
                           all_users=all_users,
                           disposition_css_mapping=DISPOSITION_CSS_MAPPING,
                           profile_points=profile_points,
                           pp_tags=pp_tags,
                           pp_counts=get_profile_point_counts(),
                           pp_scores=pp_scores,
                           pp_full=pp_full,
                           email_remediations=email_remediations)

@analysis.route('/file', methods=['GET'])
@login_required
def file():
    date = datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    target_companies = [] # of tuple(id, name)
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT `id`, `name` FROM company WHERE `name` != 'legacy' ORDER BY name")
        for row in c:
            target_companies.append(row)

    return render_template('analysis/analyze_file.html', observable_types=VALID_OBSERVABLE_TYPES, date=date, target_companies=target_companies)

@analysis.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    downloadfile = request.files['file_path']
    comment = request.form.get("comment", "")
    alert_uuid = request.form.get("alert_uuid","")
    if not downloadfile:
        flash("No file specified for upload.")
        return redirect(url_for('analysis.file'))

    file_name = downloadfile.filename
    if not alert_uuid:
        alert = Alert()
        alert.tool = 'Manual File Upload - '+file_name
        alert.tool_instance = socket.gethostname()
        alert.alert_type = 'manual_upload'
        alert.description = 'Manual File upload {0}'.format(file_name)
        alert.event_time = datetime.datetime.now()
        alert.details = {'user': current_user.username, 'comment': comment}

        # XXX database.Alert does not automatically create this
        alert.uuid = str(uuid.uuid4())

        # we use a temporary directory while we process the file
        alert.storage_dir = os.path.join(
            saq.CONFIG['global']['data_dir'],
            alert.uuid[0:3],
            alert.uuid)

        dest_path = os.path.join(SAQ_HOME, alert.storage_dir)
        if not os.path.isdir(dest_path):
            try:
                os.makedirs(dest_path)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(dest_path, str(e)))
                report_exception()
                return

        # XXX fix this!! we should not need to do this
        # we need to do this here so that the proper subdirectories get created
        alert.save()

        if not alert.lock():
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))
    else:
        alert = get_current_alert()
        if not alert.lock():
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        if not alert.load():
            flash("unable to load alert {}".format(alert))
            return redirect(url_for('analysis.index'))
            
    dest_path = os.path.join(SAQ_HOME, alert.storage_dir, os.path.basename(downloadfile.filename))

    try:
        downloadfile.save(dest_path)
    except Exception as e:
        flash("unable to save {} to {}: {}".format(file_name, dest_path, str(e)))
        report_exception()
        return redirect(url_for('analysis.file'))

    alert.add_observable(F_FILE, os.path.relpath(dest_path, start=os.path.join(SAQ_HOME, alert.storage_dir)))
    alert.sync()

    return redirect(url_for('analysis.index', direct=alert.uuid))

@analysis.route('/analyze_alert', methods=['POST'])
@login_required
def analyze_alert():
    alert = get_current_alert()

    try:
        alert.request_correlation()
    except:
        flash("Unable to sync alert")

    return redirect(url_for('analysis.index', direct=alert.uuid))

@analysis.route('/observable_action', methods=['POST'])
@login_required
def observable_action():
    from saq.crits import submit_indicator

    alert = get_current_alert()
    observable_uuid = request.form.get('observable_uuid')
    action_id = request.form.get('action_id')

    logging.debug("alert {} observable {} action {}".format(alert, observable_uuid, action_id))

    if not alert.lock():
        return "Unable to lock alert.", 500
    try:
        if not alert.load():
            return "Unable to load alert.", 500

        observable = alert.observable_store[observable_uuid]

        if action_id == 'mark_as_suspect':
            if not observable.is_suspect:
                observable.is_suspect = True
                alert.sync()
                return "Observable marked as suspect.", 200

        elif action_id == ACTION_UPLOAD_TO_CRITS:
            try:
                indicator_id = submit_indicator(observable)
                if indicator_id is None:
                    return "submission failed", 500

                return indicator_id, 200

            except Exception as e:
                logging.error("unable to submit {} to crits: {}".format(observable, str(e)))
                report_exception()
                return "unable to submit to crits: {}".format(str(e)), 500

        elif action_id == ACTION_COLLECT_FILE:
            try:
                logging.info("user {} added directive {} to {}".format(current_user, DIRECTIVE_COLLECT_FILE, observable))
                observable.add_directive(DIRECTIVE_COLLECT_FILE)
                alert.sync()
                return "File collection requested.", 200
            except Exception as e:
                logging.error("unable to mark observable {} for file collection".format(observable))
                report_exception()
                return "request failed - check logs", 500

        return "invalid action_id", 500

    except Exception as e:
        traceback.print_exc()
        return "Unable to load alert: {}".format(str(e)), 500
    finally:
        alert.unlock()

    return "Action completed. ", 200

@analysis.route('/mark_suspect', methods=['POST'])
@login_required
def mark_suspect():
    alert = get_current_alert()
    observable_uuid = request.form.get("observable_uuid")
    if not alert.lock():
        flash("unable to lock alert")
        return "", 400
    try:
        if not alert.load():
            flash("unable to load alert")
            return "", 400
        observable = alert.observable_store[observable_uuid]
        observable.is_suspect = True
        alert.sync()
    except Exception as e:
        flash("unable to load alert {0}: {1}".format(alert, str(e)))
        traceback.print_exc()
        return "", 400
    finally:
        alert.unlock()

    return url_for("analysis.index", direct=alert.uuid), 200


@analysis.route('/download_archive', methods=['GET'])
@login_required
def download_archive():
    md5 = request.values['md5']

    # look up the details of the entry by md5
    with get_db_connection('email_archive') as db:
        c = db.cursor()
        c.execute("SELECT s.hostname FROM archive a JOIN archive_server s ON a.server_id = s.server_id "
                  "WHERE a.md5 = UNHEX(%s)", (md5,))
        try:
            row = c.fetchone()

            if row is None:
                logging.error("query returned no results for md5 {}".format(md5))
                raise ValueError()

        except Exception as e:
            logging.error("archive md5 {} does not exist".format(md5))
            return "", 400

        hostname = row[0]
        logging.info("got hostname {} for md5 {}".format(hostname, md5))

    root_archive_path = saq.CONFIG['analysis_module_email_archiver']['archive_dir']
    archive_path = os.path.join(root_archive_path, hostname, md5[0:3], '{}.gz.gpg'.format(md5))
    full_path = os.path.join(SAQ_HOME, archive_path)

    if not os.path.exists(full_path):
        logging.error("archive path {} does not exist".format(full_path))
        #flash("archive path {} does not exist".format(archive_path))
        return redirect(url_for('analysis.index'))

    logging.info("user {} downloaded email archive {}".format(current_user, archive_path))
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)

@analysis.route('/image', methods=['GET'])
@login_required
def image():
    alert_uuid = request.values['alert_uuid']
    observable_uuid = request.values['observable_uuid']

    alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
    alert.load()
    _file = alert.get_observable(observable_uuid)

    with open(_file.path, 'rb') as fp:
        result = fp.read()

    response = make_response(result)
    response.headers['Content-Type'] = _file.mime_type
    return response

@analysis.route('/query_message_id', methods=['POST'])
@login_required
def query_message_ids():
    # if we passed a JSON formatted list of alert_uuids then we compute the message_ids from that
    if 'alert_uuids' in request.values:
        alert_uuids = json.loads(request.values['alert_uuids'])
        message_ids = []

        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""SELECT o.value FROM observables o JOIN observable_mapping om ON o.id = om.observable_id
                         JOIN alerts a ON om.alert_id = a.id
                         WHERE o.type = 'message_id' AND a.uuid IN ( {} )""".format(','.join(['%s' for _ in alert_uuids])),
                     tuple(alert_uuids))

            for row in c:
                message_id = row[0].decode(errors='ignore')
                message_ids.append(message_id)
    else:
        # otherwise we expect a JSON formatted list of message_ids
        message_ids = json.loads(request.values['message_ids'])

    import html
    message_ids = [html.unescape(_) for _ in message_ids]

    result = { }
    for source in get_email_archive_sections():
        result[source] = search_archive(source, message_ids, 
                                        excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(','))

        for archive_id in result[source].keys():
            result[source][archive_id] = result[source][archive_id].json

    response = make_response(json.dumps(result))
    response.mime_type = 'application/json'
    return response

class EmailRemediationTarget(object):
    def __init__(self, archive_id=None, message_id=None, recipient=None):
        self.archive_id = archive_id
        self.message_id = message_id
        self.recipient = recipient
        self.result_text = None
        self.result_success = False

    @property
    def key(self):
        return '{}:{}'.format(self.message_id, self.recipient)

    @property
    def json(self):
        return { 
            'archive_id': self.archive_id,
            'message_id': self.message_id,
            'recipient': self.recipient,
            'result_text': self.result_text,
            'result_success': self.result_success }

# the archive_id and config sections are encoded in the name of the form element
# XXX probably a gross security flaw
INPUT_CHECKBOX_REGEX = re.compile(r'^cb_archive_id_([0-9]+)_source_(.+)$')

@analysis.route('/remediate_emails', methods=['POST'])
@login_required
def remediate_emails():

    action = request.values['action']
    assert action in [ 'restore', 'remove' ];

    # generate our list of archive_ids from the list of checkboxes that were checked
    archive_ids = { }
    for key in request.values.keys():
        if key.startswith('cb_archive_id_'):
            m = INPUT_CHECKBOX_REGEX.match(key)
            if m:
                archive_id, source = m.groups()
                if source not in archive_ids:
                    archive_ids[source] = []

                archive_ids[source].append(m.group(1))

    if not archive_ids:
        logging.error("forgot to select one?")
        return "missing selection", 500

    targets = { } # key = archive_id

    for db_name in archive_ids.keys():
        with get_db_connection(db_name) as db:
            c = db.cursor()
            c.execute("""SELECT archive_id, field, value FROM archive_search 
                         WHERE ( field = 'message_id' OR field = 'env_to' ) 
                         AND archive_id IN ( {} )""".format(','.join(['%s' for _ in archive_ids[db_name]])), 
                         tuple(archive_ids[db_name]))

            for row in c:
                archive_id, field, value = row
                if archive_id not in targets:
                    targets[archive_id] = EmailRemediationTarget(archive_id=archive_id)

                if field == 'message_id':
                    targets[archive_id].message_id = value.decode(errors='ignore')

                if field == 'env_to':
                    targets[archive_id].recipient = value.decode(errors='ignore')

    # targets acquired -- perform the remediation or restoration
    params = [ ] # of tuples of ( message-id, email_address )
    for target in targets.values():
        params.append((target.message_id, target.recipient))

    results = []

    from saq.remediation import remediate_emails, unremediate_emails

    try:
        if action == 'remove':
            results = remediate_emails(params)
        elif action == 'restore':
            results = unremediate_emails(params)
    except Exception as e:
        logging.error("unable to perform email remediation action {}: {}".format(action, e))
        for target in targets.values():
            target.result_text = str(e)
            target.result_success = False

    for result in results:
        message_id, recipient, result_code, result_text = result
        for target in targets.values():
            if target.message_id == message_id and target.recipient == recipient:
                target.result_text = '({}) {}'.format(result_code, result_text)
                target.result_success = str(result_code) == '200'

    # record the results in the remediation table
    with get_db_connection() as db:
        c = db.cursor()
        for target in targets.values():
            try:
                c.execute("""INSERT INTO remediation ( `type`, `action`, `user_id`, `key`, 
                                                       `result`, `comment`, `successful` ) 
                             VALUES ( 'email', %s, %s, %s, %s, %s, %s )""", (
                          action,
                          current_user.id,
                          target.message_id + ':' + target.recipient,
                          target.result_text,
                          str(target.archive_id),
                          target.result_success))
            except Exception as e:
                logging.error("unable to insert into remediation table: {}".format(e))

        db.commit()

    # return JSON formatted results
    for key in targets.keys():
        targets[key] = targets[key].json
    
    response = make_response(json.dumps(targets))
    response.mime_type = 'application/json'
    return response
