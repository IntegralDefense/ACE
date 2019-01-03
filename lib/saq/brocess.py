# vim: sw=4:ts=4:et:cc=120
#
# utility functions to use the brocess databases

import csv
import datetime
import logging
import os.path

import saq
from saq.database import execute_with_retry, use_db
from saq.modules import AnalysisModule
from saq.util import iterate_fqdn_parts

import pymysql

@use_db(name='brocess')
def query_brocess_by_fqdn(fqdn, db, c):
        c.execute('SELECT SUM(numconnections) FROM httplog WHERE host = %s', (fqdn,))
    
        for row in c:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

@use_db(name='brocess')
def query_brocess_by_dest_ipv4(ipv4, db, c):
    c.execute('SELECT SUM(numconnections) FROM connlog WHERE destip = INET_ATON(%s)', (ipv4,))
    
    for row in c:
        count = row[0]
        return int(count) if count is not None else 0

    raise RuntimeError("failed to return a row for sum() query operation !?")

@use_db(name='brocess')
def query_brocess_by_email_conversation(source_email_address, dest_email_address, db, c):
    c.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s AND destination = %s', (
               source_email_address, dest_email_address,))
    
    for row in c:
        count = row[0]
        return int(count) if count is not None else 0

    raise RuntimeError("failed to return a row for sum() query operation !?")

@use_db(name='brocess')
def query_brocess_by_source_email(source_email_address, db, c):
    c.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s', (source_email_address,))
    
    for row in c:
        count = row[0]
        return int(count) if count is not None else 0

    raise RuntimeError("failed to return a row for sum() query operation !?")

@use_db(name='brocess')
def add_httplog(fqdn, db, c):
    for fqdn_part in iterate_fqdn_parts(fqdn):
        execute_with_retry(db, c, """
INSERT INTO httplog ( host, numconnections, firstconnectdate ) 
VALUES ( LOWER(%s), 1, UNIX_TIMESTAMP(NOW()) )
ON DUPLICATE KEY UPDATE numconnections = numconnections + 1""", ( fqdn_part, ))

    db.commit()
