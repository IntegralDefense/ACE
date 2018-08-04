# vim: sw=4:ts=4:et:cc=120

import logging

import saq
from email.utils import parseaddr
from saq.database import get_db_connection

def normalize_email_address(email_address):
    """Returns a normalized version of email address.  Returns None if the address cannot be normalized."""
    name, address = parseaddr(email_address)
    if address is None:
        return None

    address = address.strip()

    while address and address.startswith('<'):
        address = address[1:]

    while address and address.endswith('>'):
        address = address[:-1]

    if not address:
        return None

    return address.lower()

class EmailArchiveEntry(object):
    def __init__(self, archive_id):
        self.archive_id = archive_id
        self.message_id = None
        self.recipient = None
        self.subject = None
        self.sender = None
        self.remediation_history = []

    @property
    def remediated(self):
        result = False
        for history in self.remediation_history:
            if history['action'] == 'remove' and history['successful']:
                result = True
            if history['action'] == 'restore' and history['successful']:
                result = False

        return result

    @property
    def key(self):
        return '{}:{}'.format(self.message_id, self.recipient)

    @property
    def json(self):
        return {
            'archive_id': self.archive_id,
            'message_id': self.message_id,
            'recipient': self.recipient,
            'sender': self.sender,
            'subject': self.subject,
            'remediated': self.remediated,
            'remediation_history': self.remediation_history }

def get_email_archive_sections():
    """Returns the list of configuration sections for email archives.
       Includes the primary and any secondary."""

    result = []
    if saq.CONFIG['email_archive']['primary']:
        result.append(saq.CONFIG['email_archive']['primary'])
    
    for section in saq.CONFIG.keys():
        if section.startswith('database_email_archive_'):
            if section not in result:
                result.append(section[len('database_'):])

    return result

def search_archive(source, message_ids, excluded_emails=[]):
    """Searches the given email archive (specified by configuration section) for the given message_ids, 
       returns a dictionary[archive_id] = EmailArchiveEntry
       Pass an optional list of email address into excluded_emails to prevent entries with env_to to those email
       addresses from being returned."""

    if not message_ids:
        return {}

    if 'database_{}'.format(source) not in saq.CONFIG:
        logging.error("missing email archive db config section {}".format(source))
        return {}

    _buffer = { }
    with get_db_connection(source) as db:
        c = db.cursor()
        fmt_str = ','.join(['%s' for _ in message_ids])
        c.execute("""SELECT as1.field, as1.value, as1.archive_id FROM archive_search as1 
                     JOIN archive_search as2 ON as1.archive_id = as2.archive_id
                     WHERE as2.field = 'message_id' AND as2.value IN ( {} )""".format(fmt_str), tuple(message_ids))

        for row in c:
            field, value, archive_id = row
            if archive_id not in _buffer:
                _buffer[archive_id] = EmailArchiveEntry(archive_id)

            value = value.decode(errors='ignore')

            if field == 'message_id':
                _buffer[archive_id].message_id = value

            if field == 'env_to':
                _buffer[archive_id].recipient = value

            if field == 'subject':
                _buffer[archive_id].subject = value

            if field == 'body_from':
                _buffer[archive_id].sender = value

    # remove excluded entries
    excluded_archive_ids = []
    for excluded_email in excluded_emails:
        for archive_id in _buffer.keys():
            if _buffer[archive_id].recipient and _buffer[archive_id].recipient.lower() == excluded_email.lower():
                excluded_archive_ids.append(archive_id)
                continue

    if excluded_archive_ids:
        logging.debug("excluding {} entries from archive results matching {}".format(
                      len(excluded_archive_ids), excluded_emails))

    for archive_id in excluded_archive_ids:
        del _buffer[archive_id]

    # build index by key
    index = {}
    for item in _buffer.values():
        if item.message_id and item.recipient:
            index[item.key] = item

    if not index:
        return _buffer

    # get current remediation history for these emails
    with get_db_connection() as db:
        c = db.cursor()

        c.execute("""SELECT r.`id`, r.`type`, r.`action`, r.`insert_date`, 
                            u.`username`, r.`key`, r.`result`, r.`comment`, r.`successful`
                     FROM remediation r JOIN users u ON r.user_id = u.id WHERE r.`key` in ( {} )
                     ORDER BY r.insert_date ASC""".format(','.join(['%s' for _ in index.keys()])), 
                 tuple(index.keys()))

        for row in c:
            _id, _type, _action, _insert_date, _user, _key, _result, _comment, _successful = row
            index[_key].remediation_history.append({
                'id': _id,
                'type': _type,
                'action': _action,
                'insert_date': str(_insert_date),
                'user': _user,
                'key': _key,
                'result': _result,
                'comment': _comment,
                'successful': _successful})

    return _buffer
