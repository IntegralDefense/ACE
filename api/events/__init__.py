# vim: sw=4:ts=4:et
#
# ACE API event routines

from .. import db, json_result

from flask import Blueprint, request, abort, Response
from saq.database import Event

events_bp = Blueprint('events', __name__, url_prefix='/events')


@events_bp.route('/open', methods=['GET'])
def get_open_events():
    open_events = db.session.query(Event).filter_by(status='OPEN')
    return json_result([event.json for event in open_events])


@events_bp.route('/<int:event_id>/status', methods=['PUT'])
def update_event_status(event_id):
    event = db.session.query(Event).get(event_id)
    if not event:
        abort(Response("Event ID not found", 404))

    status = request.values.get('status', None)
    if status:
        if status in Event.status.property.columns[0].type.enums:
            event.status = status
            db.session.commit()
            return json_result(event.json)
        else:
            abort(Response("Invalid event status: {}".format(status), 400))

    abort(Response("Must specify event status", 400))
