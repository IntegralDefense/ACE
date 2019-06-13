# vim: ts=4:sw=4:et:cc=120

#
# routines dealing with sending notification messages
#

import collections
import datetime
import importlib
import json
import logging
import threading
import time
import uuid

import requests

import saq
from saq.error import report_exception
from saq.constants import *
from saq.database import Message, MessageRouting

from sqlalchemy import and_, func, literal, asc, text
from sqlalchemy.orm import joinedload

def initialize_message_system(*args, **kwargs):
    saq.MESSAGE_SYSTEM = MessageSystem(*args, **kwargs)

def start_message_system(*args, **kwargs):
    saq.MESSAGE_SYSTEM.start(*args, **kwargs)

def stop_message_system(*args, **kwargs):
    saq.MESSAGE_SYSTEM.stop(*args, **kwargs)

def wait_message_system(*args, **kwargs):
    saq.MESSAGE_SYSTEM.wait(*args, **kwargs)

def send_message(*args, **kwargs):
    """Submits the given message to the dispatch system. Returns the saq.database.Message object that was created."""
    if saq.MESSAGE_SYSTEM is None:
        logging.error("send_message was called but no message systems are defined")
        return None

    return saq.MESSAGE_SYSTEM.send_message(*args, **kwargs)

class MessageSystem(object):
    def __init__(self):
        self.routes = collections.defaultdict(set) # key = message_type, value = [(route, destination)]
        self.load_routes()

        self.systems = {} # key = route, value = MessageDispatchSystem
        self.load_dispatch_systems()

    def start(self):
        for system in self.systems.values():
            system.start()

    def stop(self, wait=True):
        for system in self.systems.values():
            system.stop(wait)

    def wait(self):
        for system in self.systems.values():
            system.wait()

    def add_route(self, message_type, route, destination):
        self.routes[message_type].add((route, destination))
        logging.debug(f"added message route message_type {message_type} route {route} destination {destination}")

    def remote_route(self, message_type, route, destination):
        self.routes[message_type].discard((route, destination))
        logging.debug(f"removed message route message_type {message_type} route {route} destination {destination}")

    def send_message(self, content, message_type=None):
        # find which route to send this message to
        # if message_type is None then it is sent to all routes

        if message_type is not None and message_type not in self.routes:
            logging.error(f"unknown message message_type {message_type}")
            return None

        message = Message(content=content)
        saq.db.add(message)
        saq.db.flush()

        routing = set()

        if message_type is None:
            for routing_list in self.routes.values():
                for route, destination in routing_list:
                    routing.add((route, destination))
        else:
            for route, destination in self.routes[message_type]:
                routing.add((route, destination))

        for route, destination in routing:
            message_routing = MessageRouting(message_id=message.id, route=route, destination=destination)
            saq.db.add(message_routing)

        saq.db.commit()
        logging.info("added message {} to {} destinations".format(content[:10], len(routing)))
        return message

    def load_routes(self):
        for message_type, _ in saq.CONFIG['message_routing'].items():
            # TODO I need to switch to YAML for the configuration
            for target in _.split(','):
                route, destination = target.split(':', 1)
                self.add_route(message_type, route, destination)

    # TODO this is the 3rd or 4th time we've written this exact same routine
    def load_dispatch_systems(self):
        for section_name in saq.CONFIG.keys():
            if not section_name.startswith('messaging_system_'):
                continue

            name = section_name[len('messaging_system_'):]

            if not saq.CONFIG[section_name].getboolean('enabled'):
                logging.debug(f"not loading disabled message system {name}")
                continue

            module_name = saq.CONFIG[section_name]['module']
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error(f"unable to import module {module_name}: {e}")
                report_exception()
                continue

            class_name = saq.CONFIG[section_name]['class']
            try:
                _class = getattr(_module, class_name)
            except AttributeError as e:
                logging.error(f"class {class_name} does not exist in module {module_name} "
                              f"for messaging system {name}")
                report_exception()
                continue

            try:
                logging.debug(f"loading messaging system {name}")
                system = _class(config=saq.CONFIG[section_name])
                self.systems[name] = system
            except Exception as e:
                logging.error("unable to load messaging system {name}: {e}")
                report_exception()
                continue

        logging.debug(f"loaded {len(self.systems)} messaging systems")

class ControlledStop(Exception):
    pass

class MessageDispatchSystem(object):
    def __init__(self, config):
        # the config dict (from saq.CONFIG[messaging_system_ROUTE])
        self.config = config
        # the route this system handles
        self.route = config['route']
        # random UUID used to lock messages for dispatching
        self.lock_uuid = str(uuid.uuid4())
        # primary thread for collecting and dispatching messages
        self.thread = None
        # control event to gracefully shut down dispatch system
        self.control_event = None
        # the next time we check for timed out locks
        self.next_lock_timeout_check = None
        # the number of message routing requests we'll lock at a time
        self.batch_size = saq.CONFIG['messaging'].getint('batch_size')
        # used to stop the system once all available messages (for this route) have been processed
        self.controlled_stop = False

    def start(self):
        self.control_event = threading.Event()
        self.thread = threading.Thread(target=self.loop, name=self.name)
        self.thread.start()

    def stop(self, wait=True):
        self.control_event.set()
        if wait:
            self.wait()

    def wait(self):
        logging.info(f"waiting for {self.thread} to stop...")
        self.thread.join()

    def loop(self):
        logging.info(f"started {self.name} for route {self.route}")
        while not self.control_event.is_set():
            try:
                sleep_time = self.execute()
            except ControlledStop:
                logging.info("caught controlled stop")
                break
            except Exception as e:
                logging.error(f"uncaught exception: {e}")
                report_exception()
                sleep_time = 30
            finally:
                try:
                    saq.db.close()
                except Exception as e:
                    logging.error(f"unable to close db connection: {e}")
                    report_exception()

            self.control_event.wait(sleep_time)
                
        logging.info(f"stopped {self.name}")

    def execute(self):
        # we periodically clear any locks that have exceeded lock time
        # this will be messages that were locked but never sent for some reason
        if self.next_lock_timeout_check is None or datetime.datetime.now() >= self.next_lock_timeout_check:
            saq.db.execute(MessageRouting.__table__.update().values(lock=None).where(and_(
                MessageRouting.lock == None,
                func.TIMESTAMPDIFF(text('SECOND'), MessageRouting.lock_time, func.NOW()))))
            saq.db.commit()
            self.next_lock_timeout_check = datetime.datetime.now() + \
                datetime.timedelta(seconds=saq.CONFIG['messaging'].getint('lock_timeout'))

        # get the next message to send
        message_route = saq.db.query(MessageRouting).options(joinedload('message')).filter(
            MessageRouting.lock == self.lock_uuid).order_by(asc(MessageRouting.message_id)).first()

        if message_route is None:
            # if we didn't get one then go ahead and lock the next batch of messages
            target_ids = saq.db.query(MessageRouting.id).filter(and_(
                MessageRouting.lock == None,
                MessageRouting.route == self.route))\
            .order_by(asc(MessageRouting.id))\
            .limit(self.batch_size)\
            .all()

            target_ids = [_[0] for _ in target_ids]

            # did we not find anything?
            if not target_ids:
                if self.controlled_stop:
                    raise ControlledStop()
                else:
                    return 5
                
            saq.db.execute(MessageRouting.__table__.update().values(
                lock=self.lock_uuid,
                lock_time=func.NOW()).where(and_(
                    MessageRouting.id.in_(target_ids),
                    MessageRouting.lock == None,
                    MessageRouting.route == self.route)))

            saq.db.commit()

        # try again to get the next message to send
        message_route = saq.db.query(MessageRouting).options(joinedload('message')).filter(
            MessageRouting.lock == self.lock_uuid).order_by(asc(MessageRouting.message_id)).first()

        # if we still didn't get a message then we wait for a while
        if message_route is None:
            if self.controlled_stop:
                raise ControlledStop()
            else:
                return 5 # TODO make configurable?

        # dispatch the message
        logging.debug(f"dispatching message {message_route.message_id} to route {message_route.route} destination {message_route.destination}")
        self.dispatch(message_route.message, message_route.destination)
        
        # clear this message out
        saq.db.execute(MessageRouting.__table__.delete().where(MessageRouting.id == message_route.id))

        # and finally clear the message if all the routes have completed
        saq.db.execute(Message.__table__.delete().where(Message.id.notin_(saq.db.query(MessageRouting.message_id))))
        saq.db.commit()

        return 0

    @property
    def name(self):
        return type(self).__name__

    def dispatch(self, message, destination):
        raise NotImplementedError()

class NotificationHandler(object):
    def __init__(self):
        pass

    def queue_notification(self, notification_type, message):
        """Queues the given notification into the system to be sent later."""
        raise NotImplementedError()

    def dispatch_notification(self, message):
        """Dispatches the given notification message."""
        raise NotImplementedError()

class NotificationManager(object):
    def __init__(self):
        self.handlers = {} # key = system name, value = NotificationHandler for that notification system

        # primary execution thread
        self.thread = None
        # control event to gracefully shut down the thread
        self.control = None

    def start(self):
        self.control = threading.Event()
        self.thread = threading.Thread(target=self.loop, name="Notification Manager")
        self.thread.deamon = True # we'll still try to shut down gracefully
        self.thread.start()

    def stop(self):
        self.control.set()
        self.thread.join(30)
        if self.thread.is_alive():
            logging.error("unable to stop notification manager after a reasonable time")

    def loop(self):
        logging.debug("starting notification manager")
        while not self.control.is_set():
            try:
                self.execute()
                self.control.wait(1)
            except Exception as e:
                logging.error(str(e))
                report_exception()
                self.control.wait(5)

    def execute(self):
        from saq.database import Message
        attempted_ids = [] # list of Message.id values we want to delete
        for message in saq.db.query(Message).order_by(Message.insert_date.asc()):
            try:
                dispatch(message)
                attempted_ids.append(message.id)
            except Exception as e:
                logging.error(f"unable to dispatch {message}: {e}")

            if control_function is not None and control_function():
                break

        if attempted_ids:
            saq.db.execute(Message.__table__.delete().where(Message.id.in_(attempted_ids)))
            saq.db.commit()

#
# global mapping of notification systems to the handlers that process them
notification_handlers = {} # key = notification system name, value = saq.messaging.NotificationHandler

def initialize_notification_systems():
    pass

def queue_notification(notification_type, message):
    """Queues the given notification."""
    # look up what systems this notification should go to
    try:
        destinations = saq.CONFIG['messaging'][f'notification_type_{notification_type}'].split(',')
    except KeyError:
        logging.error(f"unknown notification type: {notification_type}")
        return False

    for destination in destinations:
        try:
            handler = notification_handlers[system]
        except KeyError:
            logging.error(f"unknown notification system: {destination}")
            return False

        handler.queue_notification(notification_type, message)

def dispatch_ace_alert(alert):
    """Submits the given ACE alert to the configured outbound notification systems."""
    if saq.CONFIG['slack'].getboolean('enabled'):
        try:
            dispatch_slack_ace_alert(alert)
        except Exception as e:
            logging.error(f"unable to dispatch slack ace alert {alert}: {e}")

    return True

def dispatch_slack_ace_alert(alert):
    link = saq.CONFIG['gui']['base_uri'] + "analysis?direct=" + alert.uuid
    message = f'<{link}|[{alert.company_name}] - {alert.description}>'
    return dispatch_slack_message(message)
    
def dispatch_slack_message(message):
    from saq.database import Message
    saq.db.add(Message(type=MESSAGE_TYPE_SLACK, value=json.dumps({'text': message}).encode('utf8', errors='ignore')))
    saq.db.commit()
    return True

def dispatch_messages(control_function=None):
    """Dispatches all messages currently in queue.
       An optional control_function can return True to break out of the loop prematurely."""
    from saq.database import Message
    attempted_ids = [] # list of Message.id values we want to delete
    for message in saq.db.query(Message).order_by(Message.insert_date.asc()):
        try:
            dispatch(message)
            attempted_ids.append(message.id)
        except Exception as e:
            logging.error(f"unable to dispatch {message}: {e}")

        if control_function is not None and control_function():
            break

    if attempted_ids:
        saq.db.execute(Message.__table__.delete().where(Message.id.in_(attempted_ids)))
        saq.db.commit()

def dispatch(message):
    """Dispatches the given saq.database.Message object to whatever notification system it should go to."""
    if message.type == MESSAGE_TYPE_SLACK:
        return dispatch_slack(message)
    else:
        logging.error(f"unknown/unsupported message type {message.type}")
        return False

def dispatch_slack(message):    
    """Dispatches the message to Slack."""
    result = requests.post(saq.CONFIG['slack']['alert_url'],
                      headers={'Content-Type': 'application/json'},
                      data=message.value.decode('utf8', errors='ignore'))

    logging.info(f"dispatched message {message} to slack: {result} {result.text}")
