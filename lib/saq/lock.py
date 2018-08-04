# vim: sw=4:ts=4:et:cc=120

import datetime
import logging
import os
import os.path
import time
import uuid
import multiprocessing

import saq
from saq.error import report_exception, report_condition

local_lock_manager = None
local_lock_sync = None
local_lock_ids = None

def lock_expired(lock_time):
    """Utility function to return True if the given lock_time has expired."""
    assert isinstance(lock_time, datetime.datetime)
    elapsed_time = (datetime.datetime.now() - lock_time).total_seconds()
    minutes, seconds = map(int, saq.CONFIG['global']['lock_timeout'].split(':'))
    return elapsed_time >= (minutes * 60) + seconds

def _atexit_callback():
    if local_lock_manager:
        try:
            logging.info("shutting down local lock manager...")
            local_lock_manager.shutdown()
            logging.info("shut down local lock manager")
        except Exception as e:
            logging.error("unable to shutdown local lock manager: {}".format(e))
            report_exception()

def initialize_locking():
    import atexit

    global local_lock_manager
    global local_lock_sync
    global local_lock_ids

    logging.info("initializing locking")

    # have we already initialized locking?
    if local_lock_manager is not None:
        # then just clear out any existing lock ids
        with local_lock_sync:
            local_lock_ids = local_lock_manager.dict()

        return

    local_lock_manager = multiprocessing.Manager()
    local_lock_sync = local_lock_manager.RLock()
    # key = uuid, value = tuple(custom uuid, datetime.datetime.now().timestamp)
    local_lock_ids = local_lock_manager.dict()

    atexit.register(_atexit_callback)

class LockableObject(object):
    """Base interface for the LockableObject."""

    def lock(self):
        """Locks the object.  Returns True on success, False if object is already locked.  Does not block."""
        raise NotImplementedError()

    def unlock(self):
        """Unlocks a locked object.  Requests to unlock an unlocked object are ignored."""
        raise NotImplementedError()

    def is_locked(self):
        """Returns True if the object is currently locked, False otherwise."""
        raise NotImplementedError()

    def has_current_lock(self):
        """Returns True if this LockableObject is what currently owns the lock."""
        raise NotImplementedError()

    def refresh_lock(self):
        """Refreshes the lock of a locked object.  Locks can expire."""
        raise NotImplementedError()

    def transfer_locks_to(self, dest):
        """Transfers the locks on this LockableObject to another LockableObject."""
        raise NotImplementedError()

    def create_lock_proxy(self):
        """Creates a proxy LockableObject that can be used in place another LockableObject.
        This is intended to be used in cases where serialization is used to transport objects 
        across process boundaries.  This function returns an LockableObject that maintains the 
        properties required to lock the original target object."""
        raise NotImplementedError()

    @property
    def lock_identifier(self):
        """Returns what is the unique id for this lock."""
        raise NotImplementedError()

class LocalLockableObject(LockableObject):
    """Implements locking that is local and supports multiprocessing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the UUID we're using for the lock
        # value of None means we do not currently hold the lock
        self.lock_uuid = None

    @property
    def lock_identifier(self):
        return self.lock_uuid

    def lock(self):
        assert hasattr(self, 'uuid')

        if not self.uuid:
            logging.error("called lock() on {} when uuid was None or empty".format(self))
            return False

        existing_lock_id = None
        existing_lock_time = None

        with local_lock_sync:
            try:
                # get the existing lock
                existing_lock_id, existing_lock_time = local_lock_ids[self.uuid]
                existing_lock_time = datetime.datetime.fromtimestamp(existing_lock_time)

                # if a lock exists, check to see if it has timed out
                if lock_expired(existing_lock_time):
                    logging.warning("detected expired local lock_id {} on {}".format(self.lock_uuid, self.uuid))
                    # if the lock has expired then we act like it's not locked at all
                    existing_lock_id = None
                    existing_lock_time = None
                
            except KeyError:
                pass

            if not existing_lock_id:
                # no lock exists (or has expired) so we lock it now
                self.lock_uuid = str(uuid.uuid4())
                local_lock_ids[self.uuid] = (self.lock_uuid, datetime.datetime.now().timestamp())
                logging.debug("obtained local lock id {} for {}".format(self.lock_uuid, self.uuid))
                return True

        # otherwise we were unable to obtain the lock
        return False
                
    def unlock(self):
        assert hasattr(self, 'uuid')

        self._cleanup()

        if not self.lock_uuid:
            logging.debug("unlock() called on unlocked {}".format(self.uuid))
            return False

        if not self.uuid:
            logging.error("called unlock() on {} when uuid was None or empty".format(self))
            return False

        with local_lock_sync:
            # do we still own the lock?
            try:
                existing_lock_id, existing_lock_time = local_lock_ids[self.uuid]
            except KeyError:
                logging.warning("lock for {} no longer exists (expired?)".format(self.uuid))
                return True
        
            if existing_lock_id != self.lock_uuid:
                logging.warning("lock for {} changed (expired?)".format(self.uuid))
                return True

            # delete the entry
            logging.info("deleting lock {}".format(self.uuid))
            del local_lock_ids[self.uuid]

        logging.debug("release lock {} for {}".format(self.lock_uuid, self))
        self.lock_uuid = None
        return True

    def has_current_lock(self):
        assert hasattr(self, 'uuid')

        if not self.uuid:
            logging.error("called has_current_lock on {} when uuid was None or empty".format(self))
            return False

        return self.lock_uuid is not None

    def is_locked(self):
        assert hasattr(self, 'uuid')

        if not self.uuid:
            logging.error("called is_locked() on {} when uuid was None or empty".format(self))
            return False

        with local_lock_sync:
            try:
                # get the existing lock
                existing_lock_id, existing_lock_time = local_lock_ids[self.uuid]
                existing_lock_time = datetime.datetime.fromtimestamp(existing_lock_time)

                # if a lock exists, check to see if it has timed out
                result = lock_expired(existing_lock_time)
                if lock_expired(existing_lock_time):
                    logging.warning("detected expired local lock_id {} on {}".format(self.lock_uuid, self.uuid))
                    # if the lock has expired then we act like it's not locked at all
                    return False

                return True
                
            except KeyError:
                pass

        return False

    def refresh_lock(self):
        assert hasattr(self, 'uuid')

        if not self.lock_uuid:
            logging.debug("refresh_lock() called on unlocked {}".format(self.uuid))
            return False

        with local_lock_sync:
            # do we still own the lock?
            try:
                existing_lock_id, existing_lock_time = local_lock_ids[self.uuid]
            except KeyError:
                logging.warning("lock_id {} for for {} no longer exists (expired?)".format(self.lock_uuid, self.uuid))
                return False
        
            if existing_lock_id != self.lock_uuid:
                logging.warning("lock for {} changed (expired?)".format(self.uuid))
                return False

            # update the entry
            local_lock_ids[self.uuid] = ( self.lock_uuid, datetime.datetime.now().timestamp() )
            return True

        logging.debug("updated lock {} for {}".format(self.lock_uuid, self.uuid))

    def transfer_locks_to(self, lockable):
        assert isinstance(lockable, LocalLockableObject)
        lockable.lock_uuid = self.lock_uuid
        logging.debug("transferred locks for {} from {} to {}".format(self.uuid, self, lockable))

    def create_lock_proxy(self):
        assert hasattr(self, 'uuid')
        proxy = LocalLockableObject()
        proxy.uuid = self.uuid
        return proxy

    def _cleanup(self):
        # in the case where processes die and locks have expired with no chance
        # of anything ever locking it again, we just need to keep from having a memory leak here
        with local_lock_sync:
            expired_lock_ids = []
            for lock_uuid in local_lock_ids.keys():
                lock_id, lock_time = local_lock_ids[lock_uuid]
                if lock_expired(datetime.datetime.fromtimestamp(lock_time)):
                    logging.warning("detected expired lock {}".format(lock_id))
                    expired_lock_ids.append(lock_uuid)

            for lock_uuid in expired_lock_ids:
                del local_lock_ids[lock_uuid]

class GlobalLockableObject(LockableObject):
    """Abstract class that implements locking using the Chronos system. Subclass must define a uuid property."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # reference to the global lock id returned by Chronos
        self.global_lock_id = chronosapi.NO_LOCK # a value of 0 indicates this object is not currently locked

        # the status of the global lock
        self.global_lock_status = chronosapi.STATUS_UNLOCKED

        # the last time we checked for the status of the lock
        # we use this to prevent spamming chronos with requests
        self.last_status_check = datetime.datetime.now()

        # build the url we're going to use to talk to chronos
        self.chronos_url = 'http://{}:{}'.format(saq.CONFIG['chronos']['host'], saq.CONFIG['chronos']['port'])

    @property
    def lock_identifier(self):
        return self.global_lock_id
    
    def _verify_uuid(self):
        if not hasattr(self, 'uuid'):
            logging.error("object {} type {} does not have uuid property".format(self, type(self)))
            report_exception()
            return False

        if not self.uuid:
            logging.error("object {} type {} has a uuid propety but it is not set".format(self, type(self)))
            report_exception()
            return False

        return True

    def lock(self):
        import chronosapi
        logging.debug("global locking {}".format(self))

        # have we allocated a lock ID yet from chronos?
        if self.global_lock_id == chronosapi.NO_LOCK:
            chronos = chronosapi.Chronos(self.chronos_url)
            self.global_lock_id = chronos.lock_acquire('global-{}'.format(self.uuid), block=False)
            if self.global_lock_id == chronosapi.NO_LOCK:
                raise RuntimeError("unable to get a global lock id (got result {})".format(self.global_lock_id))

            logging.debug("acquired global lock id {} for {}".format(self.global_lock_id, self))

            # immediately get the status of the lock
            self.global_lock_status = chronos.lock_status(self.global_lock_id)
            if self.global_lock_status == chronosapi.STATUS_LOCKED:
                logging.debug("global lock id {} is active".format(self.global_lock_id))
            self.last_status_check = datetime.datetime.now()

        # is it ready?
        return self.is_locked()

    def is_locked(self):
        """This returns True if THIS OBJECT currently holds the lock.
           There is no way to determine if something else currently holds the lock on the target."""
        # if we have a global lock AND it is active, then we're good to go
        if self.global_lock_id != chronosapi.NO_LOCK and self.global_lock_status == chronosapi.STATUS_LOCKED:
            return True

        # if we have a global lock and it's NOT active, then we need to check on the status
        # we don't want to spam chronos with requests so we have a limiter on how often we can check
        # on the status of a lock
        if self.global_lock_id != chronosapi.NO_LOCK and self.global_lock_status != chronosapi.STATUS_LOCKED:
            seconds_elapsed = (datetime.datetime.now() - self.last_status_check).total_seconds()
            if seconds_elapsed < saq.CONFIG['chronos'].getfloat('status_check_frequency'):
                return False

            # check Chronos for the status of the lock
            self.last_status_check = datetime.datetime.now()
            logging.debug("requesting lock status for {}".format(self.global_lock_id))
            chronos = chronosapi.Chronos(self.chronos_url)
            self.global_lock_status = chronos.lock_status(self.global_lock_id)
            if self.global_lock_status == chronosapi.STATUS_LOCKED:
                logging.debug("global lock id {} is active".format(self.global_lock_id))
                return True

        # otherwise we return False
        return False

    def unlock(self):
        # are we not locked?
        if self.global_lock_id == chronosapi.NO_LOCK:
            return

        logging.debug("global unlocking {} with id {}".format(self, self.global_lock_id))
        try:
            chronos = chronosapi.Chronos(self.chronos_url)
            chronos.lock_release(self.global_lock_id)
        except Exception as e:
            logging.error("unable to unlock global lock id {}: {}".format(self.global_lock_id, e))
            report_exception()
        finally:
            self.global_lock_id = chronosapi.NO_LOCK
            self.global_lock_status = chronosapi.STATUS_UNLOCKED

        return True

    def refresh_lock(self):
        """Submits a keep alive message to the global lock server."""
        if self.global_lock_id == chronosapi.NO_LOCK:
            logging.warning("called keep alive on unlocked object {}".format(self))
            return

        logging.debug("sending keep alive for lock {} on {}".format(self.global_lock_id, self))

        try:
            chronos = chronosapi.Chronos(self.chronos_url)
            chronos.lock_keep_alive(self.global_lock_id)
        except Exception as e:
            logging.error("unable to send keep alive for lock {} on {}: {}".format(self.global_lock_id, self, e))
            report_exception()

    def transfer_locks_to(self, dest):
        """Transfers the locks from this LockableObject to another LockableObject."""
        assert isinstance(dest, GlobalLockableObject)
        dest.global_lock_id = self.global_lock_id
        dest.global_lock_status = self.global_lock_status
        dest.last_status_check = self.last_status_check

    def create_lock_proxy(self):
        proxy = GlobalLockableObject()
        proxy.uuid = self.uuid
        return proxy
