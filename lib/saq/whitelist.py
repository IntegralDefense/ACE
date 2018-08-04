# vim: sw=4:ts=4:et:cc=120

import logging
import os.path

from iptools import IpRangeList

WHITELIST_TYPE_SMTP_FROM = 'smtp_from'
WHITELIST_TYPE_SMTP_TO = 'smtp_to'
WHITELIST_TYPE_HTTP_HOST = 'http_host'
WHITELIST_TYPE_HTTP_SRC_IP = 'http_src_ip'
WHITELIST_TYPE_HTTP_DEST_IP = 'http_dest_ip'

VALID_WHITELIST_KEYS = [
    WHITELIST_TYPE_SMTP_FROM,
    WHITELIST_TYPE_SMTP_TO,
    WHITELIST_TYPE_HTTP_HOST,
    WHITELIST_TYPE_HTTP_SRC_IP,
    WHITELIST_TYPE_HTTP_DEST_IP ]


class BrotexWhitelist(object):
    """Manages the whitelist for brotex scanning."""
    def __init__(self, whitelist_path):
        assert whitelist_path

        # path to the whitelist
        self.whitelist_path = whitelist_path
        # last mtime when the whitelist was loaded
        self.whitelist_timestamp = None
        self.whitelist = {} # key = smtp_to, smtp_from, etc... value = set() of values

    def load_whitelist(self):
        logging.debug("loading whitelist from {}".format(self.whitelist_path))
        self.whitelist_timestamp = os.path.getmtime(self.whitelist_path)
        self.whitelist = {}

        with open(self.whitelist_path, 'r') as fp:
            for line in fp:
                line = line.strip()
                if line == '' or line.startswith('#'):
                    continue

                try:
                    key, value = line.split(':', 1)
                except Exception as e:
                    logging.error("unable to parse whitelist item {}: {}".format(line, str(e)))
                    continue

                if key not in VALID_WHITELIST_KEYS:
                    logging.error("invalid whitelist key {}".format(key))
                    continue

                # a little sanity check on the input
                if value is None or value.strip() == '':
                    logging.error("empty or all whitelist value for {}".format(key))
                    continue

                if key not in self.whitelist:
                    self.whitelist[key] = set()

                self.whitelist[key].add(value.strip())

        # translate all the IP addresses to iptools.IpRange 
        if WHITELIST_TYPE_HTTP_SRC_IP in self.whitelist:
            temp = set()
            for value in self.whitelist[WHITELIST_TYPE_HTTP_SRC_IP]:
                try:
                    temp.add(IpRangeList(value))
                except Exception as e:
                    logging.error("unable to translate {} to an IPv4 in brotex whitelist: {}".format(value, e))
                    continue
            
                self.whitelist[WHITELIST_TYPE_HTTP_SRC_IP] = temp

        # translate all the IP addresses to iptools.IpRange 
        if WHITELIST_TYPE_HTTP_DEST_IP in self.whitelist:
            temp = set()
            for value in self.whitelist[WHITELIST_TYPE_HTTP_DEST_IP]:
                try:
                    temp.add(IpRangeList(value))
                except Exception as e:
                    logging.error("unable to translate {} to an IPv4 in brotex whitelist: {}".format(value, e))
                    continue
            
                self.whitelist[WHITELIST_TYPE_HTTP_DEST_IP] = temp

    def check_whitelist(self):
        if self.whitelist_timestamp != os.path.getmtime(self.whitelist_path):
            if self.whitelist_timestamp:
                logging.info("brotex whitelist modified - loading new whitelist values")
            self.load_whitelist()

    def is_whitelisted(self, _type, value):
        if _type == WHITELIST_TYPE_SMTP_FROM:
            return self.is_whitelisted_email_from_address(value)
        elif _type == WHITELIST_TYPE_SMTP_TO:
            return self.is_whitelisted_email_to_address(value)
        elif _type == WHITELIST_TYPE_HTTP_HOST:
            return self.is_whitelisted_fqdn(value)
        elif _type == WHITELIST_TYPE_HTTP_SRC_IP:
            return self.is_whitelisted_src_ip(value)
        elif _type == WHITELIST_TYPE_HTTP_DEST_IP:
            return self.is_whitelisted_dest_ip(value)
        else:
            logging.error("OOPS no whitelist compare function for type {0}".format(_type))
            return False

    # we have slightly different compare functions for various whitelist types

    def is_whitelisted_email_from_address(self, value):
        if WHITELIST_TYPE_SMTP_FROM not in self.whitelist:
            return False

        for whitelist_item in self.whitelist[WHITELIST_TYPE_SMTP_FROM]:
            if whitelist_item.lower() in value.lower():
                logging.debug("whitelist item {} matches {}".format(whitelist_item, value))
                return True

        return False

    def is_whitelisted_email_to_address(self, value):
        if WHITELIST_TYPE_SMTP_TO not in self.whitelist:
            return False

        for whitelist_item in self.whitelist[WHITELIST_TYPE_SMTP_TO]:
            if whitelist_item.lower() in value.lower():
                logging.debug("whitelist item {} matches {}".format(whitelist_item, value))
                return True

        return False

    def is_whitelisted_fqdn(self, value):
        if WHITELIST_TYPE_HTTP_HOST not in self.whitelist:
            return False

        for whitelist_item in self.whitelist[WHITELIST_TYPE_HTTP_HOST]:
            if value.lower().endswith(whitelist_item.lower()):
                logging.debug("whitelist item {} matches {}".format(whitelist_item, value))
                return True

        return False

    def is_whitelisted_src_ip(self, value):
        if WHITELIST_TYPE_HTTP_SRC_IP not in self.whitelist:
            return False

        for whitelist_item in self.whitelist[WHITELIST_TYPE_HTTP_SRC_IP]:
            if value in whitelist_item:
                logging.debug("whitelist item {} matches {}".format(whitelist_item, value))
                return True

        return False

    def is_whitelisted_dest_ip(self, value):
        if WHITELIST_TYPE_HTTP_DEST_IP not in self.whitelist:
            return False

        for whitelist_item in self.whitelist[WHITELIST_TYPE_HTTP_DEST_IP]:
            if value in whitelist_item:
                logging.debug("whitelist item {} matches {}".format(whitelist_item, value))
                return True

        return False
