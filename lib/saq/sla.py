# vim: sw=4:ts=4:et
#
# classes for working SLA

class SLA(object):
    def __init__(self, name, enabled, timeout, warning, _property, _value):
        self.name = name
        self.enabled = enabled
        self.timeout = timeout
        self.warning = warning
        self._property = _property
        self._value = _value

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "SLA {} (enabled:{},timeout:{},warning:{},prop:{},value:{})".format(
                self.name, self.enabled, self.timeout, self.warning, self._property,
                self._value)
