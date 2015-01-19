"""utilities.py
"""

import socket


def get_preferred_ip():
    """Return the in-addr name associated to the
       ip used to contact the default gw"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connecting to a UDP address doesn't send packets
        s.connect(('8.8.8.8', 0))
        ip = s.getsockname()[0]
        return '.'.join(list(reversed(s.getsockname()[0].split(".")))) + ".in-addr.arpa"
    except Exception as e:
        return socket.getfqdn()


from functools import partial


class memoize(object):

    """cache the return value of a method

    This class is meant to be used as a decorator of methods. The return value
    from a given method invocation will be cached on the instance whose method
    was invoked. All arguments passed to a method decorated with memoize must
    be hashable.

    If a memoized method is invoked directly on its class the result will not
    be cached. Instead the method will be invoked like a static method:
    class Obj(object):
        @memoize
        def add_to(self, arg):
            return self + arg
    Obj.add_to(1) # not enough arguments
    Obj.add_to(1, 2) # returns 3, result is not cached
    """

    def __init__(self, func):
        self.func = func

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self.func
        return partial(self, obj)

    def __call__(self, *args, **kw):
        obj = args[0]
        try:
            cache = obj.__cache
        except AttributeError:
            cache = obj.__cache = {}
        key = (self.func, args[1:], frozenset(kw.items()))
        try:
            res = cache[key]
        except KeyError:
            res = cache[key] = self.func(*args, **kw)
        return res

# FIXME replace with a more generic solution like operator.attrgetter


def traverse_tree(haystack, key_path, default=None):
    """
    Look up value in a nested dict

    Args:
        dic: The dictionary to search
        key_path: An iterable containing an ordered list of dict keys to
                  traverse
        default: Value to return in case nothing is found
    Returns:
        Value of the dict at the nested location given, or default if no value
        was found
    """
    for k in key_path:
        if k in haystack:
            haystack = dic[k]
        else:
            return default
    return haystack
