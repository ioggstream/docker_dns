"""utilities.py
"""
import socket


def get_preferred_ip():
    """Return the in-addr name associated to the
       ip used to contact the default gw"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connecting to a UDP address doesn't send packets
        sock.connect(('8.8.8.8', 0))
        ip = sock.getsockname()[0]
        return ip, '.'.join(list(reversed(ip.split(".")))) + ".in-addr.arpa"
    except Exception as ex:
        return socket.getfqdn()


def traverse_tree(haystack, key_path, default=None):
    """
    Find an element in a nested dict, eg.
     traverse_tree({'Net': {'IP': '1.1.1.1'}}, ['Net', 'IP']) == '1.1.1.1'

    :param haystack: The nested dictionary to search
    :param key_path: An iterable containing an ordered list of dict keys to
                  traverse
    :param default: Value to return in case nothing is found
    :return:Value of the dict at the nested location given, or default if no value
        was found
    """
    for k in key_path:
        if k in haystack:
            haystack = haystack[k]
        else:
            return default
    return haystack
