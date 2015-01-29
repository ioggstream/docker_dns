"""
Test the traverse_tree function
"""
from dockerdns.utils import traverse_tree


theDict = {
    'pandas': {
        'are': 'cuddly',
        'and': 'awesome',
    },
    'foxes': {
        'are': 'sneaky',
        'and': 'orange',
    },
    'badgers': {
        'are': None,
    },
}


def harn_basic_check(given, expected, default=None):
    ret = traverse_tree(theDict, given, default)
    assert ret == expected, "given: %s, expected: %s, actual: %s, default: %s" % (given, expected, ret, default)


def test_basic_one():
    for given, expected in [
        ('pandas and', 'awesome'),
        ('foxes are', 'sneaky'),
        ('nothing', None),
        ('pandas bad', None),
        ('foxes', theDict['foxes']),

    ]:
        yield harn_basic_check, given.split(), expected


def test_user_default():
    for given, default in [
        ('nothing', 'Nobody here but us chickens'),
        ('pandas bad', 'NO, THAT\'S A DAMN DIRTY LIE'),
    ]:
        yield harn_basic_check, given.split(), default, default


def test_ignore_default():
    for given, expected, default in [
        ('badgers are', None, 'Badgers are none? What?')
    ]:
        yield harn_basic_check, given.split(), expected, default
