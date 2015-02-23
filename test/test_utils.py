"""
Test the traverse_tree function
"""
import docker
import fudge
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


class MockDockerClient(object):
    base_url = 'http://localhost:5000'
    version = lambda x: {'ApiVersion': '1.0'}
    inspect_container_pandas = {
        'ID': 'cidpandaslong',
        'Same': 'Value',
        'Config': {
            'Hostname': 'cuddly-pandas',
        },
        'NetworkSettings': {
            'IPAddress': '127.0.0.1'
        },
    }
    inspect_container_foxes = {
        'ID': 'cidfoxeslong',
        'Same': 'Value',
        'Config': {
            'Hostname': 'sneaky-foxes',
        },
        'NetworkSettings': {
            'IPAddress': '8.8.8.8'
        }
    }
    inspect_container_sloths = {
        'ID': 'cidslothslong',
        'Config': {
            'Hostname': 'stopped-sloths',
        },
        'NetworkSettings': {
            'IPAddress': ''
        }
    }
    inspect_container_returns = {
        'cidpandas': inspect_container_pandas,
        'cidpandaslong': inspect_container_pandas,
        'cidfoxes': inspect_container_foxes,
        'cidfoxeslong': inspect_container_foxes,
        'cidsloths': inspect_container_sloths,
        'cidslothslong': inspect_container_sloths,
    }
    containers_return = [
        {'Id': 'cidpandas'},
        {'Id': 'cidfoxes'},
        {'Id': 'cidsloths'},
    ]

    inspect_container_id = None

    def inspect_container(self, cid):
        self.inspect_container_id = cid

        try:
            return self.inspect_container_returns[cid]
        except KeyError:
            # Mocks a Docker Client Exception
            response = fudge.Fake()
            response.has_attr(status_code=404, content='PANDAS!')

            exception = docker.client.APIError('bad', response)
            raise exception

    def containers(self, *args, **kwargs):  # pylint:disable=unused-argument
        return self.containers_return
