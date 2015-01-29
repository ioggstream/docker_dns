#!/usr/bin/python

"""
Tests for Docker DNS

Author: Ricky Cook <ricky@infoxchange.net.au>
"""

# Do not care......
# noqa pylint:disable=missing-docstring,too-many-public-methods,protected-access,invalid-name

import itertools
import unittest

import docker
import fudge
from twisted.names import dns
from twisted.names.error import DNSQueryTimeoutError, DomainError
from twisted.python import log
from dockerdns.utils import traverse_tree
from dockerdns.mappings import DockerMapping
from dockerdns.resolver import DockerResolver


# FIXME I can not believe how disgusting this is
def in_generator(gen, val):
    return reduce(
        lambda old, new: old or new == val,
        gen,
        False
    )


def check_record(record, **kwargs):
    for k in kwargs:
        real_value = getattr(record, k)
        if k is 'name':
            real_value = real_value.name

        if real_value != kwargs[k]:
            log.err("Expected: %s vs %s" % (kwargs[k], real_value))
            return False

    return True


def check_deferred(deferred, success):
    completed = []

    def gimme_x_back(is_success):
        def x_back(result):
            completed.append((is_success, result))

        return x_back

    deferred.addCallbacks(gimme_x_back(True), gimme_x_back(False))
    if len(completed) != 1:
        return False

    status, result = completed[0]
    if status != success:
        raise AssertionError("Expected: %r, got %r" % (success, result))
        return False

    return result


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


class DictLookupTest(unittest.TestCase):
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

    def test_basic_one(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['pandas', 'and']
            ),
            'awesome'
        )

    def test_basic_two(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['foxes', 'are']
            ),
            'sneaky'
        )

    def test_basic_none(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['badgers', 'are'],
                'Badgers are none? What?'
            ),
            None
        )

    def test_dict(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['foxes']
            ),
            self.theDict['foxes']
        )

    def test_default_single_depth(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['nothing']
            ),
            None
        )

    def test_user_default_single_depth(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['nothing'],
                'Nobody here but us chickens'
            ),
            'Nobody here but us chickens'
        )

    def test_default_multi_depth(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['pandas', 'bad']
            ),
            None
        )

    def test_user_default_multi_depth(self):
        self.assertEqual(
            traverse_tree(
                self.theDict,
                ['pandas', 'bad'],
                'NO, THAT\'S A DAMN DIRTY LIE'
            ),
            'NO, THAT\'S A DAMN DIRTY LIE'
        )


class DockerResolverTest(unittest.TestCase):

    def setUp(self):
        self.CONFIG = {}
        from test.test_events import create_mock_db2
        self.db = create_mock_db2()
        self.mapping = DockerMapping(self.db)
        self.resolver = DockerResolver(self.mapping)

    #
    # TEST _a_records
    #
    def test__a_records_hostname(self):
        rec = self.resolver._a_records('sneaky-foxes')
        self.assertEqual(len(rec), 1)

        rec = rec[0]
        self.assertTrue(check_record(
            rec,
            name='sneaky-foxes',
            type=dns.A,
        ))
        self.assertEqual(rec.payload.dottedQuad(), '8.8.8.8')

    def test__a_records_id(self):
        rec = self.resolver._a_records('cidpandas.docker')
        self.assertEqual(len(rec), 1)

        rec = rec[0]
        self.assertTrue(check_record(
            rec,
            name='cidpandas.docker',
            type=dns.A,
        ))
        self.assertEqual(rec.payload.dottedQuad(), '127.0.0.1')

    def test__a_records_shutdown(self):
        self.assertRaises(
            DomainError,
            self.resolver._a_records,
            'cidsloths.docker'
        )

    def test__a_records_invalid(self):
        self.assertRaises(
            DomainError,
            self.resolver._a_records,
            'invalid.docker'
        )

    def test__a_records_blank_query(self):
        self.assertRaises(
            DomainError,
            self.resolver._a_records,
            ''
        )

    def test__a_records_authoritive(self):
        self.resolver.config['authoritive'] = True
        rec = self.resolver._a_records('cidpandas.docker')
        self.assertEqual(len(rec), 1)

        rec = rec[0]
        self.assertTrue(check_record(
            rec,
            name='cidpandas.docker',
            type=dns.A,
            auth=True,
        ))

    def test__a_records_non_authoritive(self):
        self.resolver.config['authoritive'] = False
        rec = self.resolver._a_records('cidpandas.docker')
        self.assertEqual(len(rec), 1)

        rec = rec[0]
        self.assertTrue(check_record(
            rec,
            name='cidpandas.docker',
            type=dns.A,
            auth=False,
        ))

    #
    # TEST lookupAddress
    #
    def test_lookupAddress_id(self):
        deferred = self.resolver.lookupAddress('cidfoxes.docker')

        result = check_deferred(deferred, True)
        self.assertNotEqual(result, False)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[1], ())
        self.assertEqual(result[2], ())
        self.assertEqual(len(result[0]), 1)

        rec = result[0][0]
        self.assertTrue(check_record(
            rec,
            name='cidfoxes.docker',
            type=dns.A,
        ))
        self.assertEqual(rec.payload.dottedQuad(), '8.8.8.8')

    def test_lookupAddress_invalid(self):
        deferred = self.resolver.lookupAddress('invalid')

        result = check_deferred(deferred, False)
        self.assertNotEqual(result, False)

    def test_lookupAddress_invalid_nxdomain(self):
        self.resolver.config['no_nxdomain'] = False
        deferred = self.resolver.lookupAddress('invalid')

        result = check_deferred(deferred, False)
        self.assertNotEqual(result, False)
        self.assertEqual(
            result.type, DomainError)  # noqa pylint:disable=maybe-no-member

    def test_lookupAddress_invalid_no_nxdomain(self):
        self.resolver.config['no_nxdomain'] = True
        deferred = self.resolver.lookupAddress('invalid')

        result = check_deferred(deferred, False)
        self.assertNotEqual(result, False)
        self.assertEqual(result.type, DNSQueryTimeoutError)
                         # noqa pylint:disable=maybe-no-member


def main():
    unittest.main()


if __name__ == '__main__':
    main()
