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
from dockerdns.mappings import DockerMapping
from dockerdns.resolver import DockerResolver, NO_NXDOMAIN
from test.test_events import create_mock_db2, create_mock_db


# FIXME I can not believe how disgusting this is
def in_generator(gen, val):
    return reduce(
        lambda old, new: old or new == val,
        gen,
        False
    )


def check_record(record, **expected):
    """
    Compare a record with the values of the kwargs
    :param record:
    :param expected:
    :return:
    """
    for k in expected:
        real_value = getattr(record, k)
        if k is 'name':
            real_value = real_value.name

        if real_value != expected[k]:
            log.err("Expected %s: %s vs %s" % (k, expected[k], real_value))
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


class DockerResolverTest(unittest.TestCase):
    def setUp(self):
        self.CONFIG = {}

        self.db = create_mock_db2()
        self.mapping = DockerMapping(self.db)
        self.resolver = DockerResolver(self.mapping)

    def harn_expected(self, name, expected_record):
        rec = self.resolver._a_records(name)
        self.assertEqual(len(rec), 1)
        rec = rec[0]
        self.assertTrue(check_record(rec, **expected_record))
        return rec

    #
    # TEST _a_records
    #
    def test__a_records_hostname(self):
        name, expected_record = 'sneaky-foxes', {'name':
                                                 'sneaky-foxes.docker', 'type': dns.A}
        rec = self.harn_expected(name, expected_record)
        self.assertEqual(rec.payload.dottedQuad(), '8.8.8.8')

    def test__a_records_id(self):
        name, expected_record = 'cidpandas', {'name':
                                              'cidpandas.docker', 'type': dns.A}
        rec = self.harn_expected(name, expected_record)
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

    def test__a_records_authoritative(self):
        name, expected_record = 'cidpandas', {'name':
                                              'cidpandas.docker', 'type': dns.A, 'auth': True}
        self.resolver.config['authoritative'] = True
        self.harn_expected(name, expected_record)

    def test__a_records_non_authoritative(self):
        name, expected_record = 'cidpandas', {'name':
                                              'cidpandas.docker', 'type': dns.A, 'auth': False}
        self.resolver.config['authoritative'] = False
        self.harn_expected(name, expected_record)

    #
    # TEST lookupAddress
    #
    def test_lookupAddress_id(self):
        expected_record, expected_authority, expected_additional = (
            {'name': 'cidfoxes.docker', 'type': dns.A},
            tuple(),
            tuple()
        )
        deferred = self.resolver.lookupAddress('cidfoxes.docker')

        result = check_deferred(deferred, True)
        self.assertNotEqual(result, False)

        response_rr, authority_rr, additional_rr = result
        # skip this tests as we're now populating
        # the authority and additional section
        self.assertEqual(len(response_rr), 1)

        rec = response_rr[0]
        self.assertTrue(check_record(
            rec,
            **expected_record
        ))
        self.assertEqual(rec.payload.dottedQuad(), '8.8.8.8')

    def test_lookupAddress_invalid(self):
        deferred = self.resolver.lookupAddress('invalid.docker')

        result = check_deferred(deferred, False)
        self.assertNotEqual(result, False)

    def test_lookupAddress_invalid_nxdomain(self):
        self.resolver.config[NO_NXDOMAIN] = False
        deferred = self.resolver.lookupAddress('invalid.docker')

        result = check_deferred(deferred, False)
        self.assertNotEqual(result, False)
        self.assertEqual(
            result.type, DomainError)  # noqa pylint:disable=maybe-no-member

    def test_lookupAddress_invalid_no_nxdomain(self):
        self.resolver.config[NO_NXDOMAIN] = True
        deferred = self.resolver.lookupAddress('invalid.docker')

        result = check_deferred(deferred, False)
        self.assertNotEqual(result, False)
        self.assertEqual(result.type, DNSQueryTimeoutError)
        # noqa pylint:disable=maybe-no-member

    def test_lookupAddress_multi(self):
        # search by image
        # host -t a impandas.*.docker
        #
        expected_records = (
            {'name': 'cidpandas.docker'},
            {'name': 'cidpandas0.docker'}
        )
        self.resolver.config[NO_NXDOMAIN] = False

        # retrieve hosts by image
        deferred = self.resolver.lookupAddress('impandas.*.docker')
        result = check_deferred(deferred, True)
        self.assertNotEqual(result, False)

        response_rr, authority_rr, additional_rr = result
        self.assertEqual(len(response_rr), len(expected_records))

        for rec, expected_record in zip(response_rr, expected_records):
            self.assertTrue(check_record(
                rec,
                **expected_record
            ))


class DockerResolver2Test(unittest.TestCase):
    def setUp(self):
        self.CONFIG = {}

        self.db = create_mock_db()
        self.mapping = DockerMapping(self.db)
        self.resolver = DockerResolver(self.mapping)

    def harn_expected(self, name, expected_record):
        rec = self.resolver._a_records(name)
        self.assertEqual(len(rec), 1)
        rec = rec[0]
        self.assertTrue(check_record(rec, **expected_record))
        return rec

    def test_lookupAddress_multi(self):
        # search by image
        # host -t a impandas.*.docker
        #
        expected_records = (
            {'name': 'jboss631.docker'},
            #            {'name': 'cidpandas0.docker'}
        )
        self.resolver.config[NO_NXDOMAIN] = False

        # retrieve hosts by image
        deferred = self.resolver.lookupAddress('eap63_tracer:v6.3.1.*.docker')
        result = check_deferred(deferred, True)
        self.assertNotEqual(result, False)

        response_rr, authority_rr, additional_rr = result
        self.assertEqual(len(response_rr), len(expected_records))

        for rec, expected_record in zip(response_rr, expected_records):
            self.assertTrue(check_record(
                rec,
                **expected_record
            ))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
