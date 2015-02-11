#!/usr/bin/python

"""
Tests for Docker DNS

Author: Ricky Cook <ricky@infoxchange.net.au>
"""

# Do not care......
# noqa pylint:disable=missing-docstring,too-many-public-methods,protected-access,invalid-name


from twisted.names import dns
from twisted.names.error import DNSQueryTimeoutError, DomainError
from twisted.python import log

from dockerdns.mappings import DockerMapping
from dockerdns.resolver import DockerResolver, NO_NXDOMAIN
from test.test_events import create_mock_db2
from nose.tools import *

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


class TestDockerResolver(object):
    def setUp(self):
        self.CONFIG = {}

        self.db = create_mock_db2()
        self.mapping = DockerMapping(self.db)
        self.resolver = DockerResolver(self.mapping)

    def harn_expected(self, name, expected_record):
        rec = self.resolver._a_records(name)
        assert_equal(len(rec), 1)
        rec = rec[0]
        assert_true(check_record(rec, **expected_record))
        return rec

    #
    # TEST _a_records
    #
    def test__a_records_hostname(self):
        name, expected_record = 'sneaky-foxes', {'name':
                                                 'sneaky-foxes.docker', 'type': dns.A}
        rec = self.harn_expected(name, expected_record)
        assert_equal(rec.payload.dottedQuad(), '8.8.8.8')

    def test__a_records_id(self):
        name, expected_record = 'cidpandas', {'name':
                                              'cidpandas.docker', 'type': dns.A}
        rec = self.harn_expected(name, expected_record)
        assert_equal(rec.payload.dottedQuad(), '127.0.0.1')

    @raises(DomainError)
    def test__a_records_shutdown(self):
        self.resolver._a_records('cidsloths.docker')

    @raises(DomainError)
    def test__a_records_invalid(self):
        self.resolver._a_records('invalid.docker')


    @raises(DomainError)
    def test__a_records_blank_query(self):
        self.resolver._a_records("")

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
        assert_not_equal(result, False)

        response_rr, authority_rr, additional_rr = result
        # skip this tests as we're now populating
        # the authority and additional section
        assert_equal(len(response_rr), 1)

        rec = response_rr[0]
        assert_true(check_record(
            rec,
            **expected_record
        ))
        assert_equal(rec.payload.dottedQuad(), '8.8.8.8')

    def test_lookupAddress_invalid(self):
        deferred = self.resolver.lookupAddress('invalid.docker')

        result = check_deferred(deferred, False)
        assert_not_equal(result, False)

    def test_lookupAddress_invalid_nxdomain(self):
        self.resolver.config[NO_NXDOMAIN] = False
        deferred = self.resolver.lookupAddress('invalid.docker')

        result = check_deferred(deferred, False)
        assert_not_equal(result, False)
        assert_equal(
            result.type, DomainError)  # noqa pylint:disable=maybe-no-member

    def test_lookupAddress_invalid_no_nxdomain(self):
        self.resolver.config[NO_NXDOMAIN] = True
        deferred = self.resolver.lookupAddress('invalid.docker')

        result = check_deferred(deferred, False)
        assert_not_equal(result, False)
        assert_equal(result.type, DNSQueryTimeoutError)
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
        assert_not_equal(result, False)

        response_rr, authority_rr, additional_rr = result
        assert_equal(len(response_rr), len(expected_records))

        for rec, expected_record in zip(response_rr, expected_records):
            assert_true(check_record(
                rec,
                **expected_record
            ))




