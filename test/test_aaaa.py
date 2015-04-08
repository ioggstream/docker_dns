#!/usr/bin/python

"""
Tests for AAAA queries

Author: Roberto Polli <roberto.polli@par-tec.it>
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


class TestAAAA(object):
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
    # TEST lookupIPV6Address
    #
    def test_lookupIPV6Address_id_empty_response(self):
        # skip testing authority_rr, additional_rr
        # as we're now populating the authority and additional section
        expected_record = tuple()
        deferred = self.resolver.lookupIPV6Address('cidfoxes.docker')

        result = check_deferred(deferred, True)
        assert_not_equal(result, False)

        response_rr, authority_rr, additional_rr = result

        # We are returning an empty reply
        #  because we're not supporting IPV6
        assert_equal(len(response_rr), 0)

    def test_lookupIPV6Address_invalid(self):
        deferred = self.resolver.lookupIPV6Address('invalid.docker')

        result = check_deferred(deferred, False)
        assert_not_equal(result, False)

    def test_lookupIPV6Address_invalid_nxdomain(self):
        self.resolver.config[NO_NXDOMAIN] = False
        deferred = self.resolver.lookupIPV6Address('invalid.docker')

        result = check_deferred(deferred, False)
        assert_not_equal(result, False)
        assert_equal(
            result.type, DomainError)  # noqa pylint:disable=maybe-no-member

    def test_lookupIPV6Address_invalid_no_nxdomain(self):
        self.resolver.config[NO_NXDOMAIN] = True
        deferred = self.resolver.lookupIPV6Address('invalid.docker')

        result = check_deferred(deferred, False)
        assert_not_equal(result, False)
        assert_equal(result.type, DNSQueryTimeoutError)
        # noqa pylint:disable=maybe-no-member

