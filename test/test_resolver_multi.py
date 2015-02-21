#!/usr/bin/python

"""
Tests for Docker DNS

Author: Ricky Cook <ricky@infoxchange.net.au>
"""

# Do not care......
# noqa pylint:disable=missing-docstring,too-many-public-methods,protected-access,invalid-name

import unittest

from twisted.names import dns
from twisted.names.error import DNSQueryTimeoutError, DomainError
from twisted.python import log

from dockerdns.mappings import DockerMapping
from dockerdns.resolver import DockerResolver, NO_NXDOMAIN
from test.test_events import create_mock_db2, create_mock_db
from test.test_resolver import check_record, in_generator, check_deferred

from nose.tools import *


class TestDockerResolver(object):
    def setup(self):
        self.CONFIG = {}

        self.db = create_mock_db()
        self.mapping = DockerMapping(self.db)
        self.resolver = DockerResolver(self.mapping)

    def harn_expected(self, name, expected_record):
        rec = self.resolver._a_records(name)
        assert_equal(len(rec), 1)
        rec = rec[0]
        assert_true(check_record(rec, **expected_record))
        return rec

    def harn_lookupAddress_multi(self, image_name, expected_records):
        # search by image
        # host -t a impandas.*.docker
        #

        # retrieve hosts by image
        deferred = self.resolver.lookupAddress(image_name)
        result = check_deferred(deferred, True)
        assert_not_equal(result, False)

        response_rr, authority_rr, additional_rr = result
        assert_equal(len(response_rr), len(expected_records))

        for rec, expected_record in zip(response_rr, expected_records):
            assert_true(check_record(
                rec,
                **expected_record
            ))

    def test_lookupAddress_multi(self):
        self.resolver.config[NO_NXDOMAIN] = False
        expected_records = (
            {'name': 'jboss631.docker'},
            #            {'name': 'cidpandas0.docker'}
        )
        self.harn_lookupAddress_multi(
            'eap63_tracer:v6.3.1.*.docker', expected_records)

    def test_lookupAddress_multi_notag(self):
        self.resolver.config[NO_NXDOMAIN] = False
        expected_records = (
            {'name': 'jboss631.docker'},
            #            {'name': 'cidpandas0.docker'}
        )
        self.harn_lookupAddress_multi(
            'eap63_tracer.*.docker', expected_records)
