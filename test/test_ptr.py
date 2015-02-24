"""
 Creating Ptr records

"""
import twisted
from dockerdns.resolver import DockerResolver
from dockerdns.mappings import DockerMapping
from test import mock_lookup_container, mock_get_ptr
from nose import SkipTest
from nose.tools import raises
from nose.twistedtools import deferred as nosedeferred
from test.test_resolver import check_deferred


class TestPtr(object):
    """
    Test lookupPointer record mocking DockerMapping functions.

    This class doesn't test DockerDB
    """
    mapping = DockerMapping(db=None)
    mapping.lookup_container = mock_lookup_container
    mapping.get_ptr = mock_get_ptr

    def check_equals(self, a, b, msg=None):
        assert a == b, msg

    def setup(self):
        self.resolver = DockerResolver(self.mapping)

    @raises(twisted.names.error.DomainError)
    @nosedeferred()
    def harn_lookupPtr_ko(self, n):
        """Harness to run lookup in a deferred
        """
        return self.resolver.lookupPointer(n)

    def test_lookupPtr_ko(self):
        expect_fail = ('166.192.in-addr.arpa').split()
        for n in expect_fail:
            yield self.harn_lookupPtr_ko, n

    def test_lookupPtr_ok(self):
        ret = self.resolver.lookupPointer("10.0.17.172.in-addr.arpa")
        ret = check_deferred(ret, True)
        print("resolved: %r" % [ret])

    def test_ptr_ok(self):
        ret, = self.resolver._ptr_record("10.0.17.172.in-addr.arpa")
        assert ret

    def test_setup(self):
        assert self.resolver
        assert self.resolver.mapping
        assert self.resolver.mapping.db is None
