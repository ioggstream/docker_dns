"""
 Creating srv records

"""
import twisted
from dockerdns.resolver import DockerResolver
from dockerdns.mappings import DockerMapping
from test import mock_lookup_container, SRV_FMT
from nose import SkipTest
from nose.tools import raises
from nose.twistedtools import deferred as nosedeferred
from test.test_resolver import check_deferred


class TestSrv(object):
    mapping = DockerMapping(db=None)
    mapping.lookup_container = mock_lookup_container

    def check_equals(self, a, b, msg=None):
        assert a == b, msg

    def setup(self):
        self.resolver = DockerResolver(self.mapping)

    def test_nat_all(self):
        host, port = "foo.docker", 8080
        ret = self.mapping.get_nat(host, port)
        assert (8080, "tcp", 18080, "0.0.0.0") in ret, "ret: %r" % ret

    def test_nat_ports(self):
        expected = [(8080, 18080),
                    (9999, 19999), (8787, 8787)]

        for pin, pout in expected:
            ret = self.mapping.get_nat("foo", pin)
            _, _, port, _ = next(ret)

            yield self.check_equals, port, pout, "unexpected value in %r" % ret

    @raises(twisted.names.error.DomainError)
    @nosedeferred()
    def harn_lookupService_ko(self, n):
        """Harness to run lookup in a deferred
        """
        return self.resolver.lookupService(n)

    def test_lookupService_ko(self):
        expect_fail = 'nondocker.domain noproto.docker noport.container.docker nonint._tcp.container.docker'.split(
        )
        for n in expect_fail:
            yield self.harn_lookupService_ko, n

    def test_lookupService_ok(self):
        ret = self.resolver.lookupService("_8080._tcp.jboss631.docker")
        ret = check_deferred(ret, True)
        print("resolved: %r" % [ret])

    def test_mapping(self):
        container = self.mapping.lookup_container("foo")

        for local, remote in container['NetworkSettings']['Ports'].items():
            port, proto = local.split("/")
            if not remote:
                continue
            try:
                remote = remote[0]
            except IndexError:
                continue

            print(SRV_FMT.format(
                svc=port,
                  proto=proto,
                  container=container['Name'][1:],
                  cclass="IN",
                  priority=100,
                  weight=100,
                  port=remote['HostPort'],
                  target=remote['HostIp'] if remote[
                  'HostIp'] != '0.0.0.0' else "localhost"
                  )
                  )

    @SkipTest
    def test_service_image(self):
        host = "impandas.docker"
        raise NotImplementedError("implement skydns-like")
