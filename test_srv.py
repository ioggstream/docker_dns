"""
 Creating srv records

"""
from docker_dns import DockerResolver, DockerMapping
from twisted.names import dns
from docker_dns_test import check_deferred
import docker

mock_list_containers = lambda self, name: [
    {u'Command': u'/bin/bash',
     u'Created': 1414430175,
     u'Id': u'7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4',
     u'Image': u'eap63_tracer:v6.3.1',
     u'Names': [u'/jboss631'],
     u'Ports': [{u'IP': u'0.0.0.0',
                 u'PrivatePort': 8080,
                 u'PublicPort': 18080,
                 u'Type': u'tcp'},
                {u'IP': u'0.0.0.0',
                 u'PrivatePort': 8787,
                 u'PublicPort': 8787,
                 u'Type': u'tcp'},
                {u'IP': u'0.0.0.0',
                 u'PrivatePort': 9999,
                 u'PublicPort': 19999,
                 u'Type': u'tcp'},
                {u'PrivatePort': 8443, u'Type': u'tcp'},
                {u'PrivatePort': 9990, u'Type': u'tcp'}],
     u'Status': u'Up 2 days'}
]


mock_lookup_container = lambda name: {
    u'Args': [],
 u'Config': {u'AttachStderr': True,
             u'AttachStdin': True,
             u'AttachStdout': True,
             u'Cmd': [u'/bin/bash'],
             u'CpuShares': 0,
             u'Cpuset': u'',
             u'Domainname': u'',
             u'Entrypoint': None,
             u'Env': [u'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
             u'ExposedPorts': {u'8080/tcp': {},
                               u'8443/tcp': {},
                               u'8787/tcp': {},
                               u'9990/tcp': {},
                               u'9999/tcp': {}},
             u'Hostname': u'7d564ceb891b',
             u'Image': u'eap63_tracer:v6.3.1',
             u'Memory': 0,
             u'MemorySwap': 0,
             u'NetworkDisabled': False,
             u'OnBuild': None,
             u'OpenStdin': True,
             u'PortSpecs': None,
             u'StdinOnce': True,
             u'Tty': True,
             u'User': u'',
             u'Volumes': {},
             u'WorkingDir': u''},
 u'Created': u'2014-10-27T17:16:15.261857884Z',
 u'Driver': u'devicemapper',
 u'ExecDriver': u'native-0.2',
 u'HostConfig': {u'Binds': [u'/home/rpolli/Downloads/:/mnt/tmp'],
                 u'CapAdd': None,
                 u'CapDrop': None,
                 u'ContainerIDFile': u'',
                 u'Devices': [],
                 u'Dns': None,
                 u'DnsSearch': None,
                 u'Links': None,
                 u'LxcConf': [],
                 u'NetworkMode': u'bridge',
                 u'PortBindings': {u'8080/tcp': [{u'HostIp': u'', u'HostPort': u'18080'}],
                                   u'8787/tcp': [{u'HostIp': u'', u'HostPort': u'8787'}],
                                   u'9999/tcp': [{u'HostIp': u'', u'HostPort': u'19999'}]},
                 u'Privileged': False,
                 u'PublishAllPorts': False,
                 u'RestartPolicy': {u'MaximumRetryCount': 0, u'Name': u''},
                 u'VolumesFrom': None},
 u'HostnamePath': u'/var/lib/docker/containers/7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4/hostname',
 u'HostsPath': u'/var/lib/docker/containers/7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4/hosts',
 u'Id': u'7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4',
 u'Image': u'1fc3b15852c8cb8f5b195cee6c3c178b739b77411d9dbebbcbb3d5217f5a6ac6',
 u'MountLabel': u'',
 u'Name': u'/jboss631',
 u'NetworkSettings': {u'Bridge': u'docker0',
                      u'Gateway': u'172.17.42.1',
                      u'IPAddress': u'172.17.0.10',
                      u'IPPrefixLen': 16,
                      u'PortMapping': None,
                      u'Ports': {u'8080/tcp': [{u'HostIp': u'0.0.0.0', u'HostPort': u'18080'}],
                                 u'8443/tcp': None,
                                 u'8787/tcp': [{u'HostIp': u'0.0.0.0', u'HostPort': u'8787'}],
                                 u'9990/tcp': None,
                                 u'9999/tcp': [{u'HostIp': u'0.0.0.0', u'HostPort': u'19999'}]}},
 u'Path': u'/bin/bash',
 u'ProcessLabel': u'',
 u'ResolvConfPath': u'/var/lib/docker/containers/7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4/resolv.conf',
 u'State': {u'ExitCode': 0,
            u'FinishedAt': u'0001-01-01T00:00:00Z',
            u'Paused': False,
            u'Pid': 8662,
            u'Restarting': False,
            u'Running': True,
            u'StartedAt': u'2014-10-27T17:16:15.756653452Z'},
 u'Volumes': {u'/mnt/tmp': u'/home/rpolli/Downloads'},
 u'VolumesRW': {u'/mnt/tmp': True}
}

SRV_FMT = "_{svc}._{proto}.{container}.docker TTL {cclass} SRV {priority} {weight} {port} {target}"


class Test(object):

    def setup(self):
        docker_client = docker.Client()
        self.mapping = DockerMapping(api=docker_client)
        self.mapping.lookup_container = mock_lookup_container
        self.resolver = DockerResolver(self.mapping)

    def test_srv(self):
        dns.Record_SRV(priority=100, weight=100, port=123, target='', ttl=None)

        mock_mapping = {}
        resolver = DockerResolver(mock_mapping)
        res = resolver.lookupService("_8888._tcp.jboss63.docker")
        return res

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
            assert port == pout, "unexpected value in %r" % ret

    def test_lookupService_ko(self):
        expect_fail = 'nondocker.domain noproto.docker noport.container.docker nonint._tcp.container.docker'.split(
        )
        for n in expect_fail:
            ret = self.resolver.lookupService(n)
            check_deferred(ret, False)

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
