#!/usr/bin/python

""" 
A simple TwistD DNS server using custom TLD and Docker as the back end for IP
resolution.

To look up a container:
 - 'A' record query a container NAME that will match a container with a docker inspect
   command with '.d' as the TLD. eg: mysql_server1.d

Code modified from 
https://github.com/infoxchange/docker_dns

Author: Bradley Cicenas <bradley@townsquaredigital.com>
"""

import docker
from warnings import warn
from socket import getfqdn
from requests.exceptions import RequestException

from twisted.application import internet, service
from twisted.internet import defer
from twisted.names import common, dns, server
from twisted.names.error import DNSQueryTimeoutError, DomainError
from twisted.python import failure, log

from functools import partial


def get_preferred_ip():
    """Return the ip associated to the default gw"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # connecting to a UDP address doesn't send packets
    s.connect(('8.8.8.8', 0))
    return s.getsockname()[0]


class memoize(object):

    """cache the return value of a method
    
    This class is meant to be used as a decorator of methods. The return value
    from a given method invocation will be cached on the instance whose method
    was invoked. All arguments passed to a method decorated with memoize must
    be hashable.
    
    If a memoized method is invoked directly on its class the result will not
    be cached. Instead the method will be invoked like a static method:
    class Obj(object):
        @memoize
        def add_to(self, arg):
            return self + arg
    Obj.add_to(1) # not enough arguments
    Obj.add_to(1, 2) # returns 3, result is not cached
    """

    def __init__(self, func):
        self.func = func

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self.func
        return partial(self, obj)

    def __call__(self, *args, **kw):
        obj = args[0]
        try:
            cache = obj.__cache
        except AttributeError:
            cache = obj.__cache = {}
        key = (self.func, args[1:], frozenset(kw.items()))
        try:
            res = cache[key]
        except KeyError:
            res = cache[key] = self.func(*args, **kw)
        return res


class DockerMapping(object):

    """
    Look up docker container data via docker.api.
    
    XXX Should it be dns-agnostic, and just a wrapper around docker.api
    """

    def __init__(self, api=None):
        """
        Args:
            api: Docker Client instance used to do API communication
        """

        self.api = api if api else docker.Client()
        log.msg("DockerMapping pointing to %r" % self.api.base_url)
        try:
            print('connected to docker instance running api version %s' %
                  self.api.version()['ApiVersion'])
        except docker.errors.APIError as ex:
            log.err("Cannot instantiate docker api")
            raise ex

    #@memoize
    def lookup_container(self, name):
        """
        Gets the container config from a DNS lookup name, or returns None if
        one could not be found

        Args:
            name: DNS query name to look up

        Returns:
            Container config dict for the first matching container
        """
        assert self.api

        key_path = 'Name'
        name = name.strip('.d')
        log.msg('lookup container: %r' % name)

        try:
            cid_all = (c['Id'] for c in self.api.containers(all=True) if c)
            log.msg('found containers: %r ' % cid_all)

            for cid in cid_all:
                cdic = self.api.inspect_container(cid)
                cname = str(cdic[key_path].strip('/'))
                if cname == name:
                    container_id = cid
                    break
                else:
                    container_id = None

                print('container matching %s: %s' % (name, container_id))

            return self.api.inspect_container(container_id)

        except docker.errors.APIError as ex:
            # 404 is valid, others aren't
            if ex.response.status_code != 404:
                warn(ex)
            return None

        except RequestException as ex:
            log.err()
            # warn(ex)
            return None

    def get_a(self, name):
        """
        Get an IPv4 address from a query name to be used in A record lookups

        Args:
            name: DNS query name to look up

        Returns:
            IPv4 address for the query name given
        """

        container = self.lookup_container(name)

        if container is None:
            print("No container found")
            return None

        addr = container['NetworkSettings']['IPAddress']

        if not addr:
            return None

        return addr

    def get_nat(self, container_name, sport=0, sproto=None):
        """ @return - a list of natted maps (local, nat, ip)

            @param sport: the port to search
            @param sproto: the protocol to search

            eg. [ (8080, 'tcp', 18080, '0.0.0.0'),
                  (8787, 'tcp', 8787, '0.0.0.0'), 
                ]
        """
        sport = int(sport)
        container = self.lookup_container(container_name)
        try:
            for local, remote in container['NetworkSettings']['Ports'].items():
                port, proto = local.split("/")
                port = int(port)
                if sport and sport != port:
                    continue
                if sproto and sproto != proto:
                    continue
                if not remote:
                    continue

                for r in remote:
                    try:
                        yield (port, proto, int(r['HostPort']), r['HostIp'])
                    except (ValueError, KeyError) as e:
                        log.err()
                        continue
        except KeyError as e:
            log.err("Bad network information from docker")


# pylint:disable=too-many-public-methods
class DockerResolver(common.ResolverBase):

    """
    DNS resolver to resolve queries with a DockerMapping instance.
    
    Twisted Names just uses the lookupXXX method
    """

    def __init__(self, mapping):
        """
        Args:
            mapping: DockerMapping instance for lookups
        """

        self.mapping = mapping

        # Change to this ASAP when Twisted uses object base
        # super(DockerResolver, self).__init__()
        common.ResolverBase.__init__(self)
        self.ttl = 10

    def _a_records(self, name):
        """
        Get A records from a query name

        Args:
            name: DNS query name to look up

        Returns:
            Tuple of formatted DNS replies
        """

        addr = self.mapping.get_a(name)
        if not addr:
            raise DomainError(name)

        return tuple([
            dns.RRHeader(name, dns.A, dns.IN, self.ttl,
                         dns.Record_A(addr, self.ttl),
                         CONFIG['authoritive'])
        ])

    def _srv_records(self, name):
        print("getting srv: %r" + name)
        return tuple([
            dns.RRHeader(name, dns.SRV, dns.IN, self.ttl,
                         dns.Record_A(addr, self.ttl),
                         CONFIG['authoritive'])
        ])

    def lookupAddress(self, name, timeout=None):
        try:
            records = self._a_records(name)
            return defer.succeed((records, (), ()))

        # We need to catch everything. Uncaught exceptian will make the server
        # stop responding
        except Exception as e:  # pylint:disable=bare-except
            if CONFIG['no_nxdomain']:
                print("E stampala sta eccezione imbecille %r" % e)
                log.err()
                # FIXME surely there's a better way to give SERVFAIL
                exception = DNSQueryTimeoutError(name)
            else:
                exception = DomainError(name)

            return defer.fail(failure.Failure(exception))

    def lookupService(self, name, timeout=None):
        """ Lookup a docker natted service of
             the form: NATTEDPORT._tcp.CONTAINERNAME.docker.
             and returns a srv record of the for:
             _service._proto.name. TTL class SRV priority weight port target. 
             
             @returns -    A Deferred which fires with a three-tuple of lists of twisted.names.dns.RRHeader instances.
                  The first element of the tuple gives answers. 
                  The second element of the tuple gives authorities. 
                  The third element of the tuple gives additional information. 
                  The Deferred may instead fail with one of the exceptions defined in twisted.names.error or with NotImplementedError. (type: Deferred)           
        """
        if not name.endswith(".docker"):
            log.err("Domain not ending with .docker: %r" % name)
            return defer.fail(failure.Failure(DomainError("not ending with docker")))
        try:
            port, proto, container, _ = name.split(".")
            port = int(port.strip("_"))
        except (IndexError, TypeError, ValueError) as e:
            log.err("Domain not of the right form: %r" % name)
            return defer.fail(failure.Failure(DomainError("not of the right form")))

        my_preferred_ip = get_preferred_ip()
        mock_records = [dns.RRHeader(
            name, dns.SRV, dns.IN, self.ttl,
                        dns.Record_SRV(
                            priority=100, weight=100, port=19999, target='name', ttl=None),
                        auth=True),
                        dns.RRHeader(
            name, dns.SRV, dns.IN, self.ttl,
                        dns.Record_SRV(
                            priority=100, weight=100, port=18080, target='name', ttl=None),
                        auth=True)
                        ]

        records = [dns.RRHeader(
            name, dns.SRV, dns.IN, self.ttl,
                        dns.Record_SRV(
                            priority=100, weight=100, port=c_nat_port, target=my_preferred_ip, ttl=None),
                        auth=True)
                   for c_port, protocol, c_nat_port, target
                   in self.mapping.get_nat(container)
                   if c_port == port  # eventually filter
                   ]
        return defer.succeed((records, (), ()))


def main():
    """
    Set everything up
    """

    docker_client = docker.Client()

    # Test docker connectivity before starting
    print(docker_client.info())
    print(docker_client.base_url)

    # Create our custom mapping and resolver
    mapping = DockerMapping(docker_client)
    resolver = DockerResolver(mapping)

    # Create twistd stuff to tie in our custom components
    factory = server.DNSServerFactory(clients=[resolver])
    factory.noisy = False

    # Protocols to bind
    bind_list = []
    if 'tcp' in CONFIG['bind_protocols']:
        bind_list.append((internet.TCPServer, factory))  # noqa pylint:disable=no-member

    if 'udp' in CONFIG['bind_protocols']:
        proto = dns.DNSDatagramProtocol(factory)
        proto.noisy = False
        bind_list.append((internet.UDPServer, proto))  # noqa pylint:disable=no-member

    # Register the service
    ret = service.MultiService()
    for (klass, arg) in bind_list:
        svc = klass(
            CONFIG['bind_port'],
            arg,
            interface=CONFIG['bind_interface']
        )
        svc.setServiceParent(ret)

    # DO IT NOW
    ret.setServiceParent(service.IServiceCollection(application))

# Load the config
try:
    from config import CONFIG  # pylint:disable=no-name-in-module,import-error
except ImportError:
    CONFIG = {}

# Merge user config over defaults
DEFAULT_CONFIG = {
    'docker_url': 'unix://var/run/docker.sock',
    'version': '1.13',
    'bind_interface': '',
    'bind_port': 53,
    'bind_protocols': ['tcp', 'udp'],
    'no_nxdomain': True,
    'authoritive': True,
}
CONFIG = dict(DEFAULT_CONFIG.items() + CONFIG.items())

application = service.Application('dnsserver', 1, 1)  # noqa pylint:disable=invalid-name
main()


# Doin' it wrong
if __name__ == '__main__':
    import sys
    print "Usage: twistd -y %s" % sys.argv[0]
