#!/usr/bin/python
#from __future__ import print_function, unicode_literals
"""
A simple TwistD DNS server using custom TLD and Docker as the back end for IP
resolution.

To look up a container:
 - 'A' record query a container NAME that will match a container with a docker inspect
   command with '.d' as the TLD. eg: mysql_server1.d
 - 'SRV' record query to _port._srv.container.docker will return the natted address.
   eg. _3306._tcp.mysql_server1.docker returns
   _18080._tcp.compassionate_poincare.docker. 10 IN SRV 100 100 8080 192.168.42.126.


Code modified from
https://github.com/infoxchange/docker_dns

Author: Bradley Cicenas <bradley@townsquaredigital.com>
Author: Roberto Polli <robipolli@gmail.com>
"""

import docker
from warnings import warn
from requests.exceptions import RequestException

from twisted.application import internet, service
from twisted.internet import defer
from twisted.names import common, dns, server
from twisted.names.error import DNSQueryTimeoutError, DomainError
from twisted.python import failure, log

from utils import get_preferred_ip, memoize
from docker_events import UpdateDB

# Merge user config over defaults
CONFIG = DEFAULT_CONFIG = {
    'docker_url': 'unix://var/run/docker.sock',
    'version': '1.13',
    'bind_interface': '',
    'bind_port': 53,
    'bind_protocols': ['tcp', 'udp'],
    'no_nxdomain': True,
    'authoritive': True,
}

# Load the config
try:
    from config import CONFIG as appcfg  # pylint:disable=no-name-in-module,import-error
    CONFIG.update(appcfg)
except ImportError:
    appcfg = {}


class DockerMapping(object):
    """
    Look up docker container data via docker.api.

    XXX Should it be dns-agnostic, and just a wrapper around docker.api
    """

    def __init__(self, api=None, db=None):
        """
        Args:
            api: Docker Client instance used to do API communication
        """
        self.db = db
        self.api = api if api else docker.Client()
        log.msg("DockerMapping pointing to %r" % self.api.base_url)
        try:
            print('connected to docker instance running api version %s' %
                  self.api.version()['ApiVersion'])
        except docker.errors.APIError as ex:
            log.err("Cannot instantiate docker api")
            raise ex

        db.populate(self.api.containers(all=True))


    def lookup_container(self, name):
        """
        Gets the container config from a DNS lookup name, or returns None if
        one could not be found

        Args:
            name: DNS query name to look up

        Returns:
            Container config dict for the first matching container
        """
        try:
            key_path = 'Name'
            name = name.replace('.docker', '')
            log.msg('lookup container: %r' % name)
            if name not in self.db.mappings_idx:
                raise KeyError("Item %s not found in %s" %
                               (name, self.db.mappings_idx.keys()))
            id = self.db.mappings_idx[name]
            return self.db.mappings[id]
        except KeyError as e:
            # warn(str(e))
            return None
        except Exception as e:
            log.exc("Unmanaged error")
            return None

    def lookup_container_old(self, name):
        """
        Gets the container config from a DNS lookup name, or returns None if
        one could not be found

        Args:
            name: DNS query name to look up

        Returns:
            Container config dict for the first matching container
        """
        key_path = 'Name'
        name = name.replace('.docker', '')
        log.msg('lookup container: %r' % name)

        try:
            cid_all = (c['Id'] for c in self.api.containers(all=True) if c)
            log.msg('found containers: %r ' % cid_all)

            for cid in cid_all:
                cdic = self.api.inspect_container(cid)
                # as container names starts with "/" we should strip it
                cname = str(cdic[key_path].strip('/'))
                if cname == name:
                    container_id = cid
                    break
                else:
                    container_id = None

                log.msg('container matching %s: %s' % (name, container_id))

            return self.api.inspect_container(container_id)

        except docker.errors.APIError as ex:
            # 404 is valid, others aren't
            if ex.response.status_code != 404:
                warn(str(ex))
            return None

        except RequestException as ex:
            log.err()
            warn(str(ex))
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
        """ @return - a generator of natted maps (local, nat, ip)

            @param sport: the port to search
            @param sproto: the protocol to search

            eg. [ (8080, 'tcp', 18080, '0.0.0.0'),
                  (8787, 'tcp', 8787, '0.0.0.0'),
                ]
        """
        sport = int(sport)
        container = self.lookup_container(container_name)
        if not container:
            log.err("Bad network information for docker")
            return

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
    mock_records = [dns.RRHeader(
                    "mock_name", dns.SRV, dns.IN, 86400,
                    dns.Record_SRV(
                        priority=100, weight=100, port=19999, target='name', ttl=None),
                    auth=True),
                    dns.RRHeader(
                    "mock_name", dns.SRV, dns.IN, 86400,
                        dns.Record_SRV(
                            priority=100, weight=100, port=18080, target='name', ttl=None),
                        auth=True)
                        ]

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
        self.my_preferred_ip = get_preferred_ip()

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

        # We need to catch everything. Uncaught exceptions will make the server
        # stop responding
        except DomainError as e:
            log.msg("DomainError: %r " % e)
            return defer.fail(failure.Failure(e))
        except Exception as e:  # pylint:disable=bare-except
            import traceback
            traceback.print_exc()

            if CONFIG['no_nxdomain']:
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
        #return defer.succeed((self.mock_records, (), ()))
        if not name.endswith(".docker"):
            log.err("Domain not ending with .docker: %r" % name)
            return defer.fail(failure.Failure(DomainError("not ending with docker")))
        try:
            port, proto, container, _ = name.split(".")
            port = int(port.strip("_"))
        except (IndexError, TypeError, ValueError) as e:
            log.err("Domain not of the right form: %r" % name)
            return defer.fail(failure.Failure(DomainError("not of the right form")))

        records = [dns.RRHeader(
            name, dns.SRV, dns.IN, self.ttl,
                   dns.Record_SRV(
                   priority=100, weight=100, port=c_nat_port, target=self.my_preferred_ip, ttl=None),
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

    # Create docker: by default dict.get returns None on missing keys
    docker_client = docker.Client(CONFIG.get('docker_url'))

    # Test docker connectivity before starting
    log.msg("Connecting to docker instance: %r" % docker_client.info())

    # Create our custom mapping and resolver
    mapping = DockerMapping(docker_client, db=UpdateDB)
    resolver = DockerResolver(mapping)

    # Create twistd stuff to tie in our custom components
    factory = server.DNSServerFactory(clients=[resolver])
    factory.noisy = False

    # Protocols to bind
    bind_list = []
    if 'tcp' in CONFIG['bind_protocols']:
        bind_list.append(
            (internet.TCPServer, factory))  # noqa pylint:disable=no-member

    if 'udp' in CONFIG['bind_protocols']:
        proto = dns.DNSDatagramProtocol(factory)
        proto.noisy = False
        bind_list.append(
            (internet.UDPServer, proto))  # noqa pylint:disable=no-member

    # Register the service
    ret = service.MultiService()
    for (InternetServerKlass, arg) in bind_list:
        svc = InternetServerKlass(
            CONFIG['bind_port'],
            arg,
            interface=CONFIG['bind_interface']
        )
        svc.setServiceParent(ret)

    # Add the event Loop
    from docker_events import EventFactory
    from urlparse import urlparse
    u = urlparse(CONFIG['docker_url'])
    efactory = EventFactory(config=CONFIG)
    docker_event_monitor = internet.TCPClient(u.hostname, u.port, efactory)
    docker_event_monitor.setServiceParent(ret)

    # DO IT NOW
    ret.setServiceParent(service.IServiceCollection(application))


#
# This is the effective twisted application
#


#
# Run it with twisted... it should be named .tac, not .py
#
application = service.Application(
    'dnsserver', 1, 1)  # noqa pylint:disable=invalid-name
main()


# Doin' it wrong
if __name__ == '__main__':
    import sys
    print "Usage: twistd -y %s" % sys.argv[0]
