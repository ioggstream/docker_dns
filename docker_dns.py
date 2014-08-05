#!/usr/bin/python

"""
A simple TwistD DNS server using custom TLD and Docker as the back end for IP
resolution.

To look up a container:
 - 'A' record query container's hostname with no TLD. Must be an exact match
 - 'A' record query an ID that will match a container with a docker inspect
   command with '.docker' as the TLD. eg: 0949efde23b.docker

Code heavily modified from
http://stackoverflow.com/a/4401671/509043

Author: Ricky Cook <ricky@infoxchange.net.au>
"""

import docker
import re

from requests.exceptions import RequestException
from twisted.application import internet, service
from twisted.internet import defer
from twisted.names import common, dns, server
from twisted.names.error import DNSQueryTimeoutError, DomainError
from twisted.python import failure
from warnings import warn

class DockerMapping(object):
    """
    Look up docker container data
    """

    id_re = re.compile(r'([a-z0-9]+)\.d')

    def __init__(self, api):
        """
        Args:
            api: Docker Client instance used to do API communication
        """

        self.api = api
        try:
            print('connected to docker instance running api version %s' % \
                    self.api.version()['ApiVersion'])
        except docker.client.APIError as ex:
            raise Exception(ex)

    def lookup_container(self, name):
        """
        Gets the container config from a DNS lookup name, or returns None if
        one could not be found

        Args:
            name: DNS query name to look up

        Returns:
            Container config dict for the first matching container
        """
        key_path = 'Name'
        warn(name)

        cid_all = [ c['Id'] for c in self.api.containers(all=True) ]
        print(cid_all)

        for cid in cid_all:
            warn(cid)
            cdic = self.api.inspect_container(cid_all['Id'])
            warn(cdic[key_path])
            if cdic[key_path] == name:
                container_id = cdic[key_path]
            else:
                container_id = None
            warn(container_id)

#        try:
        return self.api.inspect_container(container_id)
#        except RequestException as ex:
#            warn(ex)
#            return None

    def get_a(self, name):
        """
        Get an IPv4 address from a query name to be used in A record lookups

        Args:
            name: DNS query name to look up

        Returns:
            IPv4 address for the query name given
        """

        container = self.lookup_container(name)
        print 'container:'
        print(container)

        if container is None:
            return None

        addr = container['NetworkSettings']['IPAddress']

        if addr is '':
            return None

        return addr


# pylint:disable=too-many-public-methods
class DockerResolver(common.ResolverBase):
    """
    DNS resolver to resolve queries with a DockerMapping instance.
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
        print addr
        if not addr:
            raise DomainError(name)

        return tuple([
            dns.RRHeader(name, dns.A, dns.IN, self.ttl,
                         dns.Record_A(addr, self.ttl),
                         CONFIG['authoritive'])
        ])

    def lookupAddress(self, name, timeout=None):
        print('attempting lookup')
        records = self._a_records(name)
        print('records')
        print(records)
        return defer.succeed((records, (), ()))

def main():
    """
    Set everything up
    """

    # Create docker
    if CONFIG['docker_url']:
        docker_client = docker.Client(base_url=CONFIG['docker_url'], version=CONFIG['version'])
    else:
        docker_client = docker.Client(version=CONFIG['version'])

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
