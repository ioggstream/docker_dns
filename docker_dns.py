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

from twisted.application import internet, service
from twisted.names import dns, server
from twisted.python import log

from dockerdns.mappings import DockerMapping
from dockerdns.events import DockerDB
from dockerdns.resolver import DockerResolver


# Merge user config over defaults
CONFIG = DEFAULT_CONFIG = {
    'docker_url': 'unix://var/run/docker.sock',
    'version': '1.13',
    'bind_interface': '',
    'bind_port': 53,
    'bind_protocols': ['tcp', 'udp'],
    'no_nxdomain': True,
    'authoritative': True,
}

# Load the config
try:
    from config import CONFIG as appcfg  # pylint:disable=no-name-in-module,import-error
    CONFIG.update(appcfg)
except ImportError:
    appcfg = {}


def main():
    """
    Set everything up
    """
    import docker

    # Create docker: by default dict.get returns None on missing keys
    docker_client = docker.Client(CONFIG.get('docker_url'))
    infos = docker_client.info()
    # Test docker connectivity before starting
    log.msg("Connecting to docker instance: %r" % infos)

    db = DockerDB(api=docker_client)
    # Create our custom mapping and resolver
    mapping = DockerMapping(db=db)
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
    from dockerdns.events import EventFactory
    from urlparse import urlparse
    u = urlparse(CONFIG['docker_url'])
    efactory = EventFactory(config=CONFIG, db=db)
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
