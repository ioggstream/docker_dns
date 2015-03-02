#!/usr/bin/python
"""
A simple TwistD DNS server using custom TLD and Docker as the back end for IP
resolution.

To look up a container:
 - 'A' record query a container NAME that will match
        a container with a docker inspect
        command with '.d' as the TLD. eg: mysql_server1.d
 - 'SRV' record query to _port._srv.container.docker will return
        the natted address.
    eg. _3306._tcp.mysql_server1.docker returns
   _18080._tcp.nice_bohr.docker. 10 IN SRV 100 100 8080 192.168.42.126.

Code modified from
https://github.com/infoxchange/docker_dns

Author: Bradley Cicenas <bradley@townsquaredigital.com>
Author: Roberto Polli <robipolli@gmail.com>
"""
from __future__ import print_function, unicode_literals

from zope.interface import implements
import json

from twisted.application import service, internet
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.names import dns, server
from twisted.python import log
from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
import docker

from dockerdns.mappings import DockerMapping
from dockerdns.events import DockerDB
from dockerdns.resolver import DockerResolver
from dockerdns.console import ConsoleFactory


class Options(usage.Options):
    optParameters = [
        ["bind_port", "p", 10053, "The port number to listen on."],
        ["bind_interface", "h", "127.0.0.1", "The host address to bind to"],
        ["domain", "d", "docker", "The default domain"],
        ["config", "c", "dockerdns.json", "Configuration file"],
        ["docker_url", "u", 'unix://var/run/docker.sock', "Docker URL"],
        ['no_nxdomain', "x", True,
            "Return SERVFAIL instead of NXDOMAIN if container not found"],
        ["authoritative", "A", True, "Return authoritative replies"],
        ["docker-version", "V",  '1.15', "Docker API version"],
        ["bind_protocols", "B", ['tcp', 'udp'], "Bind protocols"],
        ["sftp-bind", "S", "10022", "SFTP port to expose Volume access"
                                    " eg. 10022. To specify an ip you can"
                                    " use eg. 22:interface=127.0.0.1"],
        ["sftp-keypath", "", "./", "Path to ssh_host_*key"],
        ["sftp-moduli", "", None, "Path to moduli directory"]

    ]


class MyServiceMaker(object):
    """
        Define a MultiService running:
            - dns server for tcp and udp
            - http client for retrieving docker events
    """
    implements(IServiceMaker, IPlugin)
    tapname = "dockerdns"
    description = "Run this! It'll make your docker happy."
    options = Options

    def sftpVolumeService(self, options, db):
        """
        Construct a service for operating a SSH server.

        @param options: An L{Options} instance specifying server options,
                    including where server keys are stored.

        @param db: A L{DockerDB} instance with container information

        @return: An L{IService} provider which contains the requested
                    SSH server.
        """
        from dockerdns.sftp import factory
        from dockerdns.sftp import unix, checkers as docker_checkers
        from twisted.cred import portal
        from twisted.application import strports
        # The factory just sets the ssh keys
        t = factory.OpenSSHFactory()

        r = unix.DockerRealm(db)
        t.portal = portal.Portal(r, [docker_checkers.PermitChecker()])
        t.dataRoot = options['sftp-keypath']
        t.moduliRoot = options['sftp-moduli'] or options['sftp-keypath']

        port = options['sftp-bind']
        return strports.service(port, t)

    def makeService(self, options):
        """
        Set everything up
        """
        try:
            with open(options['config']) as fh:
                appcfg = json.load(fh)
                appcfg = {k: v for k, v in appcfg.items() if k[0] is not '#'}
        except IOError as e:
            if options['config'] != "dockerdns.json":
                raise
            log.err("File {config} not found. Using default values".format(
                **options))
            appcfg = {}

        # Update config stuff with command line params
        appcfg.update(options)
        log.err("config: %r" % appcfg)
        # Create docker: by default dict.get returns None on missing keys
        docker_client = docker.Client(
            appcfg.get('docker_url'), version=appcfg.get('docker-version'))
        infos = docker_client.info()
        # Test docker connectivity before starting
        log.msg("Connecting to docker instance: %r" % infos)

        db = DockerDB(api=docker_client)
        # Create our custom mapping and resolver
        mapping = DockerMapping(db=db)
        resolver = DockerResolver(mapping, config=appcfg)

        # Create twistd stuff to tie in our custom components
        factory = server.DNSServerFactory(clients=[resolver])
        factory.noisy = False

        # Protocols to bind
        bind_list = []
        if 'tcp' in appcfg['bind_protocols']:
            bind_list.append(
                (internet.TCPServer, factory))  # noqa pylint:disable=no-member

        if 'udp' in appcfg['bind_protocols']:
            proto = dns.DNSDatagramProtocol(factory)
            proto.noisy = False
            bind_list.append(
                (internet.UDPServer, proto))  # noqa pylint:disable=no-member

        # Register the service
        ret = service.MultiService()
        for (InternetServerKlass, arg) in bind_list:
            svc = InternetServerKlass(
                int(appcfg['bind_port']),
                arg,
                interface=appcfg['bind_interface']
            )
            svc.setServiceParent(ret)

        # Add the event Loop
        from dockerdns.events import EventFactory
        from urlparse import urlparse
        if appcfg['docker_url'].startswith("http"):
            u = urlparse(appcfg['docker_url'])
            efactory = EventFactory(config=appcfg, db=db)
            docker_event_monitor = internet.TCPClient(
                u.hostname, u.port, efactory)
            docker_event_monitor.setServiceParent(ret)
        else:
            log.err("Cannot load the Event interface: "
                    "requires an http endpoint, "
                    "not {docker_url}".format(**appcfg))
        # Add the console
        consoleFactory = ConsoleFactory(db)
        console = internet.TCPServer(8080, consoleFactory)
        console.setServiceParent(ret)

        # sftp Volume
        sftp_volumes = self.sftpVolumeService(options, db)
        sftp_volumes.setServiceParent(ret)
        return ret


#
# Create the MultiService
#
serviceMaker = MyServiceMaker()
