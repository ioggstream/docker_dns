"""
author: robipolli@gmail.com

Extending twisted.names.common.ResolverBase to
reply with the informations provided by
dockerdns.mappings.DockerMapping

"""
import re
import socket
from twisted.python import log
from twisted.internet import defer
from twisted.internet.defer import failure
from twisted.names import common, dns
from twisted.names.error import DomainError, DNSQueryTimeoutError
from dockerdns.utils import get_preferred_ip


NO_NXDOMAIN = 'no_nxdomain'


# pylint:disable=too-many-public-methods
# pylint:disable=too-many-instance-attributes
class DockerResolver(common.ResolverBase):
    """
    DNS resolver to resolve queries with a DockerMapping instance.

    Twisted Names just uses the lookupXXX methods
    """
    mock_records = [
        dns.RRHeader(
            "mock_name", dns.SRV, dns.IN, 86400,
            payload=dns.Record_SRV(
                priority=100, weight=100, port=19999, target='name', ttl=None),
            auth=True),
        dns.RRHeader(
            "mock_name", dns.SRV, dns.IN, 86400,
            payload=dns.Record_SRV(
                priority=100, weight=100, port=18080, target='name', ttl=None),
            auth=True)
    ]

    def __init__(self, mapping, config=None):
        """
        :param mapping: DockerMapping instance for lookups

        TODO: configurable --bip
        """

        self.mapping = mapping
        self.config = config or {
            'domain': 'docker',
            'bip': '172.17.0.0/16',
            'ttl': 10
        }
        self.re_domain = re.compile(r'\.' + self.config['domain'] + '$')
        self.re_ptr = re.compile(r'[0-9]+\.[0-9]+\.17\.172\.in-addr\.arpa$')
        # Change to this ASAP when Twisted uses object base
        # super(DockerResolver, self).__init__()
        common.ResolverBase.__init__(self)
        self.ttl = int(self.config['ttl'])
        self.my_preferred_ip, self.my_preferred_ip_ptr_value \
            = get_preferred_ip()

        # define authority and additional records
        # an authority record defines the name IN NS TIMEOUT
        # socket.
        self.authority = [dns.RRHeader(
            name=self.config['domain'] + ".", type=dns.NS, cls=dns.IN,
            payload=dns.Record_NS(name=socket.gethostname())
        )]
        self.additional = [dns.RRHeader(
            name=socket.gethostname(), type=dns.A, cls=dns.IN,
            payload=dns.Record_A(address=self.my_preferred_ip))
        ]

    def _a_records(self, name):
        """
        Get A records from a query name

        :param name: DNS query name to look up

        :return: Tuple of formatted DNS replies
        """

        addr = self.mapping.get_a(name)
        if not addr:
            raise DomainError(name)

        return tuple([
            dns.RRHeader(
                '.'.join((name, self.config['domain'])),
                dns.A, dns.IN, self.ttl,
                payload=dns.Record_A(addr, self.ttl),
                auth=self.config.get('authoritative'))
        ])

    def _srv_records(self, name):
        print("getting srv: %r" + name)
        addr = self.mapping.get_a(name)
        return tuple([
            dns.RRHeader(
                '.'.join((name, self.config['domain'])),
                dns.SRV, dns.IN, self.ttl,
                dns.Record_A(addr, self.ttl),
                auth=self.config.get('authoritative'))
        ])

    def _ptr_record(self, name):
        """
        Get PTR records from a query name

        :param name: DNS query name to look up

        :return: Tuple of formatted DNS replies
        """
        # convert x.y.z.q.in-addr.arpa -> q.z.y.x
        ip_addr = '.'.join(reversed(name.split(".")[:4]))
        addr = self.mapping.get_ptr(ip_addr)
        if not addr:
            raise DomainError(name)
        addr = '.'.join((addr, self.config['domain']))
        return tuple([
            dns.RRHeader(
                name,
                dns.PTR, dns.IN, self.ttl,
                payload=dns.Record_PTR(addr, self.ttl),
                auth=self.config.get('authoritative'))
        ])

    def lookupAddress(self, name, timeout=None):
        """

        :param name: a name like container_name.docker, hostname.docker,
                image_name.*.docker
        :param timeout:
        :return: A deferred firing a 3-tuple
                The first element of the tuple gives answers.
                The second element of the tuple gives authorities.
                The third element of the tuple gives additional information.
                The Deferred may instead fail with one of the exceptions
                defined in twisted.names.error or
                with NotImplementedError.
        :type: Deferred

        """
        name, occurrences = self.re_domain.subn('', name)
        if not occurrences:
            log.err("Domain not ending with {domain}: {name}".format(
                name=name, **self.config))
            return defer.fail(failure.Failure(
                DomainError("not ending with docker"))
            )

        try:
            if name.endswith(".*"):
                a_multi = self.mapping.get_a_multi(name)
                log.msg(a_multi)
                records = tuple(
                    dns.RRHeader(
                        '.'.join((name_, self.config['domain'])),
                        dns.A, dns.IN, self.ttl,
                        dns.Record_A(addr_, self.ttl),
                        auth=self.config.get('authoritative')
                    )
                    for addr_, name_
                    in a_multi
                    if addr_ and name_  # skip empty entries
                )
            else:
                records = self._a_records(name)
            return defer.succeed((records, self.authority, self.additional))

        # We need to catch everything. Uncaught exceptions will make the server
        # stop responding
        except DomainError as ex:
            log.msg("DomainError: %r " % ex)
            if self.config.get(NO_NXDOMAIN):
                # FIXME surely there's a better way to give SERVFAIL
                ex = DNSQueryTimeoutError(name)
            return defer.fail(failure.Failure(ex))
        except Exception as ex:  # pylint:disable=bare-except
            import traceback

            traceback.print_exc()

            if self.config.get(NO_NXDOMAIN):
                log.err()
                # FIXME surely there's a better way to give SERVFAIL
                exception = DNSQueryTimeoutError(name)
            else:
                exception = DomainError(name)

            return defer.fail(failure.Failure(exception))

    def lookupIPV6Address(self, name, timeout=None):
        """

        :param name: a name like container_name.docker, hostname.docker,
                image_name.*.docker
        :param timeout:
        :return: A deferred firing a 3-tuple
                The first element of the tuple gives answers.
                The second element of the tuple gives authorities.
                The third element of the tuple gives additional information.
                The Deferred may instead fail with one of the exceptions
                defined in twisted.names.error or
                with NotImplementedError.
        :type: Deferred

        """
        name, occurrences = self.re_domain.subn('', name)
        if not occurrences:
            log.err("Domain not ending with {domain}: {name}".format(
                name=name, **self.config))
            return defer.fail(failure.Failure(
                DomainError("not ending with docker"))
            )

        # Raise exception if host not found
        try:
            records = self._a_records(name)

        # We need to catch everything. Uncaught exceptions will make the server
        # stop responding
        except DomainError as ex:
            log.msg("DomainError: %r " % ex)
            if self.config.get(NO_NXDOMAIN):
                # FIXME surely there's a better way to give SERVFAIL
                ex = DNSQueryTimeoutError(name)
            return defer.fail(failure.Failure(ex))
        except Exception as ex:  # pylint:disable=bare-except
            import traceback

            traceback.print_exc()

            if self.config.get(NO_NXDOMAIN):
                log.err()
                # FIXME surely there's a better way to give SERVFAIL
                exception = DNSQueryTimeoutError(name)
            else:
                exception = DomainError(name)

                return defer.fail(failure.Failure(exception))
        # Otherwise no RR -> Answer RRs: 0
        empty_record = tuple()
        return defer.succeed((empty_record, self.authority, self.additional))

    def lookupService(self, name, timeout=None):
        """ Lookup a docker natted service of
             the form: NATTEDPORT._tcp.CONTAINERNAME.docker.
             and returns a srv record of the for:
             _service._proto.name. TTL class SRV priority weight port target.

            If _service == _nat:
        :return: A Deferred firing a three-tuple of lists of
            twisted.names.dns.RRHeader instances.
            The first element of the tuple gives answers.
            The second element of the tuple gives authorities.
            The third element of the tuple gives additional information.
            The Deferred may instead fail with one of the exceptions
            defined in twisted.names.error or with NotImplementedError.
        :type: Deferred
        """
        name, occurrences = self.re_domain.subn('', name)
        if not occurrences:
            log.err("Domain not ending with {domain}: {name}".format(
                name=name, **self.config))
            return defer.fail(failure.Failure(DomainError(
                "not ending with {domain}".format(**self.config)))
            )
        try:
            port, proto, container = name.split(".")
            port = int(port.strip("_"))
        except (IndexError, TypeError, ValueError) as ex:
            log.err("Domain not of the right form: %r" % name)
            return defer.fail(failure.Failure(
                DomainError("not of the right form"))
            )

        records = [dns.RRHeader(
            name, dns.SRV, dns.IN, self.ttl,
            payload=dns.Record_SRV(
                priority=100,
                weight=100,
                port=c_nat_port,
                target=self.my_preferred_ip_ptr_value,
                ttl=None),
            auth=True)
            for c_port, protocol, c_nat_port, target
            in self.mapping.get_nat(container)
            if c_port == port  # eventually filter
        ]
        return defer.succeed((records, self.authority, self.additional))

    def lookupPointer(self, name, timeout=None):
        """

        :param name: a ptr name like 1.0.17.172.in-addr.arpa
        :param timeout:
        :return: A deferred firing a 3-tuple
                The first element of the tuple gives answers.
                The second element of the tuple gives authorities.
                The third element of the tuple gives additional information.
                The Deferred may instead fail with one of the exceptions
                defined in twisted.names.error or
                with NotImplementedError.
        :type: Deferred

        """
        if not self.re_ptr.match(name):
            log.err("Domain not in docker network {bip}: {name}".format(
                name=name, **self.config))
            return defer.fail(failure.Failure(
                DomainError("not in docker network"))
            )

        try:
            records = self._ptr_record(name)
            return defer.succeed((records, self.authority, self.additional))

        # We need to catch everything. Uncaught exceptions will make the server
        # stop responding
        except DomainError as ex:
            log.msg("DomainError: %r " % ex)
        except Exception as ex:  # pylint:disable=bare-except
            import traceback
            traceback.print_exc()
            ex = DomainError(name)
        #
        # With NO_NXDOMAIN we mask everything with a Timeout
        #
        if self.config.get(NO_NXDOMAIN):
            # FIXME surely there's a better way to give SERVFAIL
            ex = DNSQueryTimeoutError(name)
        return defer.fail(failure.Failure(ex))
