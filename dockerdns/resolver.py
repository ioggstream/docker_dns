import re
from twisted.python import log
from twisted.internet import defer
from twisted.internet.defer import failure
from twisted.names import common, dns
from twisted.names.error import DomainError, DNSQueryTimeoutError
from dockerdns.utils import get_preferred_ip


# pylint:disable=too-many-public-methods
NO_NXDOMAIN = 'no_nxdomain'


class DockerResolver(common.ResolverBase):
    """
    DNS resolver to resolve queries with a DockerMapping instance.

    Twisted Names just uses the lookupXXX methods
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

    def __init__(self, mapping, config=None):
        """
        :param mapping: DockerMapping instance for lookups
        """

        self.mapping = mapping
        self.config = config or {'domain': 'docker'}
        self.re_domain = re.compile(r'\.' + self.config['domain'] + '$')
        # Change to this ASAP when Twisted uses object base
        # super(DockerResolver, self).__init__()
        common.ResolverBase.__init__(self)
        self.ttl = 10
        self.my_preferred_ip, self.my_preferred_ip_ptr_value = get_preferred_ip()

        # define authority and additional records
        # an authority record defines the name IN NS TIMEOUT
        # socket.
        import socket

        self.authority = [dns.RRHeader(
            name=self.config['domain'] + ".", type=dns.NS, cls=dns.IN,
                                       payload=dns.Record_NS(
                                           name=socket.gethostname())
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
                '.'.join(
                    (name, self.config['domain'])), dns.A, dns.IN, self.ttl,
                         dns.Record_A(addr, self.ttl),
                         auth=self.config.get('authoritative'))
        ])

    def _srv_records(self, name):
        print("getting srv: %r" + name)
        addr = self.mapping.get_a(name)
        return tuple([
            dns.RRHeader(
                '.'.join(
                    (name, self.config['domain'])), dns.SRV, dns.IN, self.ttl,
                         dns.Record_A(addr, self.ttl),
                         auth=self.config.get('authoritative'))
        ])

    def lookupAddress(self, name, timeout=None):
        """

        :param name: a name like container_name.docker, hostname.docker, image_name.*.docker
        :param timeout:
        :return: A deferred firing a 3-tuple
                    The first element of the tuple gives answers.
                    The second element of the tuple gives authorities.
                    The third element of the tuple gives additional information.
                    The Deferred may instead fail with one of the exceptions defined in twisted.names.error
                    or with NotImplementedError. (type: Deferred)

        """
        name, occurrences = self.re_domain.subn('', name)
        if not occurrences:
            log.err("Domain not ending with {domain}: {name}".format(
                name=name, **self.config))
            return defer.fail(failure.Failure(DomainError("not ending with docker")))

        try:
            if name.endswith(".*"):
                a_multi = self.mapping.get_a_multi(name)
                log.msg(a_multi)
                records = tuple(
                    dns.RRHeader(
                        '.'.join((name_, self.config[
                                 'domain'])), dns.A, dns.IN, self.ttl,
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
        except DomainError as e:
            log.msg("DomainError: %r " % e)
            if self.config.get(NO_NXDOMAIN):
                # FIXME surely there's a better way to give SERVFAIL
                e = DNSQueryTimeoutError(name)
            return defer.fail(failure.Failure(e))
        except Exception as e:  # pylint:disable=bare-except
            import traceback

            traceback.print_exc()

            if self.config.get(NO_NXDOMAIN):
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

            If _service == _nat:
             :return: -    A Deferred which fires with a three-tuple of lists of twisted.names.dns.RRHeader instances.
                  The first element of the tuple gives answers.
                  The second element of the tuple gives authorities.
                  The third element of the tuple gives additional information.
                  The Deferred may instead fail with one of the exceptions defined in twisted.names.error or with NotImplementedError. (type: Deferred)
        """
        name, occurrences = self.re_domain.subn('', name)
        if not occurrences:
            log.err("Domain not ending with {domain}: {name}".format(
                name=name, **self.config))
            return defer.fail(failure.Failure(DomainError("not ending with {domain}".format(**self.config))))
        try:
            port, proto, container = name.split(".")
            port = int(port.strip("_"))
        except (IndexError, TypeError, ValueError) as e:
            log.err("Domain not of the right form: %r" % name)
            return defer.fail(failure.Failure(DomainError("not of the right form")))

        records = [dns.RRHeader(
            name, dns.SRV, dns.IN, self.ttl,
            dns.Record_SRV(
                priority=100, weight=100, port=c_nat_port, target=self.my_preferred_ip_ptr_value, ttl=None),
            auth=True)
            for c_port, protocol, c_nat_port, target
                   in self.mapping.get_nat(container)
                   if c_port == port  # eventually filter
        ]
        return defer.succeed((records, self.authority, self.additional))
