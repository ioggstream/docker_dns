"""
    Maps DNS requests to host
"""
import re
from twisted.python import log


class DockerMapping(object):
    """
    Look up docker info via  docker.api and

    XXX Should it be dns-agnostic, and just a wrapper around docker.api

    TODO:

    """

    def __init__(self, db=None):
        """
        Args:
            db: a DockerDB instance containing infos
        """
        self.db = db

    def lookup_container(self, name):
        """
        Gets the container config from container name or hostname

        Args:
            name: DNS query name to look up

        Returns:
            Container config dict for the first matching container
        """
        for search_f in (self.db.get_by_name, self.db.get_by_hostname):
            try:
                log.msg('lookup container: %r' % name)

                return search_f(name)
            except KeyError as e:
                # warn(str(e))
                log.msg("Container not found: %r" % name)
            except Exception as e:
                log.err("Unmanaged error: %r" % e)

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
            log.msg("No container found")
            return

        addr = container['NetworkSettings']['IPAddress']

        if not addr:
            return None

        return addr

    def get_a_multi(self, name_multi):
        """

        :param name_multi: [(addr1, name1), .., (addrX, nameX)]
        :return: a tuple of addresses
        """
        name_multi, count = re.subn(r'\.\*$', '', name_multi, 1)
        if not count:
            log.err("Not a multihost search: %r" % (name_multi,))
            return
        return tuple(
                    (container['NetworkSettings'][
                     'IPAddress'], container['Name'][1:])
            for container
                     in self.db.get_by_image(name_multi)
                     if 'NetworkSettings' in container
        )

    def get_nat(self, container_name, sport=0, sproto=None):
        """ @return - a generator of natted maps (local, proto, nat, ip)

            @param sport: the port to search
            @param sproto: the protocol to search

            eg. [ (8080, 'tcp', 18080, '0.0.0.0'),
                  (8787, 'tcp', 8787, '0.0.0.0'),
                ]
        """
        sport = int(sport)
        container = self.lookup_container(container_name)
        if container is None:
            log.msg("No container found")
            return

        try:
            nats = container['NetworkSettings']['Ports'].items()
        except (KeyError, AttributeError) as e:
            # container infos set and not None
            log.err("Bad network information for container: %r" % container)

        for local, remote in nats:
            if not remote:
                continue
            #
            # filter for port and protocol
            #
            port, proto = local.split("/")
            port = int(port)
            if sport and sport != port:
                continue
            if sproto and sproto != proto:
                continue

            for r in remote:
                try:
                    yield (port, proto, int(r['HostPort']), r['HostIp'])
                except (ValueError, KeyError) as e:
                    log.err()
                    continue
