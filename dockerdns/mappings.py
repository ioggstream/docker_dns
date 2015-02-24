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
        for map_name, search_f in (('name', self.db.get_by_name),
                                   ('hostname', self.db.get_by_hostname)):
            try:
                log.msg('lookup container by %r: %r' % (map_name, name))

                return search_f(name)
            except KeyError as e:
                # warn(str(e))
                log.msg("Container %r not found: %r" % (map_name, name))
            except Exception as e:
                log.err("Unmanaged error: %r" % e)

        return None

    def get_a(self, name):
        """
        Get an IPv4 address from a query name to be used in A record lookups

        :name: DNS query name to look up
        :return: IPv4 address for the query name given
        """

        container = self.lookup_container(name)

        if container is None:
            log.msg("No container found")
            return

        addr = container['NetworkSettings']['IPAddress']

        if not addr:
            log.msg("No IPAddress associated with container %r" % container)
            return None

        return addr

    def get_a_multi(self, image):
        """
        Return the IPs matching the given image name
        :param image:
        :return: a tuple of {(addr1, name1), .., (addrX, nameX)}
        """
        image, count = re.subn(r'\.\*$', '', image, 1)
        if not count:
            log.err("Not a multihost search: %r" % (image,))
            return
        return tuple(
                    (container['NetworkSettings'][
                     'IPAddress'], container['Name'][1:])
            for container
            in self.db.get_by_image(image)
            if 'NetworkSettings' in container
        )

    def get_nat(self, container_name, sport=0, sproto=None):
        """ @return - a generator of natted maps (local, proto, nat, ip)

            @param sport: the port to search
            @param sproto: the protocol to search

            eg. [ (8080, 'tcp', 18080, '0.0.0.0'),
                  (8787, 'tcp', 8787, '0.0.0.0'),
                ]rfiutato
        """
        sport = int(sport)
        container = self.lookup_container(container_name)
        if container is None:
            log.msg("No container found")
            return

        try:
            nats = container['NetworkSettings']['Ports'].items()
        except (KeyError, AttributeError) as ex:
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
                except (ValueError, KeyError) as ex:
                    log.err()
                    continue

    def get_ptr(self, ip):
        """
        Return the Hostname of the Container with the given IP
        :param ip:
        :return:
        """
        c = self.db.get_by_ip(ip)
        return c['Config']['Hostname']
