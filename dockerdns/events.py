from __future__ import print_function

"""
    Populate dns database getting info from docker via:
        - docker-py api
        - docker events interface
"""
from twisted.internet import reactor
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers
from os.path import join as pjoin
import simplejson as json
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol, ReconnectingClientFactory
from twisted.python import log


class DockerDB(object):
    """Update docker ip store connecting via docker-py
    """

    def __init__(self, api=None):
        """

        :param api: a docker.Client instance
        :return:
        """
        self.api = api
        # container list and some indexes:
        #  - name: id
        #  - image: names
        #  - hostname: id
        self.mappings = {}
        self.mappings_name = {}
        self.mappings_image = {}
        self.mappings_hostname = {}
        #
        # Initialize db (TODO get initialization timestamp)
        for c in self.api.containers(all=True):
            item = self.api.inspect_container(c['Id'])
            self.updatedb(item)

    def updatedb(self, item):
        assert 'Id' in item, "Entry has no Id"

        name = item['Name'][1:]
        hostname = item['Config']['Hostname']
        self.mappings_name.update({name: item['Id']})
        self.mappings_hostname.update({hostname: item['Id']})
        self.mappings.update({item['Id']: item})
        self.mappings_image.setdefault(
            item['Config']['Image'], []).append(item['Id'])

    def add_container(self, item):
        self.updatedb(item)

    def del_container(self, cid):
        name = self.mappings[cid]['Name'][1:]
        image = self.mappings[cid]['Config']['Image']
        hostname = self.mappings[cid]['Config']['Hostname']
        self.mappings_image.get(image, []).remove(cid)
        del self.mappings[cid]
        del self.mappings_name[name]
        del self.mappings_hostname[hostname]

    def get_by_name(self, name):
        if name not in self.mappings_name:
            raise KeyError("%r not in %r" % (name, self.mappings_name))

        cid = self.mappings_name[name]
        if cid not in self.mappings:
            raise KeyError("%r not in %r" % (cid, self.mappings.keys()))
        return self.mappings[cid]

    def get_by_hostname(self, name):
        if name not in self.mappings_hostname:
            raise KeyError("%r not in %r" % (name, self.mappings_hostname))

        cid = self.mappings_hostname[name]
        if cid not in self.mappings:
            raise KeyError("%r not in %r" % (cid, self.mappings.keys()))
        return self.mappings[cid]

    def get_by_image(self, image):
        """

        :param image:
        :return: an generator of container dicts
        """
        if image not in self.mappings_image:
            raise KeyError("%r not in %r" % (image, self.mappings_hostname))
        for cid in self.mappings_image[image]:
            yield self.mappings[cid]


class ContainerManager(Protocol):
    """Manage the response to /containers/{id}/json
        updating the network infos associated to the container
    """

    def __init__(self, onLost, db):
        """Initialize the Docker host database"""
        self.onLost = onLost
        self.db = db

    def dataReceived(self, bytes_):
        if bytes_:
            item = json.loads(bytes_)
            print("Get container %r" % item)
            self.db.updatedb(item)

    def connectionLost(self, reason):
        self.onLost.callback(None)


class EventManager(Protocol):
    """Manage the response to /events/json
        - start: triggers a further request with a ContainerManager cb
        - stop|die: removes the associations from IPs
    """

    def __init__(self, http_agent, config, db):
        self.http_agent = http_agent
        self.config = config
        self.db = db

        self.remaining = 1024 * 10
        self.buff = ""
        # Create an event_manager for parsing updates
        self.event_manager = ContainerManager(Deferred(), db=db)

    def update_record(self, item):
        """Update docker mapping
            item = {'status': ..., 'id': ...}
        """
        d = self.http_agent.request('GET',
                                    pjoin(self.config['docker_url'],
                                          'containers', item['id'], 'json')
                                    )
        d.addCallback(
            lambda response: response.deliverBody(self.event_manager))

    def delete_record(self, item):
        """Update docker mapping
            item = {'status': ..., 'id': ...}
        """
        log.msg("removing item: %r" % item)
        self.db.del_container(item['id'])

    def dataReceived(self, bytes_):
        """Get the container id and calls the updater"""
        try:
            if self.remaining:
                display = bytes_[:self.remaining]
                print('Some data received:', display)
                self.remaining -= len(display)
                item = json.loads(display)
                print("Parsed: %r" % item)
                if item['status'] == 'start':
                    self.update_record(item)
                elif item['status'] in ('stop', 'die'):
                    self.delete_record(item)
        except KeyError:
            log.err("Container not found")
        except json.scanner.JSONDecodeError:
            log.err("Error reading data")
        except Exception as e:
            log.err("Generic Error %r" % e)

    def connectionLost(self, reason):
        print('Finished receiving body:', reason.type, reason.value)
        Deferred().callback(None)


class EventFactory(ReconnectingClientFactory):
    """Factory to connect to docker api interface and trigger
        the first /events/ call.

    """
    agent = Agent(reactor)
    agent2 = Agent(reactor, HTTPConnectionPool(reactor))

    def __init__(self, config, db):
        """

        :param config: contains the docker url to poll
        :param db: the mappings between containers and
        :return:
        """
        log.msg("Initializing factory")
        self.db = db
        #
        # Create a protocol handler to parse docker container data
        #
        self.dockerUpdater = EventManager(
            http_agent=self.agent2, config=config, db=db)

        # Populate existing containers (this is ok to be blocking)

        #
        # Poll to the docker event interface
        #
        d = self.agent.request(
            'GET',
            pjoin(config['docker_url'], 'events'),
            Headers({'User-Agent': ['Twisted Web Client for Docker Event'],
                     'Content-Type': ['application/json']}),
            None)
        d.addCallbacks(self.cbResponse, lambda failure: print(str(failure)))

    def cbResponse(self, response):
        """Manages the response using a Protocol class defined in __init__"""
        try:
            log.msg('Response received: %r' % response)
            finished = Deferred()
            response.deliverBody(self.dockerUpdater)
        except:
            log.err()

    def buildProtocol(self, addr):
        log.msg("addr: %r" % addr)
        return self.dockerUpdater
