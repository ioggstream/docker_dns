from __future__ import print_function

from twisted.internet import reactor
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers
import os
from config import CONFIG
import simplejson as json
from twisted.internet.defer import Deferred, DeferredList
from twisted.internet.protocol import Protocol, ReconnectingClientFactory
from twisted.application import service, internet
from twisted.python import log, failure



class UpdateDB(Protocol):
    """Update docker ip store"""
    mappings = {}
    mappings_idx = {}

    def __init__(self, deferred):
        self.deferred = deferred

    def dataReceived(self, bytes_):
        if bytes_:
            item = json.loads(bytes_)
            print("Get container %r" % item)
            UpdateDB.updatedb(item)

    def connectionLost(self, reason):
        self.deferred.callback(None)

    @staticmethod
    def updatedb(item):
        assert 'Id' in item, "Entry has no Id"
        UpdateDB.mappings_idx.update({item['Name'][1:]: item['Id']})
        UpdateDB.mappings.update({item['Id']: item})

    @staticmethod
    def add_container(item):
        UpdateDB.updatedb(item)

    @staticmethod
    def del_container(id):
        name = UpdateDB.mappings[id]['Name'][1:]
        del UpdateDB.mappings[id]
        del UpdateDB.mappings_idx[name]

    @staticmethod
    def get_by_name(name):
        if name not in UpdateDB.mappings_idx:
            raise KeyError("%r not in %r" % (name, UpdateDB.mappings_idx))

        cid = UpdateDB.mappings_idx[name]
        if cid not in UpdateDB.mappings:
            raise KeyError("%r not in %r" % (cid, UpdateDB.mappings.keys()))
        return UpdateDB.mappings[id]


class UpdateDockerMapping(Protocol):
    """Parse docker events and update item store"""
    def __init__(self, agent, config):
        self.agent = agent
        self.config = config

        self.remaining = 1024 * 10
        self.buff = ""

    def update_record(self, item):
        """Update docker mapping
            item = {'status': ..., 'id': ...}
        """
        d = self.agent.request('GET',
                               os.path.join(self.config['docker_url'],
                                            'containers', item['id'], 'json')
                               )
        d.addCallback(
            lambda response: response.deliverBody(UpdateDB(Deferred())))

    def delete_record(self, item):
        """Update docker mapping
            item = {'status': ..., 'id': ...}
        """
        log.msg("removing item: %r" % item)
        UpdateDB.del_container(item['id'])

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
        except Exception:
            log.err("Generic Error")
            

    def connectionLost(self, reason):
        print('Finished receiving body:', reason.type, reason.value)
        Deferred().callback(None)


class EventFactory(ReconnectingClientFactory):
    # protocol = UpdateDockerMapping
    agent = Agent(reactor)
    agent2 = Agent(reactor, HTTPConnectionPool(reactor))

    def __init__(self, config, db=UpdateDB):
        log.msg("Initializing factory")
        self.db = db
        #
        # Create a protocol handler to parse docker container data
        #
        self.dockerUpdater = UpdateDockerMapping(agent=self.agent2, config=config)

        # Populate existing containers (this is ok to be blocking)

        #
        # Poll to the docker event interface
        #
        d = self.agent.request(
            'GET',
            os.path.join(config['docker_url'], 'events'),
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




