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
from twisted.python import log

agent1 = Agent(reactor)
agent2 = Agent(reactor, HTTPConnectionPool(reactor))


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
    def __init__(self, agent):
        self.remaining = 1024 * 10
        self.buff = ""
        self.agent = agent

    def update_record(self, item):
        """Update docker mapping
            item = {'status': ..., 'id': ...}
        """
        d = self.agent.request('GET',
                               os.path.join(CONFIG['docker_url'],
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
            log.exc()

    def connectionLost(self, reason):
        print('Finished receiving body:', reason.type, reason.value)
        Deferred().callback(None)


class EventFactory(ReconnectingClientFactory):
    # protocol = UpdateDockerMapping

    def __init__(self, agent, db=UpdateDB):
        log.msg("Initializing factory")
        self.agent = agent
        self.db = db
        d = self.agent.request(
            'GET',
            os.path.join(CONFIG['docker_url'], 'events'),
            Headers({'User-Agent': ['Twisted Web Client Example'],
                     'Content-Type': ['text/x-greeting']}),
            None)
        d.addCallbacks(self.cbResponse, lambda failure: print(str(failure)))

    def cbResponse(self, response):
        try:
            log.msg('Response received: %r' % response)
            finished = Deferred()
            response.deliverBody(UpdateDockerMapping(agent=agent2))
        except:
            log.err()

    def buildProtocol(self, addr):
        log.msg("addr: %r" % addr)
        return UpdateDockerMapping(agent=self.agent)


e_url = os.path.join(CONFIG['docker_url'], 'events')
efactory = EventFactory(agent=agent1)
log.msg("Created event Factory")
docker_event_monitor = internet.TCPClient('10.0.8.162', 5000, efactory)
