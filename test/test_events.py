from dockerdns.events import DockerDB, EventManager
import docker

from test import mock_list_containers, mock_lookup_container, mock_list_containers_2, mock_inspect_containers_2
from twisted.python import log
from twisted.web.client import Agent, Response, ResponseFailed
from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactor

from nose import SkipTest


def create_mock_db():
    """Create a mock DockerDB"""
    api = docker.Client()
    api.containers = mock_list_containers
    api.inspect_container = mock_lookup_container
    return DockerDB(api=api)


def create_mock_db2():
    """Create a mock DockerDB"""
    api = docker.Client()
    api.containers = mock_list_containers_2
    api.inspect_container = mock_inspect_containers_2
    return DockerDB(api=api)


def test_init():
    db = create_mock_db()
    ret = db.get_by_name('jboss631')
    assert ret, "Missing container"
    try:
        assert ret['NetworkSettings'][
            'IPAddress'] == '172.17.0.10', "item %r" % ret
    except KeyError as e:
        log.err("Bad container %r" % ret)
        raise


def test_get_by_ip():
    db = create_mock_db()
    ret = db.get_by_ip('172.17.0.10')
    assert ret, "Missing container"
    try:
        assert ret['NetworkSettings'][
            'IPAddress'] == '172.17.0.10', "item %r" % ret
    except KeyError as e:
        log.err("Bad container %r" % ret)
        raise


def test_init_and_get_images():
    db = create_mock_db2()
    # images are correctly added to the indexes
    assert 'impandas' in db.mappings_image, "%r, %r" % (
        db.mappings_image, db.mappings)
    assert 'cidpandas' in db.mappings_image['impandas'], "%r, %r" % (
        db.mappings_image, db.mappings)

    # images are correctly retrieved
    pandas_container = [x['Id'] for x in db.get_by_image('impandas')]
    assert set(pandas_container) == set(
        ('cidpandas', 'cidpandas0')), pandas_container


def test_clean_db():
    db = create_mock_db2()
    db.cleandb()
    assert not db.mappings, "Mappings not clean"
    assert not db.mappings_name, "Mappings not clean"
    assert not db.mappings_hostname, "Mappings not clean"
    assert not db.mappings_image, "Mappings not clean"


def test_reload_container():
    db = create_mock_db2()
    db.mappings = {}
    db.load_containers()
    assert db.mappings
    assert 'impandas' in db.mappings_image, "%r, %r" % (
        db.mappings_image, db.mappings)


class MockAgent(Agent):
    reasons = ['No Reason']

    def request(self, method, uri, **kw):
        #return defer.fail(ResponseFailed(reasons=self.reasons, response=None))
        d = defer.Deferred()
        d.addCallback(lambda *args: "ciao")
        return d


class TestEventManager(object):
    def setup(self):
        self.config = dict(docker_url='http://localhost:5000')
        self.db = create_mock_db()
        self.reactor = MemoryReactor()
        self.http_agent = MockAgent(self.reactor)

    def test_delete_record(self):
        em = EventManager(
            http_agent=self.http_agent, config=self.config, db=self.db)
        assert em
        em.delete_record({'status': 'stop', 'id': '7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4'})

    @SkipTest
    def test_update_record(self):
        em = EventManager(
            http_agent=self.http_agent, config=self.config, db=self.db)
        resp = yield em.update_record({'status': 'start', 'id': '7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4'})
        assert resp
