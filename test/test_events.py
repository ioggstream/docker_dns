from dockerdns.events import DockerDB
import docker
from test import mock_list_containers, mock_lookup_container, mock_list_containers_2, mock_inspect_containers_2
from twisted.python import log


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
