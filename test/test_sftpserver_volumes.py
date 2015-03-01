from dockerdns.sftp import unix
from twisted.python import log
from nose.tools import assert_true, assert_equal
unix.container_database = dict(
    # container_name: volume_path
    foo={"Volumes": {
        "/shared": "/data/docker/vfs/dir/ecdc183a5d7a2369a8cf1539dfed788dc677b81e0589b3aab7f5854921adbe90",
        "/shared1": "/data/docker/vfs/dir/ecdc183a5d7a2369a8cf1539dfed788dc677b81e0589b3aab7f5854921adbe90",
        "/var/log/sql": "/data/docker/vfs/dir/ecdc183a5d7a2369a8cf1539dfed788dc677b81e0589b3aab7f5854921adbe90"

        }
    }
)
MOCK_CONTAINER = "foo"
user = unix.DockerVolumeConchUser(MOCK_CONTAINER)
srv = unix.SFTPServerForDockerVolumeConchUser(user)


def test_sftpserver_subpat():
    user = unix.DockerVolumeConchUser(MOCK_CONTAINER)
    assert user.getHomeDir() == "/"


def test_server():
    user = unix.DockerVolumeConchUser(MOCK_CONTAINER)
    srv = unix.SFTPServerForDockerVolumeConchUser(user)
    for p in (
        '/', '/shared', '/shared/foo'
    ):
        log.msg(srv._absPath(p))
        yield assert_true, srv._absPath(p).startswith("/data/docker")


def test_unixdirectory_1():
    directory = unix.UnixSFTPDirectory(srv, '/')
    assert_equal(set(directory.files), set(['shared', 'var', 'shared1']))

def test_unixdir_2():
    directory = unix.UnixSFTPDirectory(srv, '/var')
    assert_equal(set(directory.files), set(["log"]))

def test_unixdir_3():
    directory = unix.UnixSFTPDirectory(srv, '/var/log')
    assert_equal(set(directory.files), set(["sql"]))
