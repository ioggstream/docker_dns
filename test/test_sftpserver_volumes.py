"""
    author: roberto.polli@par-tec.it

    This class tests the SFTP Volume access.

    To access:
        - the container jboss63
        - with the volumes "/shared", "/var/log"

    # sftp -P 10022 jboss63@localhost # no password for now
    # pwd
    /
    # ls
    /shared
    /var

"""
from dockerdns.sftp import unix
from twisted.python import log
from nose.tools import (assert_true, assert_equal, raises,
                        assert_false, assert_is_instance)

MOCK_CONTAINER = "foo"


class MockDB():
    """Mocking L{DockerDB}"""

    def get_by_name(self, *a, **kw):
        return {
            "Volumes": {
                "/shared": "/data/docker/vfs/dir/ecdc183a5d7a2369a8cf1539dfed788dc677b81e0589b3aab7f5854921adbe90",
                "/shared1": "/data/docker/vfs/dir/ecdc183a5d7a2369a8cf1539dfed788dc677b81e0589b3aab7f5854921adbe90",
                "/var/log/sql": "/data/docker/vfs/dir/ecdc183a5d7a2369a8cf1539dfed788dc677b81e0589b3aab7f5854921adbe90"
            }
        }

# initialize
db = MockDB()
user = unix.DockerVolumeConchUser(MOCK_CONTAINER, db)
srv = unix.SFTPServerForDockerVolumeConchUser(user)


def test_get_homedir_is_rootdir():
    assert user.getHomeDir() == "/"


def test_abspath_volumes_to_real_folder():
    for p in (
            '/shared', '/shared/foo.txt', '/shared1', '/var/log/sql',
            '/var/log/sql/db.out'
    ):
        real_path = srv._absPath(p)
        log.msg("real path is %r" % real_path)
        yield assert_true, real_path.startswith("/data/docker"), \
              "Not starting with /data/docker: %r" % real_path


def test_abspath_files_outside_volumes():
    for p in '/var/log/messages /shared2 /shared2/'.split():
        ex = None
        try:
            real_path = srv._absPath(p)
            print("real path is %r" % real_path)
        except Exception as ex:
            pass
        yield assert_is_instance, ex, OSError


def test_unixdirectory_1():
    directory = unix.DockerVolumeDirectory(srv, '/')
    expected_files = {'shared', 'var', 'shared1'}
    assert_equal(set(directory.files), expected_files)


def test_unixdir_2():
    test_cases = [
        ('/var', {'log'}),
        ('/var/log', {'sql'})
    ]
    for dir, expected in test_cases:
        directory = unix.DockerVolumeDirectory(srv, dir)
        assert_equal, set(directory.files), expected, "%r" % [set(directory.files)]


@raises(OSError)
def test_unixdir_3():
    forbidden_dirs = "/root".split()
    for dir in forbidden_dirs:
        unix.DockerVolumeDirectory(srv, dir)


def test_fits():
    cases_true = [
        ("/var", "/var /var/log /var/log/messages".split()),
        ("/s", "/s /s/a.out".split()),
    ]
    for v, paths in cases_true:
        for p in paths:
            yield harn_fits, assert_true, v, p


def test_fits_false():
    cases_true = [
        ('/s', "/s1 /s1/ /s1/a.out".split())
    ]
    for v, paths in cases_true:
        for p in paths:
            yield harn_fits, assert_false, v, p


def harn_fits(checker, v, p):
    checker(srv._fits(v, p))
