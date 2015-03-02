# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

import os
import re
import struct
from zope.interface import implementer

from twisted.conch.avatar import ConchUser
from twisted.conch.ssh import session, forwarding, filetransfer
from twisted.conch.unix import (UnixSFTPFile, SSHSessionForUnixConchUser,
                                SFTPServerForUnixConchUser, UnixSFTPDirectory)
from twisted.cred import portal
from twisted.python import components, log


@implementer(portal.IRealm)
class DockerRealm:
    def __init__(self, container_db):
        self.container_db = container_db

    def requestAvatar(self, username, mind, *interfaces):
        user = DockerVolumeConchUser(username, self.container_db)
        return interfaces[0], user, user.logout


class DockerVolumeConchUser(ConchUser):
    def __init__(self, container_name, container_db):
        ConchUser.__init__(self)
        self.container_name = container_name
        container = container_db.get_by_name(container_name)
        self.volumes = {
            k.encode('utf-8'): v.encode('utf-8')
            for k, v
            in container.get("Volumes", {}).items()
        }
        self.listeners = {}  # dict mapping (interface, port) -> listener
        self.channelLookup.update(
            {"session": session.SSHSession,
             "direct-tcpip": forwarding.openConnectForwardingClient})

        self.subsystemLookup.update(
            {"sftp": filetransfer.FileTransferServer})

    def getUserGroupId(self):
        return os.getuid(), os.getgid()

    def getOtherGroups(self):
        return tuple()

    def getHomeDir(self):
        return "/"

    def getShell(self):
        return "/sbin/nologin"

    def global_tcpip_forward(self, data):
        hostToBind, portToBind = forwarding.unpackGlobal_tcpip_forward(data)
        from twisted.internet import reactor

        try:
            listener = self._runAsUser(
                reactor.listenTCP, portToBind,
                forwarding.SSHListenForwardingFactory(
                    self.conn,
                    (hostToBind, portToBind),
                    forwarding.SSHListenServerForwardingChannel
                ),
                interface=hostToBind)
        except:
            return 0
        else:
            self.listeners[(hostToBind, portToBind)] = listener
            if portToBind == 0:
                portToBind = listener.getHost()[2]  # the port
                return 1, struct.pack('>L', portToBind)
            else:
                return 1

    def global_cancel_tcpip_forward(self, data):
        hostToBind, portToBind = forwarding.unpackGlobal_tcpip_forward(data)
        listener = self.listeners.get((hostToBind, portToBind), None)
        if not listener:
            return 0
        del self.listeners[(hostToBind, portToBind)]
        self._runAsUser(listener.stopListening)
        return 1

    def logout(self):
        # remove all listeners
        for listener in self.listeners.itervalues():
            self._runAsUser(listener.stopListening)
        log.msg('avatar %s logging out (%i)' % (
            self.container_name, len(self.listeners)))

    def _runAsUser(self, f, *args, **kw):
        euid = os.geteuid()
        egid = os.getegid()
        groups = os.getgroups()
        uid, gid = self.getUserGroupId()
        # os.setegid(0)
        # os.seteuid(0)
        # os.setgroups(self.getOtherGroups())
        # os.setegid(gid)
        # os.seteuid(uid)
        try:
            f = iter(f)
        except TypeError:
            f = [(f, args, kw)]
        try:
            for i in f:
                func = i[0]
                args = len(i) > 1 and i[1] or ()
                kw = len(i) > 2 and i[2] or {}
                if func in (os.lstat,):
                    for from_, to_ in self.volumes.items():
                        args = [re.sub(from_, to_, x) for x in args]
                r = func(*args, **kw)
        finally:
            # os.setegid(0)
            # os.seteuid(0)
            # os.setgroups(groups)
            # os.setegid(egid)
            # os.seteuid(euid)
            pass
        return r


class SFTPServerForDockerVolumeConchUser(SFTPServerForUnixConchUser):
    def __init__(self, avatar):
        SFTPServerForUnixConchUser.__init__(self,
                                            avatar)

    def _absPath(self, path):
        import re

        allowed_paths = tuple(self.avatar.volumes.keys()) + (".", "/")
        home = self.avatar.getHomeDir()
        if path.startswith(allowed_paths):
            apath = os.path.abspath(os.path.join(home, path))
            if apath == "/":
                return apath

            for v, folder in self.avatar.volumes.items():
                apath = re.sub('^' + v, folder, apath)
            return apath

        log.msg("not outside container path: %r" % [
            path,
            self.avatar.volumes.keys()]
        )
        os.stat("/dev/File not found")

    def openFile(self, filename, flags, attrs):
        return UnixSFTPFile(self, self._absPath(filename), flags, attrs)

    def openDirectory(self, path):
        return DockerVolumeDirectory(self, self._absPath(path))


class DockerVolumeDirectory(UnixSFTPDirectory):
    """
    Expose volumes of an host as tree.

    """

    @staticmethod
    def _dirname(path):
        try:
            return path.split("/")[1]
        except IndexError, TypeError:
            return path

    def __init__(self, server, directory):
        self.server = server
        allowed_volumes, allowed_paths = zip(
            *self.server.avatar.volumes.items())
        if directory == "/":
            self.files = [self._dirname(x)
                          for x
                          in allowed_volumes]
        elif any(x for x in allowed_volumes if x.startswith(directory)):
            self.files = [self._dirname(x.replace(directory, ""))
                          for x
                          in allowed_volumes
                          if x.startswith(directory)]
        else:
            log.err("Accessing %r" % directory)
            if not directory.startswith(tuple(allowed_paths)):
                raise OSError(2, "No such file or directory", directory)
            self.files = server.avatar._runAsUser(os.listdir, directory)
        self.dir = directory


components.registerAdapter(SFTPServerForDockerVolumeConchUser,
                           DockerVolumeConchUser, filetransfer.ISFTPServer)
components.registerAdapter(
    SSHSessionForUnixConchUser, DockerVolumeConchUser, session.ISession)
