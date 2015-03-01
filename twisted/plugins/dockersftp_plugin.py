# -*- test-case-name: twisted.conch.test.test_tap -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Support module for making SSH servers with twistd.
"""
from zope.interface.declarations import implements
from twisted.application.service import IServiceMaker

from twisted.conch import checkers as conch_checkers
from twisted.cred import portal, checkers, strcred
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.application import strports
try:
    from twisted.cred import pamauth
except ImportError:
    pamauth = None

from dockerdns.sftp import factory
from dockerdns.sftp import unix, checkers as docker_checkers
class Options(usage.Options, strcred.AuthOptionMixin):
    synopsis = "[-i <interface>] [-p <port>] [-d <dir>] "
    longdesc = ("Makes a Conch SSH server.  If no authentication methods are "
        "specified, the default authentication methods are UNIX passwords, "
        "SSH public keys, and PAM if it is available.  If --auth options are "
        "passed, only the measures specified will be used.")
    optParameters = [
        ["interface", "i", "", "local interface to which we listen"],
        ["port", "p", "tcp:22", "Port on which to listen"],
        ["data", "d", "/etc", "directory to look for host keys in"],
        ["moduli", "", None, "directory to look for moduli in "
            "(if different from --data)"]
    ]
    compData = usage.Completions(
        optActions={"data": usage.CompleteDirs(descr="data directory"),
                    "moduli": usage.CompleteDirs(descr="moduli directory"),
                    "interface": usage.CompleteNetInterfaces()}
        )


    def __init__(self, *a, **kw):
        usage.Options.__init__(self, *a, **kw)

        # call the default addCheckers (for backwards compatibility) that will
        # be used if no --auth option is provided - note that conch's
        # UNIXPasswordDatabase is used, instead of twisted.plugins.cred_unix's
        # checker
        super(Options, self).addChecker(conch_checkers.UNIXPasswordDatabase())
        super(Options, self).addChecker(conch_checkers.SSHPublicKeyChecker(
            conch_checkers.UNIXAuthorizedKeysFiles()))
        if pamauth is not None:
            super(Options, self).addChecker(
                checkers.PluggableAuthenticationModulesChecker())
        self._usingDefaultAuth = True


    def addChecker(self, checker):
        """
        Add the checker specified.  If any checkers are added, the default
        checkers are automatically cleared and the only checkers will be the
        specified one(s).
        """
        if self._usingDefaultAuth:
            self['credCheckers'] = []
            self['credInterfaces'] = {}
            self._usingDefaultAuth = False
        super(Options, self).addChecker(checker)


class MyServiceMaker(object):
    """
        Define a MultiService running:
            - dns server for tcp and udp
            - http client for retrieving docker events
    """
    implements(IServiceMaker, IPlugin)
    tapname = "dockersftp"
    description = "Run this! It'll make your docker happy."
    options = Options

    def makeService(self, options):
        """
        Construct a service for operating a SSH server.

        @param options: An L{Options} instance specifying server options, including
        where server keys are stored and what authentication methods to use.

        @return: An L{IService} provider which contains the requested SSH server.
        """
        # The factory just sets the ssh keys
        t = factory.OpenSSHFactory()

        r = unix.DockerRealm()
        t.portal = portal.Portal(r, [docker_checkers.PermitChecker()])
        t.dataRoot = options['data']
        t.moduliRoot = options['moduli'] or options['data']

        port = options['port']
        if options['interface']:
            # Add warning here
            port += ':interface=' + options['interface']
        return strports.service(port, t)

#
# Create the MultiService
#
serviceMaker = MyServiceMaker()
