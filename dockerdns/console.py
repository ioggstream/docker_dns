"""
    author: robipolli@gmail.com
    Management Console
"""
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.web.http import Request
from dockerdns.events import DockerDB
import simplejson
import time

HELP_STR = """
Allowed commands:

Retrieve container names \t\t\tcurl 'http://localhost:8080/name'
Retrieve container hostnames \t\t\tcurl 'http://localhost:8080/hostname'
Retrieve container ids\t\t\tcurl 'http://localhost:8080/id'
Refresh dns mapping\t\t\tcurl -XPOST 'http://localhost:8080/refresh'

"""


def serialize(item):
    return simplejson.dumps(item, indent=True)


class RestConsole(Resource):
    isLeaf = True

    def __init__(self, db):
        """

        :param db:
        :return:
        """
        assert isinstance(db, DockerDB)
        self.db = db
        Resource.__init__(self)

    def dump(self, table, k=None):
        """
        Return a value from a given mapping of DB.
        TODO This should be moved to DockerDB
        """
        try:
            d = getattr(self.db, 'mappings_' +
                        table if table != "id" else "mappings")
        except AttributeError:
            return "Table not found %r" % table

        if k:
            return d[k]

        return d

    def render_GET(self, request):
        """

        :param request:
        :type twisted.web.http.Request
        :return:
        """
        assert isinstance(request, Request)
        rpath = request.path.strip("/").split("/")
        action = rpath[0]

        if 'ping' in request.path:
            return "<html><body>{0:s}</body></html>".format([
                time.ctime(), request.path])
        if action in ('help', 'refresh'):
            return HELP_STR

        return serialize(self.dump(action, *rpath[1:]))

    def render_POST(self, request):
        """

        :param request:
        :type twisted.web.http.Request
        :return:
        """
        assert isinstance(request, Request)
        rpath = request.path.strip("/").split("/")
        action = rpath[0]

        if action == 'refresh':
            self.db.cleandb()
            self.db.load_containers()
            return serialize(dict(status="ok", action="refresh"))
        raise ValueError("Not Found")


class ConsoleFactory(Site):
    def __init__(self, db):
        Site.__init__(self, RestConsole(db))
