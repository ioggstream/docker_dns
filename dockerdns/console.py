"""
    Management Console
"""
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.web.http import Request
from events import DockerDB
import simplejson
import time


class RestConsole(Resource):
    isLeaf = True

    def __init__(self, db):
        """

        :param db:
        :return:
        """
        assert isinstance(db, DockerDB)
        self.db = db

    def dump(self, table, k=None):
        """
        Return a value from a given mapping of DB. This should be moved to DockerDB
        """
        try:
            d = getattr(self.db, 'mappings_' + table if table != "id" else "mappings" )
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
        serialize = lambda x: simplejson.dumps(x, indent=True)
        assert isinstance(request, Request)
        r = request.path.strip("/").split("/")
        action = r[0]
        
	
        if 'ping' in request.path:
            return "<html><body>%s</body></html>" % [time.ctime(), request.path]

        return serialize(self.dump(action, *r[1:]))
        #    return serialize(dict(error='command not found', msg='try http://localhost:8080/{hostname,image,dump}/'))

class ConsoleFactory(Site):
    def __init__(self, db):
        Site.__init__(self, RestConsole(db))

