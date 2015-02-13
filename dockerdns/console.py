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

    def render_GET(self, request):
        """

        :param request:
        :type twisted.web.http.Request
        :return:
        """
        serialize = lambda x: simplejson.dumps(x, indent=True)
        assert isinstance(request, Request)
        if 'ping' in request.path:
            return "<html><body>%s</body></html>" % (time.ctime(),)
        elif 'hostname/' in request.path:
            return serialize(self.db.mappings_hostname)
        elif 'image/' in request.path:
            return serialize(self.db.mappings_image)
        elif 'dump/' in request.path:
            return serialize(self.db.mappings)
        else:
            return serialize(dict(error='command not found',
                                  msg='try http://localhost:8080/{hostname,image,dump}/'))

class ConsoleFactory(Site):
    def __init__(self, db):
        Site.__init__(self, RestConsole(db))

