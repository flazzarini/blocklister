import logging

from werkzeug.contrib.cache import SimpleCache
from flask import request

LOG = logging.getLogger(__name__)
cache = SimpleCache()


class cached(object):
    def __init__(self, timeout=300):
        self.timeout = timeout

    def __call__(self, f):
        def decorator(*args, **kwargs):
            path = request.path
            qargs = str(hash(frozenset(request.args.items())))
            keyname = "{}_{}".format(path, qargs)

            response = cache.get(keyname)
            if response is None:
                LOG.debug("Put response onto cache")
                response = f(*args, **kwargs)
                cache.set(keyname, response, self.timeout)
            else:
                LOG.debug("Got response from cache")
            return response
        return decorator
