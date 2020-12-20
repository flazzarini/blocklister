import logging

from flask import Flask, request, render_template, make_response
from flask_limiter import Limiter

from blocklister import __version__, __changelog__
from blocklister.models import Blocklist
from blocklister.config import Config
from blocklister.exc import FetcherException, EmptyListError
from blocklister.summerizer import Summerizer

LOG = logging.getLogger(__name__)
app = Flask(__name__)
limiter = Limiter(app, headers_enabled=True)
config = Config()
store = config.get('blocklister', 'store', default="/tmp")
dedupe = config.get_boolean('blocklister', 'deduplicate', default=False)


@app.errorhandler(IOError)
def handle_filenotavailable(exc):
    msg = "File on disk is not available"
    response = make_response(msg, 500)
    response.headers['Content-Type'] = "text/plain"
    return response


@app.errorhandler(ValueError)
def handle_unknown_blacklist(exc):
    routes = [
        "/%s" % x.__name__.lower() for x in Blocklist.__subclasses__()
    ]
    msg = render_template(
        'unknown_blacklist.jinja2',
        routes=routes,
        exc=exc,
    )
    response = make_response(msg, 404)
    response.headers['Content-Type'] = "text/plain"
    return response


@app.errorhandler(EmptyListError)
def handle_empty_ip_list(exc):
    response = make_response(str(exc), 404)
    response.headers['Content-Type'] = "text/plain"
    return response


@app.errorhandler(FetcherException)
def handle_downloaderror(exc):
    msg = (
        "Fetcher was unable to download the latest file from upstream "
        "provider")
    response = make_response(msg, 500)
    response.headers['Content-Type'] = "text/plain"
    return response


@app.errorhandler(429)
def handle_ratelimit(exc):
    msg = "Too Many Request from your ip"
    response = make_response(msg, 429)
    response.headers['Content-Type'] = "text/plain"
    return response


@limiter.request_filter
def check_whitelist():
    whitelist_ips = config.get('blocklister', 'whitelist_ips', "").split("\n")
    if request.remote_addr in whitelist_ips:
        LOG.debug("%s is whitelisted" % request.remote_addr)
        return True
    return False


@app.route("/", methods=['GET'])
def index():
    lists = []
    for subcls in Blocklist.__subclasses__():
        lists.append(subcls.__name__)

    result = render_template(
        "welcome.jinja2",
        lists=sorted(lists),
        version=__version__)
    response = make_response(result, 200)
    response.headers['Content-Type'] = "text/plain"
    return response


@app.route("/changelog", methods=['GET'])
def changelog():
    response = make_response(__changelog__, 200)
    response.headers['Content-Type'] = "text/plain"
    return response


@limiter.limit("50 per day")
@app.route("/<string:blacklist>", methods=['GET'])
def get_list(blacklist):
    # Get query arguments
    cidr_notation = request.args.get('cidr', default=False)

    # First find the right class
    bl = Blocklist.get_class(blacklist, store)
    ips = bl.get_ips(cidr_notation=cidr_notation)

    if not ips:
        raise EmptyListError("No ips found for %s" % blacklist.title())

    # If deduplicating, process
    if dedupe:
        smr = Summerizer(ips)
        ips = smr.summary()

    # Get User variables if any
    listname = request.args.get(
        "listname", default="%s_list" % bl.__class__.__name__.lower())
    comment = request.args.get(
        "comment", default="%s" % bl.__class__.__name__.title())

    result = render_template(
        "mikrotik_addresslist.jinja2",
        ips=ips,
        listname=listname,
        comment=comment
    )
    response = make_response(result, 200)
    response.headers['Content-Type'] = "text/plain"
    return response


@limiter.limit("10 per day")
@app.route("/multilist", methods=['GET'])
def get_multiple_lists():
    # Get query arguments
    cidr_notation = request.args.get('cidr', default=False)

    blocklists = request.args.get('blocklists', default=None)
    listname = request.args.get("listname", default="blocklist")
    blists = [] if not blocklists else blocklists.split(',')
    comment = request.args.get("comment", default="multilist")
    ips = []

    for blist in blists:
        try:
            bl = Blocklist.get_class(blist, store)
            ips.extend(bl.get_ips(cidr_notation=cidr_notation))
        except ValueError:
            # Silently ignore unknown blocklist
            pass

    # Make List of ips unique and sorted
    ips = list(set(ips))
    ips.sort()

    result = render_template(
        "mikrotik_addresslist.jinja2",
        ips=ips,
        listname=listname,
        comment=comment)
    response = make_response(result, 200)
    response.headers['Content-Type'] = "text/plain"
    return response


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    app.debug = True
    app.run()
