import logging
import time
from threading import Thread

from blocklister.models import Blocklist

store = '/tmp'
LOG = logging.getLogger(__name__)


class Updater(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        LOG.info("Start Blocklister-Updater")

        instances = []
        for subcls in Blocklist.__subclasses__():
            instances.append(subcls(store))

        while True:
            for instance in instances:
                if instance.fetcher.needs_update:
                    LOG.info(
                        "Updating Blocklister list {}".format(
                            instance.__class__.__name__))
                    instance.fetcher.update()
            time.sleep(20)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    REQLOG = logging.getLogger("requests")
    URLLOG = logging.getLogger("urllib3")
    REQLOG.setLevel(logging.WARN)
    URLLOG.setLevel(logging.WARN)
    u = Updater()
    u.run()
