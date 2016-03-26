import logging
import time
from threading import Thread

from blocklister.models import Blocklist
from blocklister.config import Config

LOG = logging.getLogger(__name__)


class Updater(Thread):
    def __init__(self, config=Config()):
        Thread.__init__(self)
        self.config = config
        self.store = self.config.get(
            'blocklister', 'store', default="/tmp")
        self.interval = self.config.get_int(
            'blocklister', 'update_interval', default=120)

    def run(self):
        LOG.info("Start Blocklister-Updater")

        instances = []
        for subcls in Blocklist.__subclasses__():
            instances.append(subcls(self.store))

        while True:
            for instance in instances:
                if instance.fetcher.needs_update:
                    LOG.info(
                        "Updating Blocklister list {}".format(
                            instance.__class__.__name__))
                    instance.fetcher.update()
            time.sleep(self.interval)


def run():
    logging.basicConfig(level=logging.INFO)
    REQLOG = logging.getLogger("requests")
    URLLOG = logging.getLogger("urllib3")
    REQLOG.setLevel(logging.WARN)
    URLLOG.setLevel(logging.WARN)
    u = Updater()
    u.run()

if __name__ == "__main__":
    run()
