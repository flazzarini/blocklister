import logging
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from gzip import GzipFile
from io import BytesIO
from os.path import join
from datetime import datetime
from os.path import getmtime, exists

from blocklister.exc import DownloadError


LOG = logging.getLogger(__name__)


class Blocklist(object):
    source = "http://bogus.site.com"
    regex = (
        "^.*:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-"
        "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    )
    template = "firewall_addresslist.jinja2"
    gzip = False

    def __init__(self, store, filename=None):
        self.name = self.__class__.__name__.lower()
        self.store = store
        self.filename = filename if filename else join(self.name + '.txt')
        self.filepath = join(self.store, self.filename)
        self.request = Request(self.source)

    def __repr__(self):
        return (
            "{0}({1}, filename={2})".format(
                self.__class__.__name__, self.store, self.filename
            )
        )

    @property
    def file_exists(self):
        if exists(self.filepath):
            LOG.debug("File {} exists".format(self.filepath))
            return True
        else:
            LOG.debug("File {} does not exists".format(self.filepath))
            return False

    @property
    def last_saved(self):
        if exists(self.filepath):
            file_date = datetime.fromtimestamp(getmtime(self.filepath))
            LOG.debug("File has a timestamp of {}".format(file_date))
            return file_date
        raise IOError("File not found")

    def get(self, request=None):
        try:
            LOG.info(
                "Downloading new version of list from {}"
                .format(self.source)
            )
            if not request:
                request = self.request

            with urlopen(request) as response:
                raw_content = response.read()

                if self.gzip:
                    LOG.debug("Source file is gziped, unpack file first")
                    buf = BytesIO(raw_content)
                    data = GzipFile(fileobj=buf)
                    raw_content = data.read().decode('utf-8')
                    data.close()
                    buf.close()

                destination_file = join(self.store, self.filename)

                with open(destination_file, 'w') as fileobj:
                    fileobj.write(raw_content)
                    LOG.debug("File written to {}".format(destination_file))

                return raw_content
        except (HTTPError, URLError) as exc:
            raise DownloadError("Could not download source {}".format(exc))
        except IOError as exc:
            raise DownloadError("Could not write file to disk {}".format(exc))

    def get_ips(self):
        results = []
        with open(self.filepath, 'r') as f:
            for line in f:
                res = re.search(self.regex, line)

                if not res:
                    continue

                entry = ""
                for el in res.groups():
                    if not entry:
                        entry = "{}".format(el)
                    else:
                        entry = "{}-{}".format(entry, el)

                results.append(entry)
        return list(set(results))

    @classmethod
    def get_class(cls, name, store):
        """
        Run through all subclassess of `Blocklist` and return the
        appropiate class, if None was found raise a `ValueError`

        :param name: str Classname to look up
        :param store: str which storage to use
        :rtype instance
        :returns Class instance for which we were looking for
        """
        for subcls in cls.__subclasses__():
            if subcls.__name__ == name.title():
                return subcls(store)
        raise ValueError("No class found for {}".format(name))


class Ads(Blocklist):
    source = "http://list.iblocklist.com/?list=bt_ads"
    gzip = True


class Spyware(Blocklist):
    source = "http://list.iblocklist.com/?list=bt_spyware"
    gzip = True


class Level1(Blocklist):
    source = "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw"
    gzip = True


class Level2(Blocklist):
    source = "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw"
    gzip = True


class Level3(Blocklist):
    source = "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh"
    gzip = True


class Edu(Blocklist):
    source = "http://list.iblocklist.com/?list=imlmncgrkbnacgcwfjvh"
    gzip = True


class Proxy(Blocklist):
    source = "http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb"
    gzip = True


class Badpeers(Blocklist):
    source = "http://list.iblocklist.com/?list=cwworuawihqvocglcoss"
    gzip = True


class Microsoft(Blocklist):
    source = "http://list.iblocklist.com/?list=xshktygkujudfnjfioro"
    gzip = True


class Spider(Blocklist):
    source = "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy"
    gzip = True


class Hijacked(Blocklist):
    source = "http://list.iblocklist.com/?list=usrcshglbiilevmyfhse"
    gzip = True


class Dshield(Blocklist):
    source = "http://list.iblocklist.com/?list=xpbqleszmajjesnzddhv"
    gzip = True


class Malwaredomainlist(Blocklist):
    source = "http://www.malwaredomainlist.com/hostslist/ip.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"


class Openbl(Blocklist):
    source = "https://www.openbl.org/lists/base.txt.gz"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"
    gzip = True


class Openbl_180(Blocklist):
    source = "https://www.openbl.org/lists/base_180days.txt.gz"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"
    gzip = True


class Openbl_360(Blocklist):
    source = "https://www.openbl.org/lists/base_360days.txt.gz"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"
    gzip = True


class Spamhausdrop(Blocklist):
    source = "https://www.spamhaus.org/drop/drop.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$"


class Spamhausedrop(Blocklist):
    source = "https://www.spamhaus.org/drop/edrop.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$"


class Blocklistde_All(Blocklist):
    source = "http://lists.blocklist.de/lists/all.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"


class Blocklistde_Ssh(Blocklist):
    source = "http://lists.blocklist.de/lists/ssh.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"


class Blocklistde_Mail(Blocklist):
    source = "http://lists.blocklist.de/lists/mail.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"


class Blocklistde_Imap(Blocklist):
    source = "http://lists.blocklist.de/lists/imap.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"


class Blocklistde_Apache(Blocklist):
    source = "http://lists.blocklist.de/lists/apache.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"


class Blocklistde_Ftp(Blocklist):
    source = "http://lists.blocklist.de/lists/ftp.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"


class Blocklistde_Strongips(Blocklist):
    source = "http://lists.blocklist.de/lists/strongips.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
