import logging
import re
from os.path import join
from datetime import timedelta
from ipaddress import (
    IPv4Network,
    IPv4Address,
    summarize_address_range
)

from blocklister.fetcher import Fetcher


LOG = logging.getLogger(__name__)


class Blocklist(object):
    source = "http://bogus.site.com"
    regex = (
        "^.*:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-"
        "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")
    template = "firewall_addresslist.jinja2"
    gzip = False

    def __init__(self, store, filename=None, refresh_list=timedelta(days=2)):
        self.name = self.__class__.__name__.lower()
        self.store = store
        self.filename = filename
        self.refresh_list = refresh_list
        self.fetcher = Fetcher(
            self.source, self.filepath, refresh=self.refresh_list)

    def __repr__(self):
        return (
            "{0}({1}, filename={2})".format(
                self.__class__.__name__, self.store, self.filename))

    @property
    def filepath(self):
        """
        Compiles the absolute filepath to the local data source for this List
        """
        _filename = self.filename
        if not _filename:
            _filename = self.name + '.txt'
        return join(self.store, _filename)

    def get_ips(self):
        """
        Runs through the source file line by line to parse the lines and return
        a list `IPv4Network`s.

        :returns list of textual ipaddress notations
        :rtype list
        """
        # First check if we need a forced update?
        if not self.fetcher.file_exists:
            self.fetcher.update()

        # Run through the list and gather all textual ipaddresses
        results = []
        linenr = 1
        filehandler = open(self.filepath, 'r')
        for line in filehandler:
            res = re.search(self.regex, line)

            if not res:
                LOG.debug(
                    "{} Line:{} Regular Expression mismatch {}"
                    .format(self.filepath, line, self.__class__.__name__)
                )
                continue

            if len(res.groups()) == 1:
                entry = IPv4Network(res.groups()[0])
                results.append(entry)

            elif len(res.groups()) > 1:
                start = IPv4Address(res.groups()[0])
                end = IPv4Address(res.groups()[1])
                networks = list(summarize_address_range(start, end))
                results += networks

            linenr += 1

        filehandler.close()
        return list(results)

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
    source = "http://www.spamhaus.org/drop/drop.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$"


class Spamhausedrop(Blocklist):
    source = "http://www.spamhaus.org/drop/edrop.txt"
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
