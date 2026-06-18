import logging
import re
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import (
    IPv4Address,
    IPv4Network,
    summarize_address_range,
)
from pathlib import Path
from typing import ClassVar

from blocklister.fetcher import Fetcher


LOG = logging.getLogger(__name__)


@dataclass(init=False)
class Blocklist:
    SOURCE: ClassVar[str] = "http://bogus.site.com"
    REGEX: ClassVar[re.Pattern] = re.compile(
        r"^.*:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-"
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    )
    TEMPLATE: ClassVar[str] = "firewall_addresslist.jinja2"
    GZIP: ClassVar[bool] = False
    DEDUPE: ClassVar[bool] = True

    store: str | Path
    refresh_list: timedelta
    filename: str | None

    def __init__(
        self,
        store: str | Path = "/tmp",
        filename: str | None = None,
        refresh_list: timedelta = timedelta(days=2),
    ):
        self.store = store
        self.filename = filename
        self.refresh_list = refresh_list

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.store}, filename={self.filename})"

    @property
    def name(self) -> str:
        return self.__class__.__name__.lower()

    @property
    def fetcher(self):
        return Fetcher(
            self.SOURCE,
            self.filepath,
            refresh=self.refresh_list,
        )

    @property
    def filepath(self) -> Path:
        """
        Compiles the absolute filepath to the local data source for this List
        """
        filename = self.filename if self.filename is not None else f"{self.name}.txt"
        return Path(self.store) / filename

    def get_ips(self, cidr_notation=False):
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
            if not line.strip():
                continue

            if line.startswith("#"):
                continue

            res = re.search(self.REGEX, line)
            if not res:
                LOG.debug(
                    "{} Line:{} Regular Expression mismatch {}"
                    .format(self.filepath, line, self.__class__.__name__)
                )
                continue

            if len(res.groups()) == 1:
                if cidr_notation:
                    entry = IPv4Network(res.groups()[0])
                    results.append(entry)
                else:
                    results.append(res.groups()[0])

            elif len(res.groups()) > 1:
                if cidr_notation:
                    start = IPv4Address(res.groups()[0])
                    end = IPv4Address(res.groups()[1])
                    networks = list(summarize_address_range(start, end))
                    results += networks
                else:
                    results.append(
                        "{}-{}".format(res.groups()[0], res.groups()[1]))

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
            if subcls.__name__.lower() == name.lower():
                return subcls(store)
        raise ValueError("No class found for {}".format(name))


class Ads(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=bt_ads"
    GZIP = True


class Spyware(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=bt_spyware"
    GZIP = True


class Level1(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw"
    GZIP = True
    DEDUPE = False  # The source list is too big


class Level2(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw"
    GZIP = True
    DEDUPE = False  # The source list is too big


class Level3(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh"
    GZIP = True
    DEDUPE = False  # The source list is too big


class Edu(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=imlmncgrkbnacgcwfjvh"
    GZIP = True
    DEDUPE = False  # The source list is too big


class Proxy(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb"
    GZIP = True


class Badpeers(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=cwworuawihqvocglcoss"
    GZIP = True


class Microsoft(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=xshktygkujudfnjfioro"
    GZIP = True


class Spider(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy"
    GZIP = True


class Hijacked(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=usrcshglbiilevmyfhse"
    GZIP = True


class Dshield(Blocklist):
    SOURCE = "http://list.iblocklist.com/?list=xpbqleszmajjesnzddhv"
    GZIP = True


class Spamhausdrop(Blocklist):
    SOURCE = "http://www.spamhaus.org/drop/drop.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$")


class Spamhausedrop(Blocklist):
    SOURCE = "http://www.spamhaus.org/drop/edrop.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$")


class Blocklistde_All(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/all.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class Blocklistde_Ssh(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/ssh.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class Blocklistde_Mail(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/mail.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class Blocklistde_Imap(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/imap.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class Blocklistde_Apache(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/apache.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class Blocklistde_Ftp(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/ftp.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class Blocklistde_Strongips(Blocklist):
    SOURCE = "http://lists.blocklist.de/lists/strongips.txt"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class UltimateHostsBlacklist(Blocklist):
    SOURCE = "https://hosts.ubuntu101.co.za/ips.list"
    REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")
