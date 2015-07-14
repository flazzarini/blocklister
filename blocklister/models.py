import logging
import re
from os.path import join
from datetime import datetime
from os.path import getmtime, exists
from subprocess import check_call, CalledProcessError, STDOUT

from blocklister.exc import DownloadError


LOG = logging.getLogger(__name__)


class BlackList(object):
    source = "http://bogus.site.com"
    regex = (
        "^.*:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-"
        "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    )
    template = "firewall_addresslist.jinja2"
    nogzip = False

    def __init__(self, store):
        self.store = store
        self.filename = join(
            self.store,
            self.__class__.__name__.lower() + ".txt"
        )

    @property
    def file_exists(self):
        LOG.debug("Does {} already exist".format(self.filename))
        if exists(self.filename):
            return True
        return False

    @property
    def last_saved(self):
        LOG.debug("Get creation time for file {}".format(self.filename))
        if exists(self.filename):
            file_date = datetime.fromtimestamp(getmtime(self.filename))
            LOG.debug("File has a timestamp of {}".format(file_date))
            return file_date
        raise IOError("File not found")

    def get(self):
        try:
            LOG.debug("Get List from {}".format(self.source))
            devnull = open('/dev/null', 'w')

            if self.nogzip:
                cmd = (
                    "wget -O - {} > {}"
                    .format(self.source, self.filename)
                )
            else:
                cmd = (
                    "wget -O - {} | gunzip > {}"
                    .format(self.source, self.filename)
                )
            check_call(cmd, shell=True, stdout=devnull, stderr=STDOUT)
            LOG.info("List has been saved to {}".format(self.filename))
        except CalledProcessError as exc:
            raise DownloadError(exc)
        finally:
            devnull.close()

    def get_ips(self):
        results = []
        with open(self.filename, 'r') as f:
            for line in f:
                res = re.search(self.regex, line)

                if res:
                    from_ip = res.groups(0)[0]
                    to_ip = res.groups(0)[1]

                    # Convert to CIDR Notation
                    # TODO leave this out as it is killing the CPU
                    #ilist = list(iter_iprange(from_ip, to_ip))
                    #ip = str(ilist.pop())

                    ip = "{}-{}".format(from_ip, to_ip)
                    results.append(ip)
        return results


class Ads(BlackList):
    source = "http://list.iblocklist.com/?list=bt_ads"


class Spyware(BlackList):
    source = "http://list.iblocklist.com/?list=bt_spyware"


class Level1(BlackList):
    source = "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw"


class Level2(BlackList):
    source = "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw"


class Level3(BlackList):
    source = "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh"


class Edu(BlackList):
    source = "http://list.iblocklist.com/?list=imlmncgrkbnacgcwfjvh"


class Proxy(BlackList):
    source = "http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb"


class Badpeers(BlackList):
    source = "http://list.iblocklist.com/?list=cwworuawihqvocglcoss"


class Microsoft(BlackList):
    source = "http://list.iblocklist.com/?list=xshktygkujudfnjfioro"


class Spider(BlackList):
    source = "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy"


class Hijacked(BlackList):
    source = "http://list.iblocklist.com/?list=usrcshglbiilevmyfhse"


class Dshield(BlackList):
    source = "http://list.iblocklist.com/?list=xpbqleszmajjesnzddhv"


class Malwaredomainlist(BlackList):
    source = "http://www.malwaredomainlist.com/hostslist/ip.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"
    nogzip = True
