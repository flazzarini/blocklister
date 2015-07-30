import logging
import re
from os.path import join
from datetime import datetime
from os.path import getmtime, exists
from subprocess import check_call, CalledProcessError, STDOUT

from blocklister.exc import DownloadError


LOG = logging.getLogger(__name__)


class Blocklist(object):
    source = "http://bogus.site.com"
    regex = (
        "^.*:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-"
        "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    )
    template = "firewall_addresslist.jinja2"
    nogzip = False

    def __init__(self, store, filename=None):
        self.name = self.__class__.__name__.lower()
        self.store = store
        self.filename = filename if filename else join(self.name + '.txt')
        self.filepath = join(self.store, self.filename)

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

    def get(self):
        try:
            LOG.debug("Get List from {}".format(self.source))
            devnull = open('/dev/null', 'w')

            if self.nogzip:
                cmd = (
                    "wget -O - {} > {}"
                    .format(self.source, self.filepath)
                )
            else:
                cmd = (
                    "wget -O - {} | gunzip > {}"
                    .format(self.source, self.filepath)
                )
            check_call(cmd, shell=True, stdout=devnull, stderr=STDOUT)
            LOG.info("List has been saved to {}".format(self.filepath))
        except CalledProcessError as exc:
            raise DownloadError(exc)
        finally:
            devnull.close()

    def get_ips(self):
        results = []
        with open(self.filepath, 'r') as f:
            for line in f:
                print(line)
                res = re.search(self.regex, line)
                print(res)

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


class Ads(Blocklist):
    source = "http://list.iblocklist.com/?list=bt_ads"


class Spyware(Blocklist):
    source = "http://list.iblocklist.com/?list=bt_spyware"


class Level1(Blocklist):
    source = "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw"


class Level2(Blocklist):
    source = "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw"


class Level3(Blocklist):
    source = "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh"


class Edu(Blocklist):
    source = "http://list.iblocklist.com/?list=imlmncgrkbnacgcwfjvh"


class Proxy(Blocklist):
    source = "http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb"


class Badpeers(Blocklist):
    source = "http://list.iblocklist.com/?list=cwworuawihqvocglcoss"


class Microsoft(Blocklist):
    source = "http://list.iblocklist.com/?list=xshktygkujudfnjfioro"


class Spider(Blocklist):
    source = "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy"


class Hijacked(Blocklist):
    source = "http://list.iblocklist.com/?list=usrcshglbiilevmyfhse"


class Dshield(Blocklist):
    source = "http://list.iblocklist.com/?list=xpbqleszmajjesnzddhv"


class Malwaredomainlist(Blocklist):
    source = "http://www.malwaredomainlist.com/hostslist/ip.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"
    nogzip = True


class Openbl(Blocklist):
    source = "https://www.openbl.org/lists/base.txt.gz"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"


class Openbl_180(Blocklist):
    source = "https://www.openbl.org/lists/base_180days.txt.gz"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"


class Openbl_360(Blocklist):
    source = "https://www.openbl.org/lists/base_360days.txt.gz"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$"


class Spamhausdrop(Blocklist):
    source = "https://www.spamhaus.org/drop/drop.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$"
    nogzip = True


class Spamhausedrop(Blocklist):
    source = "https://www.spamhaus.org/drop/edrop.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s;\sSBL.*.*$"
    nogzip = True


class Blocklistde_All(Blocklist):
    source = "http://lists.blocklist.de/lists/all.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True


class Blocklistde_Ssh(Blocklist):
    source = "http://lists.blocklist.de/lists/ssh.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True


class Blocklistde_Mail(Blocklist):
    source = "http://lists.blocklist.de/lists/mail.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True


class Blocklistde_Imap(Blocklist):
    source = "http://lists.blocklist.de/lists/imap.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True


class Blocklistde_Apache(Blocklist):
    source = "http://lists.blocklist.de/lists/apache.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True


class Blocklistde_Ftp(Blocklist):
    source = "http://lists.blocklist.de/lists/ftp.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True


class Blocklistde_Strongips(Blocklist):
    source = "http://lists.blocklist.de/lists/strongips.txt"
    regex = "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    nogzip = True
