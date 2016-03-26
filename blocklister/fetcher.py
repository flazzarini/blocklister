import logging
from collections import namedtuple
from datetime import datetime, timedelta
from os.path import getmtime, getsize, exists
from io import BytesIO
from gzip import GzipFile

import requests

from .exc import FetcherException

LOG = logging.getLogger(__name__)
Resource = namedtuple("Resource", "content, url, status_code")


class Fetcher(object):
    """
    Fetcher is a simple class with one specific task which is to get a
    resource via `HTTP GET` and store it on a given location on disk.

    :param url: Resource to fetch (e.g. http://www.domain.com/list.txt)
    :type url: string
    :param filename: Filename to write Content to
    :type filename: str
    :param refresh: Will be used to update the file if file is older than
                    `refresh`
    :type refresh: `datetime.timedelta`
    """
    def __init__(self, url, filename, refresh=timedelta(days=1)):
        self.url = url
        self.filename = filename
        self.refresh = refresh

    def __repr__(self):
        return (
            "Fetcher({},{},{})".format(self.url, self.filename, self.refresh))

    @property
    def updated(self):
        """
        Get last modified date of the `output` file raise `FetcherException` if
        file could not be read

        :returns Timestamp of the last modification to the file
        :rtype `datetime.datetime`
        """
        try:
            result = datetime.fromtimestamp(getmtime(self.filename))
            return result
        except IOError as exc:
            raise FetcherException(
                "Can't get timestamp from file %s - %s" % (self.filename, exc))

    @property
    def file_exists(self):
        """
        Check wether the file exists and has more than 0 bytes

        :returns True if file exists otherwise False
        :rtype boolean
        """
        if exists(self.filename) and getsize(self.filename) > 0:
            LOG.debug("File {} exists".format(self.filename))
            return True
        LOG.debug("File {} does not exists".format(self.filename))
        return False

    @property
    def needs_update(self):
        if not self.file_exists:
            LOG.info("Get initial file from %s" % self.url)
            self.update()

        difference = datetime.now() - self.updated
        if difference > self.refresh:
            return True
        elif getsize(self.filename) == 0:
            return True
        return False

    def check_update(self):
        """
        Check if file needs to be updated if so launch the update
        """
        difference = datetime.now() - self.updated
        if difference > self.refresh:
            LOG.info(
                "File %s is older than %s launch update" % (
                    self.filename, self.refresh))
            self.update()
        elif getsize(self.filename) == 0:
            LOG.error("File %s has 0 bytes updating it" % self.filename)
            self.update()

    def update(self):
        """
        Update the file by getting the source url
        """
        LOG.info("Get update from %s" % self.url)
        resource = self._get_resource(self.url)
        fileobj = open(self.filename, 'w+')
        fileobj.seek(0)
        fileobj.write(resource.content.decode('ascii', 'ignore'))
        fileobj.truncate()
        fileobj.close()

    def _get_resource(self, url):
        """
        Get resource

        :param url: URL to `GET`
        :type url: str

        :returns `Resource`
        :rtype `blocklister.fetcher.Resource`
        """
        try:
            response = requests.get(url)
        except Exception as exc:
            raise FetcherException(exc)

        if response.status_code != 200:
            raise FetcherException("Unable to get resource from %s" % url)

        if response.url.endswith(".gz") or response.url.endswith(".gzip"):
            output = self._decompress_gzip(response.content)
        else:
            output = response.content

        return Resource(
            output,
            response.url,
            response.status_code)

    def _decompress_gzip(self, gzip_content):
        """
        Decompress gzip content

        :param gzip: Byte String
        :type gzip: bytes

        :returns Unziped Byte String
        :rtype bytes
        """
        buf = BytesIO(gzip_content)
        data = GzipFile(fileobj=buf)
        content = data.read()
        data.close()
        buf.close()
        return content
