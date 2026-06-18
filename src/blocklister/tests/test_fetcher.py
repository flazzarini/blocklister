import sys
import unittest

if sys.version_info[0] == 3:  # noqa
    from unittest.mock import MagicMock, patch
else:
    from mock import MagicMock, patch

from datetime import datetime, timedelta
from tempfile import NamedTemporaryFile
from io import BytesIO
from gzip import GzipFile

from blocklister.fetcher import Fetcher, Resource
from blocklister.exc import FetcherException
from requests.exceptions import RequestException


class TestFetcher(unittest.TestCase):
    def setUp(self):
        self.url = "http://www.domain.com/list.txt"
        self.gzip_url = "http://www.domain.com/list.gz"
        self.fileobj = NamedTemporaryFile()
        self.filename = self.fileobj.name
        self.refresh = timedelta(days=1)
        self.fetcher = Fetcher(self.url, self.filename, refresh=self.refresh)

    def test_repr(self):
        expected = (
            "Fetcher({},{},{})".format(self.url, self.filename, self.refresh))
        self.assertEqual(self.fetcher.__repr__(), expected)

    def test_updated_type(self):
        result = self.fetcher.updated
        self.assertIsInstance(result, datetime)

    @patch('blocklister.fetcher.requests')
    def test__get_resource(self, req_mock):
        ex_content = b'1.1.1.1\n2.2.2.2\n'
        expected = Resource(ex_content, self.url, 200)

        response_mock = MagicMock()
        response_mock.status_code = 200
        response_mock.url = self.url
        response_mock.content = ex_content

        req_mock.get.return_value = response_mock

        result = self.fetcher._get_resource(self.fetcher.url)
        self.assertEqual(result, expected)

    @patch('blocklister.fetcher.requests')
    def test__get_resource_gziped(self, req_mock):
        ex_content = b'1.1.1.1\n2.2.2.2\n'
        expected = Resource(ex_content, self.gzip_url, 200)

        # To test gzip decompression lets gzip our `ex_content`
        ex_content_gziped = BytesIO()
        g = GzipFile(fileobj=ex_content_gziped, mode='w', compresslevel=5)
        g.write(ex_content)
        g.close()
        ex_content_gziped.seek(0)

        response_mock = MagicMock()
        response_mock.status_code = 200
        response_mock.url = self.gzip_url
        response_mock.content = ex_content_gziped.read()

        req_mock.get.return_value = response_mock

        result = self.fetcher._get_resource(self.gzip_url)
        self.assertEqual(result, expected)

    @patch('blocklister.fetcher.requests')
    def test__get_resource_raises_non_200(self, req_mock):
        response_mock = MagicMock()
        response_mock.status_code = 409

        req_mock.get.return_value = response_mock

        with self.assertRaises(FetcherException):
            self.fetcher._get_resource(self.fetcher.url)

    @patch('blocklister.fetcher.requests')
    def test__get_resource_raises(self, req_mock):
        req_mock.get.side_effect = RequestException()

        with self.assertRaises(FetcherException):
            self.fetcher._get_resource(self.fetcher.url)
