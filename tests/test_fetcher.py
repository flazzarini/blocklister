from datetime import datetime, timedelta
from io import BytesIO
from gzip import GzipFile

import pytest
from unittest.mock import MagicMock

from blocklister.fetcher import Fetcher, Resource
from blocklister.exc import FetcherException
from requests.exceptions import RequestException


@pytest.fixture
def fetcher(tmp_path):
    url = "http://www.domain.com/list.txt"
    filename = tmp_path / "list.txt"
    filename.write_text("", encoding="utf-8")
    refresh = timedelta(days=1)
    return Fetcher(url, str(filename), refresh=refresh)


def test_repr(fetcher):
    """Fetcher.__repr__ returns the expected representation string."""
    expected = f"Fetcher({fetcher.url},{fetcher.filename},{fetcher.refresh})"
    assert repr(fetcher) == expected


def test_updated_type(fetcher):
    """Fetcher.updated returns a datetime instance."""
    assert isinstance(fetcher.updated, datetime)


def test__get_resource(monkeypatch, fetcher):
    """Fetcher._get_resource returns a Resource for a successful request."""
    ex_content = b"1.1.1.1\n2.2.2.2\n"
    expected = Resource(ex_content, fetcher.url, 200)

    response_mock = MagicMock()
    response_mock.status_code = 200
    response_mock.url = fetcher.url
    response_mock.content = ex_content

    requests_mock = MagicMock()
    requests_mock.get.return_value = response_mock
    monkeypatch.setattr("blocklister.fetcher.requests", requests_mock)

    result = fetcher._get_resource(fetcher.url)
    assert result == expected


def test__get_resource_gziped(monkeypatch, fetcher):
    """Fetcher._get_resource decompresses gzip content before returning."""
    ex_content = b"1.1.1.1\n2.2.2.2\n"
    expected = Resource(ex_content, "http://www.domain.com/list.gz", 200)

    ex_content_gziped = BytesIO()
    with GzipFile(fileobj=ex_content_gziped, mode="w", compresslevel=5) as g:
        g.write(ex_content)
    ex_content_gziped.seek(0)

    response_mock = MagicMock()
    response_mock.status_code = 200
    response_mock.url = "http://www.domain.com/list.gz"
    response_mock.content = ex_content_gziped.read()

    requests_mock = MagicMock()
    requests_mock.get.return_value = response_mock
    monkeypatch.setattr("blocklister.fetcher.requests", requests_mock)

    result = fetcher._get_resource("http://www.domain.com/list.gz")
    assert result == expected


def test__get_resource_raises_non_200(monkeypatch, fetcher):
    """Fetcher._get_resource raises FetcherException for non-200 responses."""
    response_mock = MagicMock()
    response_mock.status_code = 409

    requests_mock = MagicMock()
    requests_mock.get.return_value = response_mock
    monkeypatch.setattr("blocklister.fetcher.requests", requests_mock)

    with pytest.raises(FetcherException):
        fetcher._get_resource(fetcher.url)


def test__get_resource_raises(monkeypatch, fetcher):
    """Fetcher._get_resource raises FetcherException when the request fails."""
    requests_mock = MagicMock()
    requests_mock.get.side_effect = RequestException()
    monkeypatch.setattr("blocklister.fetcher.requests", requests_mock)

    with pytest.raises(FetcherException):
        fetcher._get_resource(fetcher.url)
