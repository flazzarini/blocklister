import pytest
from textwrap import dedent
from datetime import datetime
from unittest.mock import MagicMock, PropertyMock

from blocklister.main import app
from blocklister.models import Blocklist


def create_mock_blocklist(name, ips):
    klass = MagicMock()
    klass.__name__ = name
    type(klass).last_saved = PropertyMock(return_value=datetime.now())
    klass.get_ips.return_value = ips
    return klass


@pytest.fixture
def client():
    return app.test_client()


@pytest.fixture
def blocklist_classes():
    return [subcls for subcls in Blocklist.__subclasses__()]


def test_index(client):
    """The index route returns text/plain and HTTP 200."""
    result = client.get("/")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"


def test_index_contains_all_lists(client, blocklist_classes):
    """The index includes the names of all available Blocklist subclasses."""
    result = client.get("/")
    body = result.get_data().decode("utf-8")
    for klass in blocklist_classes:
        assert klass.__name__ in body


def test_changelog(client):
    """The changelog endpoint returns plain text with HTTP 200."""
    result = client.get("/changelog")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"


def test_get_default_lists(monkeypatch, client):
    """The default list endpoint renders the address list for the given blocklist."""
    klass = create_mock_blocklist("test", ["1.1.1.1"])
    monkeypatch.setattr(Blocklist, "get_class", lambda *_: klass)

    result = client.get("/test")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"

    expected_content = dedent("""\
        # Remove all old entries first
        :foreach i in=[/ip firewall address-list find ] do={
          :if ( [/ip firewall address-list get $i comment] = "Magicmock") do={
              /ip firewall address-list remove $i
          }
        }

        # Now let's add the new ones
        /ip firewall address-list
        add address="1.1.1.1" list="magicmock_list" comment="Magicmock"
        """)
    assert result.get_data().decode("ascii") == expected_content


def test_get_lists_listname(monkeypatch, client):
    """The endpoint returns the same list data when called by list name."""
    klass = create_mock_blocklist("test", ["1.1.1.1"])
    monkeypatch.setattr(Blocklist, "get_class", lambda *_: klass)

    result = client.get("/test")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"

    expected_content = dedent("""\
        # Remove all old entries first
        :foreach i in=[/ip firewall address-list find ] do={
          :if ( [/ip firewall address-list get $i comment] = "Magicmock") do={
              /ip firewall address-list remove $i
          }
        }

        # Now let's add the new ones
        /ip firewall address-list
        add address="1.1.1.1" list="magicmock_list" comment="Magicmock"
        """)
    assert result.get_data().decode("ascii") == expected_content


def test_get_default_lists_cidr(monkeypatch, client):
    """The endpoint honors the cidr query option when rendering the list."""
    klass = create_mock_blocklist("test", ["1.1.1.1/32"])
    monkeypatch.setattr(Blocklist, "get_class", lambda *_: klass)

    result = client.get("/test?cidr=enabled")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"

    expected_content = dedent("""\
        # Remove all old entries first
        :foreach i in=[/ip firewall address-list find ] do={
          :if ( [/ip firewall address-list get $i comment] = "Magicmock") do={
              /ip firewall address-list remove $i
          }
        }

        # Now let's add the new ones
        /ip firewall address-list
        add address="1.1.1.1/32" list="magicmock_list" comment="Magicmock"
        """)
    assert result.get_data().decode("ascii") == expected_content


def test_get_lists_listname_cidr(monkeypatch, client):
    """The list endpoint includes cidr output and preserves the name."""
    klass = create_mock_blocklist("test", ["1.1.1.1/32"])
    monkeypatch.setattr(Blocklist, "get_class", lambda *_: klass)

    result = client.get("/test?cidr=enabled")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"
    assert "Magicmock" in result.get_data().decode("utf-8")

    expected_content = dedent("""\
        # Remove all old entries first
        :foreach i in=[/ip firewall address-list find ] do={
          :if ( [/ip firewall address-list get $i comment] = "Magicmock") do={
              /ip firewall address-list remove $i
          }
        }

        # Now let's add the new ones
        /ip firewall address-list
        add address="1.1.1.1/32" list="magicmock_list" comment="Magicmock"
        """)
    assert result.get_data().decode("ascii") == expected_content


def test_get_multilist(monkeypatch, client):
    """The multilist endpoint aggregates multiple blocklists."""
    foo_klass = create_mock_blocklist("foo", ["1.1.1.1"])
    bar_klass = create_mock_blocklist("bar", ["2.2.2.2"])
    mock_get_class = MagicMock(side_effect=[foo_klass, bar_klass])
    monkeypatch.setattr(Blocklist, "get_class", mock_get_class)

    result = client.get("/multilist?blocklists=foo,bar")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"
    assert "multilist" in result.get_data().decode("utf-8")

    expected_content = dedent("""\
        # Remove all old entries first
        :foreach i in=[/ip firewall address-list find ] do={
          :if ( [/ip firewall address-list get $i comment] = "multilist") do={
              /ip firewall address-list remove $i
          }
        }

        # Now let's add the new ones
        /ip firewall address-list
        add address="1.1.1.1" list="blocklist" comment="multilist"
        add address="2.2.2.2" list="blocklist" comment="multilist"
        """)
    assert result.get_data().decode("ascii") == expected_content


def test_get_multilist_cidr(monkeypatch, client):
    """The multilist endpoint renders CIDR addresses when enabled."""
    foo_klass = create_mock_blocklist("foo", ["1.1.1.1/32"])
    bar_klass = create_mock_blocklist("bar", ["2.2.2.2/32"])
    mock_get_class = MagicMock(side_effect=[foo_klass, bar_klass])
    monkeypatch.setattr(Blocklist, "get_class", mock_get_class)

    result = client.get("/multilist?blocklists=foo,bar&cidr=enabled")
    assert result.status_code == 200
    assert result.mimetype == "text/plain"
    assert "multilist" in result.get_data().decode("utf-8")
