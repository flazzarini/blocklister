from ipaddress import IPv4Network
from textwrap import dedent

import pytest

from blocklister.models import (
    Blocklist,
    Ads,
    Spyware,
    Level1,
    Level2,
    Level3,
    Edu,
    Proxy,
    Badpeers,
    Microsoft,
    Spider,
    Hijacked,
    Dshield,
    Spamhausdrop,
    Spamhausedrop,
    Blocklistde_All,
    Blocklistde_Ssh,
    Blocklistde_Mail,
    Blocklistde_Imap,
    Blocklistde_Apache,
    Blocklistde_Ftp,
    Blocklistde_Strongips,
)

RANGE_CLASSES = [
    (Ads, "Ads"),
    (Spyware, "Spyware"),
    (Level1, "Level"),
    (Level2, "Level"),
    (Level3, "Level"),
    (Edu, "Edu"),
    (Proxy, "Proxy"),
    (Badpeers, "Badpeers"),
    (Microsoft, "Microsoft"),
    (Hijacked, "Hijacked"),
    (Spider, "Spider"),
    (Dshield, "Dshield"),
]

SIMPLE_LINE_CLASSES = [
    Blocklistde_All,
    Blocklistde_Ssh,
    Blocklistde_Mail,
    Blocklistde_Imap,
    Blocklistde_Apache,
    Blocklistde_Ftp,
    Blocklistde_Strongips,
]

CIDR_CLASSES = [Spamhausdrop, Spamhausedrop]


def write_temp_file(tmp_path, content):
    file_path = tmp_path / "testfile.txt"
    file_path.write_text(dedent(content).lstrip("\n"), encoding="utf-8")
    return file_path


def assert_items_equal(actual, expected):
    assert sorted(actual) == sorted(expected)


def test_blocklist_init(tmp_path):
    """Blocklist stores the provided store path and filename."""
    file_path = write_temp_file(tmp_path, "dummy:1.1.1.1-1.1.1.1\n")
    bl = Blocklist(str(file_path.parent), filename=file_path.name)
    assert bl.store == str(file_path.parent)
    assert bl.filename == file_path.name


def test_blocklist_repr(tmp_path):
    """Blocklist.__repr__ returns the expected string representation."""
    file_path = write_temp_file(tmp_path, "")
    bl = Blocklist(str(file_path.parent), filename=file_path.name)
    assert repr(bl) == f"Blocklist({bl.store}, filename={bl.filename})"


def test_blocklist_get_class_returns_subclass():
    """Blocklist.get_class returns the correct subclass for each name."""
    for klass in Blocklist.__subclasses__():
        result = Blocklist.get_class(klass.__name__, "store")
        assert result.__class__ is klass


def test_blocklist_get_class_raises():
    """Blocklist.get_class raises ValueError for unknown blocklist names."""
    with pytest.raises(ValueError):
        Blocklist.get_class("nonexisting", "store")


def test_blocklist_get_ips_simple(tmp_path):
    """Blocklist.get_ips extracts IP ranges from a simple list file."""
    file_path = write_temp_file(
        tmp_path,
        """
        Test:1.1.1.1-2.2.2.2
        Some other Test:3.3.3.3-3.3.3.3
        """,
    )
    bl = Blocklist(str(file_path.parent), filename=file_path.name)
    assert_items_equal(bl.get_ips(), ["1.1.1.1-2.2.2.2", "3.3.3.3-3.3.3.3"])


def test_blocklist_get_ips_cidr(tmp_path):
    """Blocklist.get_ips returns IPv4 networks when cidr_notation=True."""
    file_path = write_temp_file(
        tmp_path,
        """
        Test:1.1.1.1-2.2.2.2
        Some other Test:3.3.3.3-3.3.3.3
        """,
    )
    bl = Blocklist(str(file_path.parent), filename=file_path.name)
    expected = [
        IPv4Network('1.1.1.1/32'),
        IPv4Network('1.1.1.2/31'),
        IPv4Network('1.1.1.4/30'),
        IPv4Network('1.1.1.8/29'),
        IPv4Network('1.1.1.16/28'),
        IPv4Network('1.1.1.32/27'),
        IPv4Network('1.1.1.64/26'),
        IPv4Network('1.1.1.128/25'),
        IPv4Network('1.1.2.0/23'),
        IPv4Network('1.1.4.0/22'),
        IPv4Network('1.1.8.0/21'),
        IPv4Network('1.1.16.0/20'),
        IPv4Network('1.1.32.0/19'),
        IPv4Network('1.1.64.0/18'),
        IPv4Network('1.1.128.0/17'),
        IPv4Network('1.2.0.0/15'),
        IPv4Network('1.4.0.0/14'),
        IPv4Network('1.8.0.0/13'),
        IPv4Network('1.16.0.0/12'),
        IPv4Network('1.32.0.0/11'),
        IPv4Network('1.64.0.0/10'),
        IPv4Network('1.128.0.0/9'),
        IPv4Network('2.0.0.0/15'),
        IPv4Network('2.2.0.0/23'),
        IPv4Network('2.2.2.0/31'),
        IPv4Network('2.2.2.2/32'),
        IPv4Network('3.3.3.3/32'),
    ]
    assert_items_equal(bl.get_ips(cidr_notation=True), expected)


@pytest.mark.parametrize("klass,prefix", RANGE_CLASSES)
def test_range_class_get_ips(tmp_path, klass, prefix):
    """Range-based blocklist classes extract ranges from input data."""
    file_path = write_temp_file(
        tmp_path,
        f"""
        {prefix}:1.1.1.0-1.1.1.255
        {prefix}:2.2.2.0-2.2.2.255
        """,
    )
    instance = klass(str(file_path.parent), filename=file_path.name)
    assert_items_equal(instance.get_ips(), ["1.1.1.0-1.1.1.255", "2.2.2.0-2.2.2.255"])


@pytest.mark.parametrize("klass,prefix", RANGE_CLASSES)
def test_range_class_get_ips_cidr(tmp_path, klass, prefix):
    """Range-based blocklist classes return CIDR networks when requested."""
    file_path = write_temp_file(
        tmp_path,
        f"""
        {prefix}:1.1.1.0-1.1.1.255
        {prefix}:2.2.2.0-2.2.2.255
        """,
    )
    instance = klass(str(file_path.parent), filename=file_path.name)
    expected = [IPv4Network('1.1.1.0/24'), IPv4Network('2.2.2.0/24')]
    assert_items_equal(instance.get_ips(cidr_notation=True), expected)


@pytest.mark.parametrize("klass", CIDR_CLASSES)
def test_cidr_class_get_ips(tmp_path, klass):
    """CIDR blocklist classes parse CIDR lines correctly."""
    file_path = write_temp_file(
        tmp_path,
        """
        1.1.1.1/32 ; SBLTest
        2.2.2.2/32 ; SBLTest2
        """,
    )
    instance = klass(str(file_path.parent), filename=file_path.name)
    assert_items_equal(instance.get_ips(), ["1.1.1.1/32", "2.2.2.2/32"])


@pytest.mark.parametrize("klass", CIDR_CLASSES)
def test_cidr_class_get_ips_cidr(tmp_path, klass):
    """CIDR blocklist classes return IPv4Network objects when cidr_notation=True."""
    file_path = write_temp_file(
        tmp_path,
        """
        1.1.1.1/32 ; SBLTest
        2.2.2.2/32 ; SBLTest2
        """,
    )
    instance = klass(str(file_path.parent), filename=file_path.name)
    expected = [IPv4Network('1.1.1.1/32'), IPv4Network('2.2.2.2/32')]
    assert_items_equal(instance.get_ips(cidr_notation=True), expected)


@pytest.mark.parametrize("klass", SIMPLE_LINE_CLASSES)
def test_simple_line_class_get_ips(tmp_path, klass):
    """Simple blocklist classes read plain IP lines correctly."""
    file_path = write_temp_file(
        tmp_path,
        """
        1.1.1.1
        2.2.2.2
        """,
    )
    instance = klass(str(file_path.parent), filename=file_path.name)
    assert_items_equal(instance.get_ips(), ["1.1.1.1", "2.2.2.2"])


@pytest.mark.parametrize("klass", SIMPLE_LINE_CLASSES)
def test_simple_line_class_get_ips_cidr(tmp_path, klass):
    """Simple blocklist classes return /32 CIDR networks when requested."""
    file_path = write_temp_file(
        tmp_path,
        """
        1.1.1.1
        2.2.2.2
        """,
    )
    instance = klass(str(file_path.parent), filename=file_path.name)
    expected = [IPv4Network('1.1.1.1/32'), IPv4Network('2.2.2.2/32')]
    assert_items_equal(instance.get_ips(cidr_notation=True), expected)
