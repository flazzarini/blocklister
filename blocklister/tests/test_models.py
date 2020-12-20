import sys
import unittest

if sys.version_info[0] == 3:  # noqa
    from unittest.mock import MagicMock
else:
    from mock import MagicMock

from ipaddress import IPv4Network

import os
from tempfile import NamedTemporaryFile
from textwrap import dedent

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


class TestBlocklistBase(unittest.TestCase):
    def setUp(self):
        self.tempfile = NamedTemporaryFile()
        self.filename = os.path.basename(self.tempfile.name)
        self.store = os.path.dirname(self.tempfile.name)

    def tearDown(self):
        self.tempfile.close()


class TestBlocklist(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklist, self).setUp()
        self.bl = Blocklist(self.store, filename=self.filename)

    def test_init(self):
        self.assertEqual(self.bl.store, self.store)
        self.assertEqual(self.bl.filename, self.filename)

    def test_repr(self):
        expected = (
            "{0}({1}, filename={2})".format(
                "Blocklist",
                self.store,
                self.filename
            )
        )
        self.assertEqual(self.bl.__repr__(), expected)

    def get_class(self):
        store = MagicMock()
        classes = []
        for subcls in Blocklist.__subclasses__():
            classes.append(subcls)

        for klass in classes:
            result = Blocklist.get_class(klass.__name__, store)
            self.assertEqual(result.__class__, klass)

    def get_class_raises(self):
        store = MagicMock()
        with self.assertRaises(ValueError):
            Blocklist.get_class('nonexisting', store)

    def test_get_ips_simple(self):
        self.maxDiff = None
        contents = dedent(
            """
            Test:1.1.1.1-2.2.2.2
            Some other Test:3.3.3.3-3.3.3.3
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = ["1.1.1.1-2.2.2.2", "3.3.3.3-3.3.3.3"]
        result = self.bl.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        self.maxDiff = None
        contents = dedent(
            """
            Test:1.1.1.1-2.2.2.2
            Some other Test:3.3.3.3-3.3.3.3
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'1.1.1.2/31'),
            IPv4Network(u'1.1.1.4/30'),
            IPv4Network(u'1.1.1.8/29'),
            IPv4Network(u'1.1.1.16/28'),
            IPv4Network(u'1.1.1.32/27'),
            IPv4Network(u'1.1.1.64/26'),
            IPv4Network(u'1.1.1.128/25'),
            IPv4Network(u'1.1.2.0/23'),
            IPv4Network(u'1.1.4.0/22'),
            IPv4Network(u'1.1.8.0/21'),
            IPv4Network(u'1.1.16.0/20'),
            IPv4Network(u'1.1.32.0/19'),
            IPv4Network(u'1.1.64.0/18'),
            IPv4Network(u'1.1.128.0/17'),
            IPv4Network(u'1.2.0.0/15'),
            IPv4Network(u'1.4.0.0/14'),
            IPv4Network(u'1.8.0.0/13'),
            IPv4Network(u'1.16.0.0/12'),
            IPv4Network(u'1.32.0.0/11'),
            IPv4Network(u'1.64.0.0/10'),
            IPv4Network(u'1.128.0.0/9'),
            IPv4Network(u'2.0.0.0/15'),
            IPv4Network(u'2.2.0.0/23'),
            IPv4Network(u'2.2.2.0/31'),
            IPv4Network(u'2.2.2.2/32'),
            IPv4Network(u'3.3.3.3/32'),
        ]
        result = self.bl.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestAds(TestBlocklistBase):
    def setUp(self):
        super(TestAds, self).setUp()
        self.ads = Ads(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Ads:1.1.1.1-1.1.1.1
            Some stupid ad server:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1-1.1.1.1',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.ads.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Ads:1.1.1.1-1.1.1.1
            Some stupid ad server:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.ads.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestSpyware(TestBlocklistBase):
    def setUp(self):
        super(TestSpyware, self).setUp()
        self.spyware = Spyware(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Spyware:1.1.1.0-1.1.1.255
            Some other spyware:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.spyware.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Spyware:1.1.1.0-1.1.1.255
            Some other spyware:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.spyware.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestLevel1(TestBlocklistBase):
    def setUp(self):
        super(TestLevel1, self).setUp()
        self.level1 = Level1(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Level:1.1.1.0-1.1.1.255
            Level:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.level1.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Level:1.1.1.0-1.1.1.255
            Level:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.level1.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestLevel2(TestBlocklistBase):
    def setUp(self):
        super(TestLevel2, self).setUp()
        self.level2 = Level2(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Level:1.1.1.0-1.1.1.255
            Level:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.level2.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Level:1.1.1.0-1.1.1.255
            Level:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.level2.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestLevel3(TestBlocklistBase):
    def setUp(self):
        super(TestLevel3, self).setUp()
        self.level3 = Level3(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Level:1.1.1.0-1.1.1.255
            Level:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.level3.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Level:1.1.1.0-1.1.1.255
            Level:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.level3.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestEdu(TestBlocklistBase):
    def setUp(self):
        super(TestEdu, self).setUp()
        self.edu = Edu(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Edu:1.1.1.0-1.1.1.255
            Edu:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.edu.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Edu:1.1.1.0-1.1.1.255
            Edu:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.edu.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestProxy(TestBlocklistBase):
    def setUp(self):
        super(TestProxy, self).setUp()
        self.proxy = Proxy(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Proxy:1.1.1.0-1.1.1.255
            Proxy:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.proxy.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Proxy:1.1.1.0-1.1.1.255
            Proxy:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.proxy.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBadpeers(TestBlocklistBase):
    def setUp(self):
        super(TestBadpeers, self).setUp()
        self.badpeers = Badpeers(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Badpeers:1.1.1.0-1.1.1.255
            Badpeers:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.badpeers.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Badpeers:1.1.1.0-1.1.1.255
            Badpeers:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.badpeers.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestMicrosoft(TestBlocklistBase):
    def setUp(self):
        super(TestMicrosoft, self).setUp()
        self.microsoft = Microsoft(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Microsoft:1.1.1.0-1.1.1.255
            Microsoft:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.microsoft.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Microsoft:1.1.1.0-1.1.1.255
            Microsoft:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.microsoft.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestHijacked(TestBlocklistBase):
    def setUp(self):
        super(TestHijacked, self).setUp()
        self.hijacked = Hijacked(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Hijacked:1.1.1.0-1.1.1.255
            Hijacked:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.hijacked.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Hijacked:1.1.1.0-1.1.1.255
            Hijacked:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.hijacked.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestSpider(TestBlocklistBase):
    def setUp(self):
        super(TestSpider, self).setUp()
        self.spider = Spider(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Spider:1.1.1.0-1.1.1.255
            Spide:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.spider.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Spider:1.1.1.0-1.1.1.255
            Spider:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.spider.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestDshield(TestBlocklistBase):
    def setUp(self):
        super(TestDshield, self).setUp()
        self.dshield = Dshield(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            Dshield:1.1.1.0-1.1.1.255
            Dshield:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.0-1.1.1.255',
            '2.2.2.0-2.2.2.255',
        ]
        result = self.dshield.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            Dshield:1.1.1.0-1.1.1.255
            Dshield:2.2.2.0-2.2.2.255
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.0/24'),
            IPv4Network(u'2.2.2.0/24'),
        ]
        result = self.dshield.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestSpamhausdrop(TestBlocklistBase):
    def setUp(self):
        super(TestSpamhausdrop, self).setUp()
        self.spamhaus = Spamhausdrop(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1/32 ; SBLTest
            2.2.2.2/32 ; SBLTest2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1/32',
            '2.2.2.2/32',
        ]
        result = self.spamhaus.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1/32 ; SBLTest
            2.2.2.2/32 ; SBLTest2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.spamhaus.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestSpamhausedrop(TestBlocklistBase):
    def setUp(self):
        super(TestSpamhausedrop, self).setUp()
        self.spamhaus = Spamhausedrop(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1/32 ; SBLTest
            2.2.2.2/32 ; SBLTest2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1/32',
            '2.2.2.2/32',
        ]
        result = self.spamhaus.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1/32 ; SBLTest
            2.2.2.2/32 ; SBLTest2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.spamhaus.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_All(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_All, self).setUp()
        self.blde = Blocklistde_All(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_Ssh(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_Ssh, self).setUp()
        self.blde = Blocklistde_Ssh(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_Mail(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_Mail, self).setUp()
        self.blde = Blocklistde_Mail(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_Imap(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_Imap, self).setUp()
        self.blde = Blocklistde_Imap(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_Apache(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_Apache, self).setUp()
        self.blde = Blocklistde_Apache(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_Ftp(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_Ftp, self).setUp()
        self.blde = Blocklistde_Ftp(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)


class TestBlocklistde_Strongips(TestBlocklistBase):
    def setUp(self):
        super(TestBlocklistde_Strongips, self).setUp()
        self.blde = Blocklistde_Strongips(self.store, filename=self.filename)

    def test_get_ips(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = self.blde.get_ips()
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)

    def test_get_ips_cidr(self):
        contents = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            IPv4Network(u'1.1.1.1/32'),
            IPv4Network(u'2.2.2.2/32'),
        ]
        result = self.blde.get_ips(cidr_notation=True)
        if sys.version_info[0] == 3:  # noqa
            self.assertCountEqual(result, expected)
        else:
            self.assertItemsEqual(result, expected)
