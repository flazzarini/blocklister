import unittest
from unittest.mock import patch, MagicMock

import os
from io import StringIO, BytesIO
from gzip import compress
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
    Malwaredomainlist,
    Openbl,
    Openbl_180,
    Openbl_360,
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

    def test_file_exists(self):
        result = self.bl.file_exists
        self.assertTrue(result)

    def test_file_exists_False(self):
        store = "/somethingNoneExisting"
        filename = "intothevoid.txt"
        bl = Blocklist(store, filename)
        result = bl.file_exists
        self.assertFalse(result)

    def test_file_last_saved(self):
        from os.path import getmtime
        from datetime import datetime
        expected = datetime.fromtimestamp(getmtime(self.tempfile.name))
        result = self.bl.last_saved
        self.assertEqual(result, expected)

    def test_file_last_saved_raises(self):
        store = "/somethingNoneExisting"
        filename = "intothevoid.txt"
        bl = Blocklist(store, filename)
        with self.assertRaises(IOError):
            bl.last_saved

    def test_get(self):
        # Prepare mocked content
        content = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        content_fileobj = bytes(content.encode('ascii'))

        # Prepare our request mock
        request_mock = MagicMock()
        request_mock.return_value = content_fileobj

        # Get Result from get method
        result = self.bl.get(request=request_mock)

        # Read actual content in file created on disk
        self.tempfile.file.seek(0)
        file_content = self.tempfile.file.read().decode('utf-8')

        self.assertEqual(result, file_content)

    def test_get_gzip(self):
        # Prepare mocked content
        content = dedent(
            """
            1.1.1.1
            2.2.2.2
            """
        )
        content_gzip = compress(content.encode('utf-8'))
        content_fileobj = bytes(content_gzip)

        # Prepare our request mock
        request_mock = MagicMock()
        request_mock.return_value = content_fileobj

        # Get Result from get method
        self.bl.gzip = True
        result = self.bl.get(request=request_mock)

        # Read actual content in file created on disk
        self.tempfile.file.seek(0)
        file_content = self.tempfile.file.read().decode('utf-8')

        self.assertEqual(result, file_content)

    def test_get_ips_simple(self):
        contents = dedent(
            """
            Test:1.1.1.1-2.2.2.2
            Some other Test:3.3.3.3-3.3.3.3
            """
        )
        self.tempfile.file.write(contents.encode('utf-8'))
        self.tempfile.file.flush()
        expected = [
            '1.1.1.1-2.2.2.2',
            '3.3.3.3-3.3.3.3'
        ]
        result = self.bl.get_ips()
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


class TestBadpeers(TestBlocklistBase):
    def setUp(self):
        super(TestBadpeers, self).setUp()
        self.badpeers = Badpeers(self.store, filename=self.filename)

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
        result = self.badpeers.get_ips()
        self.assertCountEqual(result, expected)


class TestMicrosoft(TestBlocklistBase):
    def setUp(self):
        super(TestMicrosoft, self).setUp()
        self.microsoft = Microsoft(self.store, filename=self.filename)

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
        result = self.microsoft.get_ips()
        self.assertCountEqual(result, expected)


class TestHijacked(TestBlocklistBase):
    def setUp(self):
        super(TestHijacked, self).setUp()
        self.hijacked = Hijacked(self.store, filename=self.filename)

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
        result = self.hijacked.get_ips()
        self.assertCountEqual(result, expected)


class TestSpider(TestBlocklistBase):
    def setUp(self):
        super(TestSpider, self).setUp()
        self.spider = Spider(self.store, filename=self.filename)

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
        result = self.spider.get_ips()
        self.assertCountEqual(result, expected)


class TestDshield(TestBlocklistBase):
    def setUp(self):
        super(TestDshield, self).setUp()
        self.dshield = Dshield(self.store, filename=self.filename)

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
        result = self.dshield.get_ips()
        self.assertCountEqual(result, expected)


class TestMalwaredomainlist(TestBlocklistBase):
    def setUp(self):
        super(TestMalwaredomainlist, self).setUp()
        self.ml = Malwaredomainlist(self.store, filename=self.filename)

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
        result = self.ml.get_ips()
        self.assertCountEqual(result, expected)


class TestOpenbl(TestBlocklistBase):
    def setUp(self):
        super(TestOpenbl, self).setUp()
        self.openbl = Openbl(self.store, filename=self.filename)

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
        result = self.openbl.get_ips()
        self.assertCountEqual(result, expected)


class TestOpenbl_180(TestBlocklistBase):
    def setUp(self):
        super(TestOpenbl_180, self).setUp()
        self.openbl = Openbl_180(self.store, filename=self.filename)

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
        result = self.openbl.get_ips()
        self.assertCountEqual(result, expected)


class TestOpenbl_360(TestBlocklistBase):
    def setUp(self):
        super(TestOpenbl_360, self).setUp()
        self.openbl = Openbl_360(self.store, filename=self.filename)

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
        result = self.openbl.get_ips()
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)


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
        self.assertCountEqual(result, expected)
