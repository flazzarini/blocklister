import unittest
from textwrap import dedent
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime
from blocklister.main import app
from blocklister.models import Blocklist


class TestMain(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.classes = []
        for subcls in Blocklist.__subclasses__():
            self.classes.append(subcls)

    def test_index(self):
        result = self.client.get("/")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")

    def test_index_contains_all_lists(self):
        result = self.client.get("/")
        for klass in self.classes:
            self.assertIn(klass.__name__, result.get_data().decode('utf-8'))

    def test_changelog(self):
        result = self.client.get("/changelog")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")

    @patch('blocklister.main.Blocklist')
    def test_get_default_lists(self, bl_mock):
        self.maxDiff = None
        klass = MagicMock()
        klass.__name__ = "test"
        type(klass).last_saved = PropertyMock(return_value=datetime.now())
        klass.get_ips.return_value = ['1.1.1.1']

        bl_mock.get_class.return_value = klass

        url = "/{}".format(klass.__name__.lower())
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")

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
            """)  # noqa
        self.assertEqual(result.get_data().decode('ascii'), expected_content)

    @patch('blocklister.main.Blocklist')
    def test_get_lists_listname(self, bl_mock):
        klass = MagicMock()
        klass.__name__ = "test"
        type(klass).last_saved = PropertyMock(return_value=datetime.now())
        klass.get_ips.return_value = ['1.1.1.1']

        bl_mock.get_class.return_value = klass

        url = "/{}".format(klass.__name__.lower())
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")

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
            """)  # noqa
        self.assertEqual(result.get_data().decode('ascii'), expected_content)

    @patch('blocklister.main.Blocklist')
    def test_get_default_lists_cidr(self, bl_mock):
        klass = MagicMock()
        klass.__name__ = "test"
        type(klass).last_saved = PropertyMock(return_value=datetime.now())
        klass.get_ips.return_value = ['1.1.1.1/32']

        bl_mock.get_class.return_value = klass

        url = "/{}?cidr=enabled".format(klass.__name__.lower())
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")

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
            """)  # noqa
        self.assertEqual(result.get_data().decode('ascii'), expected_content)

    @patch('blocklister.main.Blocklist')
    def test_get_lists_listname_cidr(self, bl_mock):
        klass = MagicMock()
        klass.__name__ = "test"
        type(klass).last_saved = PropertyMock(return_value=datetime.now())
        klass.get_ips.return_value = ['1.1.1.1/32']

        bl_mock.get_class.return_value = klass

        url = "/{}?cidr=enabled".format(klass.__name__.lower())
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")
        self.assertIn("Magicmock", result.get_data().decode('utf-8'))

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
            """)  # noqa
        self.assertEqual(result.get_data().decode('ascii'), expected_content)

    @patch('blocklister.main.Blocklist')
    def test_get_multilist(self, bl_mock):
        foo_klass = MagicMock()
        foo_klass.__name__ = "foo"
        type(foo_klass).last_saved = PropertyMock(return_value=datetime.now())
        foo_klass.get_ips.return_value = ['1.1.1.1']

        bar_klass = MagicMock()
        bar_klass.__name__ = "bar"
        type(bar_klass).last_saved = PropertyMock(return_value=datetime.now())
        bar_klass.get_ips.return_value = ['2.2.2.2']

        bl_mock.get_class.side_effect = [foo_klass, bar_klass]
        url = "/multilist?blocklists=foo,bar"
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")
        self.assertIn("multilist", result.get_data().decode('utf-8'))

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
            """)  # noqa
        self.assertEqual(result.get_data().decode('ascii'), expected_content)

    @patch('blocklister.main.Blocklist')
    def test_get_multilist_cidr(self, bl_mock):
        foo_klass = MagicMock()
        foo_klass.__name__ = "foo"
        type(foo_klass).last_saved = PropertyMock(return_value=datetime.now())
        foo_klass.get_ips.return_value = ['1.1.1.1/32']

        bar_klass = MagicMock()
        bar_klass.__name__ = "bar"
        type(bar_klass).last_saved = PropertyMock(return_value=datetime.now())
        bar_klass.get_ips.return_value = ['2.2.2.2/32']

        bl_mock.get_class.side_effect = [foo_klass, bar_klass]
        url = "/multilist?blocklists=foo,bar&cidr=enabled"
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")
        self.assertIn("multilist", result.get_data().decode('utf-8'))
