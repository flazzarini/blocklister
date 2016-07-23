import unittest
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
        klass = MagicMock()
        klass.__name__ = "test"
        type(klass).last_saved = PropertyMock(return_value=datetime.now())
        klass.get_ips.return_value = ['1.1.1.1']

        bl_mock.get_class.return_value = klass

        url = "/{}".format(klass.__name__.lower())
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/plain")

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
        self.assertIn("Magicmock", result.get_data().decode('utf-8'))

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
