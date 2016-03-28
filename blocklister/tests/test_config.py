import unittest
from unittest.mock import patch
from textwrap import dedent

from tempfile import NamedTemporaryFile
from blocklister.config import Config, ConfigError


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = NamedTemporaryFile(delete=True)
        self.content = dedent(
            """
            [testing]
            list = item1
                item2
                item3
            list_single = item1
            foo = 1
            bar = foo
            enabled = True
            disabled = False
            """)
        self.f = open(self.tmp.name, "w")
        self.f.write(self.content)
        self.f.close()
        self.config = Config(filename=self.tmp.name)

    @patch('blocklister.config.Config._load')
    def test_filename(self, loadmock):
        """
        Test if file is set correctly
        """
        result = 'test.ini'
        cl = Config(filename=result)
        self.assertEqual(cl.filename, result)

    def test_load(self):
        """
        Test loading an ini file
        """
        result = self.config.loadedfiles
        expected = [self.tmp.name]
        self.assertEqual(result, expected)

    def test_get(self):
        """
        test_get getting the testing option from temp ini file
        """
        result = self.config.get('testing', 'bar')
        expected = 'foo'
        self.assertEqual(result, expected)

    def test_get_default(self):
        """
        Test get default for non existing option
        """
        result = self.config.get('testing', 'notfound', default='amp')
        expected = 'amp'
        self.assertEqual(result, expected)

    def test_get_list(self):
        result = self.config.get_list('testing', 'list')
        expected = ['item1', 'item2', 'item3']
        self.assertCountEqual(result, expected)

    def test_get_list_single_item(self):
        result = self.config.get_list('testing', 'list_single')
        expected = ['item1']
        self.assertCountEqual(result, expected)

    def test_get_list_default(self):
        result = self.config.get_list(
            'testing', 'listNotFound', default=['1', '2'])
        expected = ['1', '2']
        self.assertCountEqual(result, expected)

    def test_get_int(self):
        result = self.config.get_int('testing', 'foo')
        expected = 1
        self.assertEqual(result, expected)

    def test_get_int_valueerror(self):
        with self.assertRaises(ConfigError):
            self.config.get_int('testing', 'bar')

    @patch('blocklister.config.exists')
    def test_load_searchfile(self, exists_mock):
        """
        Test lookup function
        """
        exists_mock = True
        cl = Config(filename='testing.ini')
        result = cl.loadedfiles
        expected = ['/etc/blocklister/testing.ini',
                    '~/.testing.ini',
                    'testing.ini']
        self.assertEqual(result, expected)
