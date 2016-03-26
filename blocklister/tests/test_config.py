import unittest
from unittest.mock import patch

from tempfile import NamedTemporaryFile
from blocklister.config import Config, ConfigError


class TestConfigloader(unittest.TestCase):
    def setUp(self):
        self.tmp = NamedTemporaryFile(delete=True)
        self.content = "[testing]\noption = value\n"
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
        result = self.config.get('testing', 'option')
        expected = 'value'
        self.assertEqual(result, expected)

    def test_get_default(self):
        """
        Test get default for non existing option
        """
        result = self.config.get('testing', 'notfound', default='amp')
        expected = 'amp'
        self.assertEqual(result, expected)

    def test_not_found(self):
        """
        Test for config file not found
        """
        with self.assertRaises(ConfigError):
            Config(filename="tztztztztest1234.ini")

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
