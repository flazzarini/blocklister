import unittest
from blocklister.main import app, get_class
from blocklister.models import (
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


class TestHelpers(unittest.TestCase):
    def setUp(self):
        self.classes = [
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
        ]

    def test_get_class(self):
        for klass in self.classes:
            result = get_class(klass.__name__.title())
            self.assertEqual(result, klass)

    def test_get_class_raises(self):
        with self.assertRaises(ValueError):
            get_class("NonExistingClass")


class TestMain(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
