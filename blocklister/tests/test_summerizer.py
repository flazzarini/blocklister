import unittest
from unittest.mock import patch
from blocklister.summerizer import Summerizer

class TestSummerizer(unittest.TestCase):

    def testRangeOfOne(self):
        smr = Summerizer(['213.239.193.209-213.239.193.209'])
        self.assertEqual(smr.summary(),['213.239.193.209'])

    def testOridnaryRange(self):
        smr = Summerizer(['213.221.87.72-213.221.87.79'])
        self.assertEqual(smr.summary(),['213.221.87.72-213.221.87.79'])

    def testRangeOverflow(self):
        smr = Summerizer(['72.32.242.248-72.32.243.255','64.69.78.73'])
        self.assertEqual(smr.summary(),['64.69.78.73','72.32.242.248-72.32.243.255'])

    def testReversedOrder(self):
        smr = Summerizer(['72.32.243.255-72.32.242.248'])
        self.assertEqual(smr.summary(),['72.32.242.248-72.32.243.255'])
