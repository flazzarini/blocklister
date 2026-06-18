import pytest

from blocklister.summerizer import Summerizer


def assert_items_equal(actual, expected):
    assert sorted(actual) == sorted(expected)


def test_range_of_one():
    """A single IP range returns the exact IP when summarized."""
    smr = Summerizer(['213.239.193.209-213.239.193.209'])
    result = smr.summary()
    assert_items_equal(result, ['213.239.193.209'])


def test_ordinary_range():
    """A normal contiguous range remains unchanged."""
    smr = Summerizer(['213.221.87.72-213.221.87.79'])
    result = smr.summary()
    assert_items_equal(result, ['213.221.87.72-213.221.87.79'])


def test_range_overflow():
    """A range spanning a rollover and a standalone IP are preserved correctly."""
    smr = Summerizer(['72.32.242.248-72.32.243.255', '64.69.78.73'])
    result = smr.summary()
    assert_items_equal(result, ['72.32.242.248-72.32.243.255', '64.69.78.73'])


def test_reverse_order():
    """A reversed range is normalized to ascending order."""
    smr = Summerizer(['72.32.243.255-72.32.242.248'])
    result = smr.summary()
    assert_items_equal(result, ['72.32.242.248-72.32.243.255'])


def test_overlaps():
    """Overlapping ranges are merged into a single summarized range."""
    smr = Summerizer(['1.1.1.1-1.1.1.5', '1.1.1.2'])
    result = smr.summary()
    assert_items_equal(result, ['1.1.1.1-1.1.1.5'])


def test_complex_unsorted_duplicates_and_multiple_ranges():
    """A complex unsorted input with duplicates yields merged ranges correctly."""
    smr = Summerizer([
        '72.32.243.255-72.32.242.248',
        '72.32.243.250',
        '72.32.243.252-72.32.243.254',
        '72.32.243.249',
        '72.32.245.1-72.32.245.2',
        '64.69.78.73',
        '64.69.78.73',
    ])
    result = smr.summary()
    expected = [
        '64.69.78.73',
        '72.32.242.248-72.32.243.255',
        '72.32.245.1-72.32.245.2',
    ]
    assert result == expected
