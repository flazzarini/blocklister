from textwrap import dedent

import pytest

from blocklister.config import Config, ConfigError


@pytest.fixture
def config_file(tmp_path):
    """Fixture that creates a temporary config file for testing."""
    content = dedent(
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
    file_path = tmp_path / "test.ini"
    file_path.write_text(content, encoding="utf-8")
    return file_path


@pytest.fixture
def config(config_file):
    return Config(filename=str(config_file))


def test_filename():
    """Config stores the supplied filename without loading a file."""
    config_obj = Config(filename="test.ini")
    assert config_obj.filename == "test.ini"


def test_load(config, config_file):
    """Config loads the temporary ini file and records the loaded path."""
    assert config.loadedfiles == [str(config_file)]


def test_get(config):
    """Config.get returns the stored value for an existing option."""
    assert config.get("testing", "bar") == "foo"


def test_get_default(config):
    """Config.get returns the default when an option is missing."""
    assert config.get("testing", "notfound", default="amp") == "amp"


def test_get_list(config):
    """Config.get_list splits a multiline option into a list."""
    assert config.get_list("testing", "list") == ["item1", "item2", "item3"]


def test_get_list_single_item(config):
    """Config.get_list returns a single-item list for a one-line option."""
    assert config.get_list("testing", "list_single") == ["item1"]


def test_get_list_default(config):
    """Config.get_list returns the provided default when the option is missing."""
    assert config.get_list("testing", "listNotFound", default=["1", "2"]) == ["1", "2"]


def test_get_int(config):
    """Config.get_int converts an option value to an integer."""
    assert config.get_int("testing", "foo") == 1


def test_get_int_valueerror(config):
    """Config.get_int raises ConfigError for non-integer values."""
    with pytest.raises(ConfigError):
        config.get_int("testing", "bar")


def test_get_boolean(config):
    """Config.get_boolean converts a boolean option correctly."""
    assert config.get_boolean("testing", "enabled", default=False)


def test_load_searchfile(monkeypatch):
    """Config searches through default paths for a missing filename."""
    monkeypatch.setattr("blocklister.config.exists", lambda path: True)

    config_obj = Config(filename="testing.ini")

    assert config_obj.loadedfiles == [
        "/etc/blocklister/testing.ini",
        "~/.testing.ini",
        "testing.ini",
    ]
