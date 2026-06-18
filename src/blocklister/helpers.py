from importlib.resources import read_text


def get_changelog():
    return read_text(__name__, "changelog.txt", encoding="ascii")
