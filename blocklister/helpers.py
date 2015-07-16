from pkg_resources import resource_string


def get_changelog():
    content = resource_string(__name__, "changelog.txt")
    return content
