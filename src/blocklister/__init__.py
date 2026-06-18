from importlib.metadata import version
from .helpers import get_changelog

__version__ = version("blocklister")
__changelog__ = get_changelog()
