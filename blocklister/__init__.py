from pkg_resources import resource_string
from .helpers import get_changelog

__version__ = resource_string(__name__, "version.txt").decode('ascii').strip()
__changelog__ = get_changelog()
