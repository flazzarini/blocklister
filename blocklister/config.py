import logging

from configparser import ConfigParser, NoSectionError, NoOptionError
from os.path import exists

LOG = logging.getLogger(__name__)
DEFAULT_PATHS = ['/etc/blocklister/', '~/.', '']


class Config(object):
    def __init__(self, filename='blocklister.conf', paths=DEFAULT_PATHS):
        self.config = ConfigParser()
        self.filename = filename
        self.loadedfiles = []
        self.paths = paths
        try:
            self._load()
        except ConfigError as exc:
            raise ConfigError(exc)

    def _load(self):
        for path in self.paths:
            searchfile = "{0}{1}".format(path, self.filename)
            if exists(searchfile):
                LOG.debug("{0} from {1}".format(
                    self.loadedfiles and 'Updating' or 'Loading',
                    searchfile))
                self.loadedfiles.append(searchfile)
                self.config.read(searchfile)

    def get(self, section, option, default=None):
        """
        Returns the value of an option in a section in the config file. When
        using this method you can specify a `default` value to be returned if
        the option is not present in the loaded configuration file.

        :param section: Option file section
        :param option: Section option
        :param default: Specify a default value to be used if option is not
                        found
        """
        try:
            value = self.config.get(section, option)
            return value
        except (NoSectionError, NoOptionError) as exc:
            LOG.debug(
                "{0} Returning specified default value {1}"
                .format(exc, default))
            return default

    def get_list(self, section, option, default=[]):
        """
        Returns a list of values which are specified in an option. In a config
        file you could specify a list of values by using new lines as a
        seperator. For instance like this

            [blocklister]
            iplist=1.1.1.1
                2.2.2.2
                3.3.3.3
            store=/tmp/
        """
        try:
            source = self.config.get(section, option)
            values = source.split('\n')
            return values
        except (NoSectionError, NoOptionError) as exc:
            LOG.debug(
                "{0} Returning specified default value {1}"
                .format(exc, default))
            return default

    def get_int(self, section, option, default=0):
        """
        Return the value of the option specified as an integer.
        """
        try:
            value = self.config.getint(section, option)
            return value
        except (NoSectionError, NoOptionError) as exc:
            LOG.debug(
                "{0} Returning specified default value {1}"
                .format(exc, default))
            return default
        except ValueError as exc:
            msg = (
                "Value in section {0} option {1} cannot be cast as integer"
                .format(section, option))
            raise ConfigError(msg)

    def get_boolean(self, section, option, default=0):
        """
        Return the value of the option specified as a boolean.
        """
        try:
            value = self.config.getboolean(section, option)
            return value
        except (NoSectionError, NoOptionError) as exc:
            LOG.debug(
                "{0} Returning specified default value {1}"
                .format(exc, default))
            return default
        except ValueError as exc:
            msg = (
                "Value in section {0} option {1} cannot be cast as boolean"
                .format(section, option))
            raise ConfigError(msg)


class ConfigError(Exception):
    pass
