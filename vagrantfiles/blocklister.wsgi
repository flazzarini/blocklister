import os
import logging
import logging.config

activate_this = "/var/www/blocklister/env/bin/activate_this.py"
execfile(activate_this, dict(__file__=activate_this))

logging.basicConfig(level=logging.INFO)
logging.config.fileConfig("/var/www//blocklister/logging.ini")

from blocklister.main import app as application
