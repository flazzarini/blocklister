from StringIO import StringIO
from os import path, environ
import fabric.api as fab
import fabric.colors as clr

PYREPO_DIR = "/var/www/gefoo.org/pyrepo"
PYREPO_URL = "https://pyrepo.gefoo.org"
DEPLOY_DIR = "/var/www/gefoo.org/blocklister"
PACKAGE_NAME = 'blocklister'
USER = 'blocklister'

fab.env.roledefs = {
    'pyrepo': ['pyrepo.gefoo.org'],
    'prod': ['spoon.gefoo.org'],
    'staging': ['foodtaster.lchome.net'],
}


@fab.task
def develop():
    if not path.exists("env"):
        fab.local("virtualenv -p /usr/bin/python3 env")
    fab.local("env/bin/python setup.py develop")
    fab.local("env/bin/pip install pytest")
    fab.local("env/bin/pip install pytest-xdist")


@fab.task
def test():
    fab.local("env/bin/py.test -f --color yes blocklister")


@fab.roles('pyrepo')
@fab.task
def publish():
    fab.local("env/bin/python setup.py sdist")
    tar_filename = fab.local(
        "env/bin/python setup.py --fullname", capture=True
    )
    dist_filename = "dist/{}.tar.gz".format(tar_filename)
    fab.put(dist_filename, PYREPO_DIR)


@fab.task
def deploy():
    branch = fab.local('git rev-parse --abbrev-ref HEAD', capture=True)

    if branch == "develop":
        fab.local("env/bin/python setup.py sdist")
        tar_filename = "{}.tar.gz".format(
            fab.local(
                "env/bin/python setup.py --fullname", capture=True
            )
        )
        dist_filename = "dist/{}".format(tar_filename)
        dest_filename = "/tmp/{}".format(tar_filename)
        fab.put(dist_filename, dest_filename)

        fab.env.user = USER
        with fab.cd(DEPLOY_DIR):
            fab.run(
                "env/bin/pip uninstall --trusted-host pyrepo.gefoo.org -y {}"
                .format(PACKAGE_NAME))
            fab.run(
                "env/bin/pip install --trusted-host pyrepo.gefoo.org "
                "--upgrade {}"
                .format(dest_filename))

    else:
        fab.execute("publish")
        fab.env.user = USER
        with fab.cd(DEPLOY_DIR):
            fab.run(
                "env/bin/pip install --trusted-host pyrepo.gefoo.org "
                "--upgrade -f {} {}"
                .format(PYREPO_URL, PACKAGE_NAME)
            )


@fab.task
def bootstrap():
    """
    Bootstrap environment
    """
    # Install system dependencies
    deps = [
        'apache2',
        'libapache2-mod-wsgi',
        'curl',
        'gzip',
        'python-setuptools',
    ]
    fab.sudo("aptitude install -q -y {0}".format(" ".join(deps)))
    fab.sudo("easy_install virtualenv")

    # Create Application User on the node
    fab.env.warn_only = True
    if not fab.run("cat /etc/passwd | grep \"^{}:.*$\"".format(USER)):
        fab.sudo(
            "useradd -d {0} -r -s /bin/sh {1}".format(DEPLOY_DIR, USER)
        )
        fab.sudo(
            "install -o {0} -g {0} -d {1}".format(USER, DEPLOY_DIR)
        )

    home = environ['HOME']
    publickeyfile = "{0}/.ssh/id_rsa.pub".format(home)
    if not path.exists(publickeyfile):
        print clr.red(
            "Could not continue! You need a public key on the target "
            "machine!"
        )
    publickey = readfile(publickeyfile)

    with fab.cd(DEPLOY_DIR):
        fab.sudo("[ -d .ssh ] || mkdir .ssh")
        fab.sudo("echo {0} > .ssh/authorized_keys".format(publickey))
        fab.sudo("chown {0}.{0} .ssh -R".format(USER))
        fab.sudo("install -o {0} -g {1} -d log".format("www-data", USER))
        fab.sudo("install -o {0} -g {0} -d conf".format(USER, USER))
        fab.sudo("install -o {0} -g {0} -d wsgi".format(USER, USER))

    # Create Apache config files
    apache_content = apache_template(
        PACKAGE_NAME,
        DEPLOY_DIR,
        USER,
        servername="{}.gefoo.org".format(PACKAGE_NAME)
    )
    apache_filename = (
        "/etc/apache2/sites-available/{}.conf".format(PACKAGE_NAME)
    )
    fab.put(StringIO(apache_content), apache_filename, use_sudo=True)

    fab.env.user = USER
    with fab.cd(DEPLOY_DIR):
        fab.run("virtualenv env")

        # Create config files
        apache_content = apache_template(
            PACKAGE_NAME,
            DEPLOY_DIR,
            USER,
            servername="{}.gefoo.org".format(PACKAGE_NAME)
        )
        apache_filename = (
            "/etc/apache2/sites-available/{}.conf".format(PACKAGE_NAME)
        )

        wsgi_content = wsgi_template(
            PACKAGE_NAME,
            DEPLOY_DIR,
        )
        wsgi_filename = "{0}/wsgi/{1}.wsgi".format(DEPLOY_DIR, PACKAGE_NAME)

        logging_content = logging_template()
        logging_filename = "{0}/logging.ini".format(DEPLOY_DIR)

        fab.put(StringIO(wsgi_content), wsgi_filename)
        fab.put(StringIO(logging_content), logging_filename)


@fab.task
def unbootstrap():
    """
    Remove bootstrap
    """
    fab.sudo("rm -Rf {0}".format(DEPLOY_DIR))
    fab.sudo("userdel {0}".format(USER))


def readfile(filename):
    if path.exists(filename):
        return open(filename, "r").read().strip()


def wsgi_template(appname, path, logging_level="INFO"):
    """
    Returns a wsgi configuration based on this template
    """
    template = (
        'import os\n'
        'import logging\n'
        'import logging.config\n'
        '\n'
        'activate_this = "{path}/env/bin/activate_this.py"\n'
        'execfile(activate_this, dict(__file__=activate_this))\n'
        '\n'
        'logging.basicConfig(level=logging.{logging_level})\n'
        'logging.config.fileConfig("{path}/logging.ini")\n'
        '\n'
        'from {app}.main import app as application\n'
        .format(
            app=appname,
            app_up=appname.upper(),
            path=path,
            logging_level=logging_level
        )
    )
    return template


def logging_template():
    """
    Returns a logging configuration based on this template
    """
    template = (
        '[loggers]\n'
        'keys=root\n'
        '\n'
        '[handlers]\n'
        'keys=consoleHandler\n'
        '\n'
        '[formatters]\n'
        'keys=simpleFormatter\n'
        '\n'
        '[logger_root]\n'
        'level=DEBUG\n'
        'handlers=consoleHandler\n'
        '\n'
        '[handler_consoleHandler]\n'
        'class=StreamHandler\n'
        'level=DEBUG\n'
        'formatter=simpleFormatter\n'
        'args=(sys.stdout,)\n'
        '\n'
        '[formatter_simpleFormatter]\n'
        'format=%(asctime)s - %(name)s - %(levelname)s - %(message)s\n'
        'datefmt=\n')
    return template


def apache_template(app, path, user, servername=None):
    template = (
        '<VirtualHost *:80>\n'
        '    ServerName {servername}\n'
        '    \n'
        '    WSGIDaemonProcess {app} user={user} group={user} threads=5\n'
        '    WSGIScriptAlias / {path}/wsgi/{app}.wsgi\n'
        '    \n'
        '    <Directory {path}>\n'
        '        WSGIProcessGroup {app}\n'
        '        WSGIApplicationGroup %{{GLOBAL}}\n'
        '        Order deny,allow\n'
        '        Allow from all\n'
        '    </Directory>\n'
        '    \n'
        '    # Log Files\n'
        '    LogLevel warn\n'
        '    CustomLog {path}/log/access.log combined\n'
        '    ErrorLog  {path}/log/error.log\n'
        '</VirtualHost>\n'

    )
    if not servername:
        servername = fab.prompt(
            "What will be the apache servername?",
            default="app.local.net"
        )
    return template.format(
        app=app,
        path=path,
        servername=servername,
        user=user
    )
