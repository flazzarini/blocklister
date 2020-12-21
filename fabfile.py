import re
import sys
import os
from collections import namedtuple
from datetime import datetime
from fileinput import input as finput
from netrc import netrc
from os import listdir
from os.path import join
from typing import List

from fabric import task
from fabric.connection import Connection

Credentials = namedtuple('Credentials', 'username, password')


def get_package_name(conn):
    """Return package name"""
    result = conn.run("env/bin/python setup.py --name")
    return result.stdout.strip("\n")


def get_package_description(conn):
    """Return package description"""
    result = conn.run("env/bin/python setup.py --description")
    return result.stdout.strip("\n")


def get_version(conn):
    """Returns version of the package"""
    version_output = conn.run("./env/bin/python setup.py --version")
    return version_output.stdout.strip("\n")


def get_surrounding_years():
    """
    Gets the surrounding years -1 from current year and +1 from current year
    """
    year = datetime.now().year
    return [year - 1, year, year + 1]


def get_credentials(sitename: str) -> Credentials:
    """Retrieves username and password from .netrc file"""
    netrc_instance = netrc()
    result = netrc_instance.authenticators(sitename)
    if not result:
        raise Exception("Please add your credentials to "
                        "your ~/.netrc file for site %s" % sitename)

    return Credentials(result[0], result[2])


def get_docker_tags(package_name: str, version: str) -> List[str]:
    """
    Prepare docker tags to put on images
    """
    targets = [
        "flazzarini/%s:latest" % package_name,
        "flazzarini/%s:%s" % (package_name, version),
    ]
    targets.extend(
        [
            "registry.gefoo.org/%s" % (_) for _ in targets
        ]
    )
    return targets


def verify_pip_config(conn, executed_in_ci=False):
    """
    Verifies if your pip configuration contains `pypi.gefoo.org` and sets
    credentials if executed in CI
    """
    # Skip this check when executed in CI, we are probably relying on
    # Environment Variables
    if executed_in_ci:
        twine_env_vars = [
            'TWINE_USERNAME',
            'TWINE_PASSWORD',
            'TWINE_REPOSITORY',
        ]
        for twine_env_var in twine_env_vars:
            if not os.environ.get(twine_env_var):
                print("Make sure you have %r set" % (twine_env_var))
        return

    result = conn.run("cat ~/.pypirc | grep -e \"^\[pypi.gefoo.org\]$\"")
    if result.exited != 0:
        raise Exception(
            "pypi.gefoo.org repository is not configured in your ~/.pypirc")
    return


@task
def build(conn):
    """Builds python package"""
    conn.run("./env/bin/python setup.py clean")
    conn.run("./env/bin/python setup.py bdist bdist_wheel")


@task
def develop(conn):
    """Creates development environment"""
    conn.run("[ -d env ] || python3 -m venv env", replace_env=False)
    conn.run("env/bin/pip install -U pip setuptools", replace_env=False)
    conn.run("env/bin/pip install wheel", replace_env=False)
    conn.run("env/bin/pip install -e .[test,dev]", replace_env=False)


@task
def publish(conn):
    """Publish to pyrepo"""
    verify_pip_config(conn)
    conn.run("./env/bin/python setup.py clean")
    conn.run("./env/bin/python setup.py bdist bdist_wheel")
    filename = conn.run(
        "./env/bin/python setup.py --fullname").stdout.strip("\n")

    dist_file = "dist/%s-py3-none-any.whl" % (filename)
    conn.run("./env/bin/twine upload -r pypi.gefoo.org %s" % dist_file)


@task
def doc(conn):
    """Builds doc"""
    conn.run("rm -Rf doc/_build/*")
    conn.run("rm -Rf doc/api-doc/*.rst")
    conn.run("find doc/ -name '*.rst' -exec touch {} \;")
    conn.run(
        "./env/bin/python ci/scripts/gen_api_doc.py --dest doc/api-doc",
        pty=True)

    for year in get_surrounding_years():
        conn.run(
            """\
            ./env/bin/python ci/scripts/gen_weeknr_map_doc.py \
                --dest doc/weektables-doc/weektable_{year}.rst \
                --year {year}
            """.format(year=year))
    conn.run("./env/bin/sphinx-build --color -aE doc doc/_build", pty=True)


@task
def publish_doc(conn, username=None, password=None, branch='develop'):
    """Publishes doc to https://docs.gefoo.org"""
    if not username or not password:
        credentials = get_credentials("docs.gefoo.org")
    else:
        credentials = Credentials(username, password)

    doc(conn)
    conn.run("cd doc/_build && zip -r doc.zip *")
    package = get_package_name(conn)
    description = get_package_description(conn)

    print("Got branch %s" % branch)
    if branch and branch != "master":
        version = 'develop'
    else:
        version = get_version(conn)

    conn.run(
        """\
        cd doc/_build && \
        curl -X POST \
            --user {username}:{password} \
            -F filedata=@doc.zip \
            -F name="{package}" \
            -F version="{version}" \
            -F description="{description}" \
            https://docs.gefoo.org/hmfd
        """.format(username=credentials.username,
                   password=credentials.password,
                   package=package,
                   version=version,
                   description=description))


@task
def test(conn):
    """Run tests"""
    conn.run("[ -d .pytest_cache ] && rm -Rf .pytest_cache")
    conn.run(
        "env/bin/pytest-watch %s/ tests/ -- --lf -vv --color yes" % (
            get_package_name(conn)
        )
    )


@task
def test_cov(conn):
    """Run tests with coverage checks"""
    conn.run(
        "env/bin/py.test --cov=%s --cov-report=term" % get_package_name(conn))


@task
def test_covhtml(conn):
    """Run tests with coverage checks as html report"""
    conn.run(
        "env/bin/py.test --cov=%s --cov-report=html" % get_package_name(conn))


@task
def build_docker(conn, do_python_build=True):
    """Builds docker image"""
    if do_python_build:
        build(conn)

    package_name = get_package_name(conn)
    version = get_version(conn)
    targets = get_docker_tags(package_name, version)
    for target in targets:
        conn.run(
            "docker build "
            "--build-arg VERSION=%s "
            "-t %s -f Dockerfile-Blocklister ." % (
                version,
                target,
            )
        )

    # Separate build process for blocklister-updater
    package_name = "blocklister-updater"
    version = get_version(conn)
    targets = get_docker_tags(package_name, version)
    for target in targets:
        conn.run(
            "docker build "
            "--build-arg VERSION=%s "
            "-t %s -f Dockerfile-Updater ." % (
                version,
                target,
            )
        )


@task
def build_and_upload_docker(conn):
    """Builds all docker test images and uploads them"""
    build_docker(conn)

    package_name = get_package_name(conn)
    version = get_version(conn)
    targets = get_docker_tags(package_name, version)
    for target in targets:
        if "registry.gefoo.org" in target:
            conn.run("docker push %s" % target)


@task
def build_changelog(conn, filename="CHANGELOG.md"):
    """Parses the CHANGELOG.md and adds a link for each issue id"""
    issue_links = get_changelog_links(filename=filename)
    clean_changelog_links(filename=filename)
    append_changelog_links(filename=filename, links_entries=issue_links)


@task
def run(conn):
    """Run application with gunicorn"""
    package_name = get_package_name(conn)
    conn.run(
        """
        ./env/bin/gunicorn -b 0.0.0.0 %s.main:app --reload
        """ % package_name,
        pty=True,
        replace_env=False
    )

