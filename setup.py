from setuptools import setup, find_packages
from os.path import join

NAME = "blocklister"
DESCRIPTION = "Create Mikrotik Firewall address-lists and offer them via http"
AUTHOR = "Frank Lazzarini"
AUTHOR_EMAIL = "flazzarini@gmail.com"
VERSION = open(join(NAME, 'version.txt')).read().strip()
LONG_DESCRIPTION = open("README.rst").read()

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license="Private",
    include_package_data=True,
    install_requires=[
        "Flask >=1.0.0, <2.0",
        "Flask-Limiter==0.9.1",
        "requests >=2.9,<3.0",
    ],
    entry_points={
        'console_scripts': [
            'blocklister-updater=blocklister.updater:run'
        ]
    },
    extras_require={
        "dev": [
            "sphinx",
            "sphinx-rtd-theme",
            "gunicorn",
        ],
        "test": [
            "pylint",
            "pyroma",
            "pytest",
            "pytest-cov",
            "radon",
        ]
    },
    dependency_links=[],
    packages=find_packages(exclude=["tests.*", "tests"]),
    zip_safe=False,
)
