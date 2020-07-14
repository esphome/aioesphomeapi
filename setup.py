#!/usr/bin/env python3
"""aioesphomeapi setup script."""
from setuptools import find_packages, setup

VERSION = '2.6.1'
PROJECT_NAME = 'aioesphomeapi'
PROJECT_PACKAGE_NAME = 'aioesphomeapi'
PROJECT_LICENSE = 'MIT'
PROJECT_AUTHOR = 'Otto Winter'
PROJECT_COPYRIGHT = ' 2019, Otto Winter'
PROJECT_URL = 'https://esphome.io/'
PROJECT_EMAIL = 'contact@otto-winter.com'

PROJECT_GITHUB_USERNAME = 'esphome'
PROJECT_GITHUB_REPOSITORY = 'aioesphomeapi'

PYPI_URL = 'https://pypi.python.org/pypi/{}'.format(PROJECT_PACKAGE_NAME)
GITHUB_PATH = '{}/{}'.format(PROJECT_GITHUB_USERNAME, PROJECT_GITHUB_REPOSITORY)
GITHUB_URL = 'https://github.com/{}'.format(GITHUB_PATH)

DOWNLOAD_URL = '{}/archive/{}.zip'.format(GITHUB_URL, VERSION)

REQUIRES = [
    'attrs>=19.3.0',
    'protobuf>=3.12.2,<4.0',
    'zeroconf>=0.28.0,<1.0',
]

setup(
    name=PROJECT_PACKAGE_NAME,
    version=VERSION,
    url=PROJECT_URL,
    download_url=DOWNLOAD_URL,
    author=PROJECT_AUTHOR,
    author_email=PROJECT_EMAIL,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIRES,
    python_requires='>=3.5.3',
)
