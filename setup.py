#!/usr/bin/env python3
"""aioesphomeapi setup script."""
from setuptools import find_packages, setup

VERSION = '1.3.0'
PROJECT_NAME = 'aioesphomeapi'
PROJECT_PACKAGE_NAME = 'aioesphomeapi'
PROJECT_LICENSE = 'MIT'
PROJECT_AUTHOR = 'Otto Winter'
PROJECT_COPYRIGHT = ' 2018, Otto Winter'
PROJECT_URL = 'https://esphomelib.com/esphomeyaml/'
PROJECT_EMAIL = 'contact@otto-winter.com'

PROJECT_GITHUB_USERNAME = 'OttoWinter'
PROJECT_GITHUB_REPOSITORY = 'aioesphomelibpy3haapiclient'

PYPI_URL = 'https://pypi.python.org/pypi/{}'.format(PROJECT_PACKAGE_NAME)
GITHUB_PATH = '{}/{}'.format(PROJECT_GITHUB_USERNAME, PROJECT_GITHUB_REPOSITORY)
GITHUB_URL = 'https://github.com/{}'.format(GITHUB_PATH)

DOWNLOAD_URL = '{}/archive/{}.zip'.format(GITHUB_URL, VERSION)

REQUIRES = [
    'attrs',
    'protobuf',
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
