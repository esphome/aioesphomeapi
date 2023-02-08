#!/usr/bin/env python3
"""aioesphomeapi setup script."""
import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding="utf-8") as readme_file:
    long_description = readme_file.read()


VERSION = "13.2.0"
PROJECT_NAME = "aioesphomeapi"
PROJECT_PACKAGE_NAME = "aioesphomeapi"
PROJECT_LICENSE = "MIT"
PROJECT_AUTHOR = "Otto Winter"
PROJECT_COPYRIGHT = " 2019-2020, Otto Winter"
PROJECT_URL = "https://esphome.io/"
PROJECT_EMAIL = "esphome@nabucasa.com"

PROJECT_GITHUB_USERNAME = "esphome"
PROJECT_GITHUB_REPOSITORY = "aioesphomeapi"

PYPI_URL = "https://pypi.python.org/pypi/{}".format(PROJECT_PACKAGE_NAME)
GITHUB_PATH = "{}/{}".format(PROJECT_GITHUB_USERNAME, PROJECT_GITHUB_REPOSITORY)
GITHUB_URL = "https://github.com/{}".format(GITHUB_PATH)

DOWNLOAD_URL = "{}/archive/{}.zip".format(GITHUB_URL, VERSION)

with open(os.path.join(here, "requirements.txt")) as requirements_txt:
    REQUIRES = requirements_txt.read().splitlines()

setup(
    name=PROJECT_PACKAGE_NAME,
    version=VERSION,
    url=PROJECT_URL,
    download_url=DOWNLOAD_URL,
    author=PROJECT_AUTHOR,
    author_email=PROJECT_EMAIL,
    description="Python API for interacting with ESPHome devices.",
    long_description=long_description,
    license=PROJECT_LICENSE,
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIRES,
    python_requires=">=3.9",
    test_suite="tests",
)
