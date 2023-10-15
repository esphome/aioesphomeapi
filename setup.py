#!/usr/bin/env python3
"""aioesphomeapi setup script."""
import os

from setuptools import find_packages, setup
import os
from distutils.command.build_ext import build_ext


here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding="utf-8") as readme_file:
    long_description = readme_file.read()


VERSION = "18.0.2"
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


setup_kwargs = {
    "name": PROJECT_PACKAGE_NAME,
    "version": VERSION,
    "url": PROJECT_URL,
    "download_url": DOWNLOAD_URL,
    "author": PROJECT_AUTHOR,
    "author_email": PROJECT_EMAIL,
    "description": "Python API for interacting with ESPHome devices.",
    "long_description": long_description,
    "license": PROJECT_LICENSE,
    "packages": find_packages(exclude=["tests", "tests.*"]),
    "include_package_data": True,
    "zip_safe": False,
    "install_requires": REQUIRES,
    "python_requires": ">=3.9",
    "test_suite": "tests",
}


class OptionalBuildExt(build_ext):
    def build_extensions(self):
        try:
            super().build_extensions()
        except Exception:
            pass


def cythonize_if_available(setup_kwargs):
    if os.environ.get("SKIP_CYTHON", False):
        return
    try:
        from Cython.Build import cythonize

        setup_kwargs.update(
            dict(
                ext_modules=cythonize(
                    [
                        "aioesphomeapi/connection.py",
                        "aioesphomeapi/_frame_helper/plain_text.py",
                        "aioesphomeapi/_frame_helper/noise.py",
                        "aioesphomeapi/_frame_helper/base.py",
                    ],
                    compiler_directives={"language_level": "3"},  # Python 3
                ),
                cmdclass=dict(build_ext=OptionalBuildExt),
            )
        )
    except Exception:
        if os.environ.get("REQUIRE_CYTHON"):
            raise
        pass


cythonize_if_available(setup_kwargs)

setup(**setup_kwargs)
