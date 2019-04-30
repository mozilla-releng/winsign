#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from glob import glob
from os.path import basename, splitext

from setuptools import Extension, find_packages, setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

requirements = []

setup_requirements = ["pytest-runner", "cython"]

test_requirements = ["pytest"]

setup(
    author="Chris AtLee",
    author_email="catlee@mozilla.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    description="Utilities to support code signing Windows executable files",
    install_requires=requirements,
    license="MPL2.0",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="winsign",
    name="winsign",
    packages=find_packages("src"),
    package_dir={"": "src"},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    ext_modules=[Extension("winsign._hash", ["src/winsign/_hash.c"])],
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/catlee/winsign",
    version="0.1.0",
    zip_safe=False,
)
