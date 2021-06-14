#!/usr/bin/env python
# --------------------------------------------------------------------
# Copyright (c) tokenchain. All rights reserved.
# Licensed under the MIT License.
# See License.txt in the project root for license information.
# --------------------------------------------------------------------

"""
    setup
    =====

    Tron: A Python API for interacting with Tron (TRX)

    :copyright: © 2021 by the tokenchain.
    :license: MIT License
"""

import codecs
import os
import platform

from setuptools import (
    find_packages,
    setup,
)
_dir = os.path.dirname(__file__)
py_version = platform.python_version()


def find_version():
    f = codecs.open('version', 'r', 'utf-8-sig')
    line = f.readline()
    f.close()
    return line

def finedescription():
    line = ''
    with open(os.path.join(_dir, 'README.rst')) as f:
        line = f.read()
    return line

PACKAGE_VERSION = str(find_version())
PACKAGE_LONG_DESCRIPTION = str(finedescription())
EXTRAS_REQUIRE = {
    "tester": [
        "coverage",
        "pep8",
        "pyflakes",
        "pylint",
        "pytest-cov"
    ],

    "docs": [
        "mock",
        "sphinx-better-theme>=0.1.4",
        "click>=5.1",
        "configparser==3.5.0",
        "contextlib2>=0.5.4",
        "py-solc>=0.4.0",
        "pytest>=2.7.2",
        "sphinx",
        "pdoc3",
        "sphinx_rtd_theme>=0.1.9",
        "toposort>=1.4",
        "urllib3",
        "wheel >= 0.31.0"
    ],

    "dev": [
        "bumpversion",
        "flaky>=3.3.0",
        "hypothesis>=3.31.2",
        "pytest>=3.5.0,<4",
        "pytest-mock==1.*",
        "pytest-pythonpath>=0.3",
        "pytest-watch==4.*",
        "pytest-xdist==1.*",
        "setuptools>=38.6.0",
        "tox>=1.8.0",
        "twine >= 1.11.0",
        "tqdm",
        "pyinstall",
        "when-changed"
    ]

}

EXTRAS_REQUIRE['dev'] = (
        EXTRAS_REQUIRE['tester'] +
        EXTRAS_REQUIRE['docs'] +
        EXTRAS_REQUIRE['dev']
)

install_requires = [
    "mypy-extensions==0.4.3",
    "web3>=5.20.0",
    "eth-utils==1.10.0"
]


setup(
    name='moodyeth',
    version=PACKAGE_VERSION,
    description='A Python API for interacting with Ethereum based networks',
    long_description=PACKAGE_LONG_DESCRIPTION,
    long_description_content_type='text/x-rst',
    keywords='ethereum eth-api eth-api-python eth-base cli sdk pentest',
    url='https://github.com/tokenchain/moodyeth',
    author='Heskemo',
    author_email='jobhesk@gmail.com',
    license='MIT License',
    zip_safe=False,
    python_requires='>=3.6,<4',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ],
    packages=find_packages(exclude=['examples','lab','test']),
    include_package_data=True,
    install_requires=install_requires,
    tests_require=EXTRAS_REQUIRE['tester'],
    extras_require=EXTRAS_REQUIRE,
)
