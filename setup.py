#!/usr/bin/env python3
"""
Setup script for module `python-camellia`.

Usage:
    setup.py build          Build extension modules and prepare for install.
    setup.py install        Install module.

    setup.py sdist          Create source package.
    setup.py bdist_wheel    Create a `wheel` binary package.
"""

from __future__ import print_function

import sys


try:
    from setuptools import setup, find_packages
except ImportError:
    print('This module requires setuptools.')
    print('Please install setuptools with get-pip.py!')

    sys.exit(1)


description = 'Camellia block cipher in Python'


def long_description(short=description):
    """Try to read README.rst or returns fallback."""
    try:
        return open('README.rst').read()
    except FileNotFoundError:
        return short


setup(
    name='python-camellia',
    version='1.1.0.dev0',
    description=description,
    long_description=long_description(),
    author='Simon Biewald',
    author_email='simon@fam-biewald.de',
    url='https://github.com/varbin/python-camellia',
    project_urls={
        'Documentation': 'https://python-camellia.readthedocs.io',
        'Source': 'https://github.com/Varbin/python-camellia',
        'Tracker': 'https://github.com/Varbin/python-camellia/issues'
    },
    packages=['camellia'],
    package_dir={'camellia': 'src/camellia'},
    package_data={
        "": ["py.typed", "*.pyi"],
    },

    cffi_modules=['src/_camellia_build/camellia_build.py:ffi'],

    license='MIT and BSD-2-Clause',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
        'Typing :: Typed'
    ],
    keywords=[
        'camellia', 'encryption', 'block cipher'
    ],

    platforms=['all'],

    setup_requires=['cffi>=1.0.0', 'pytest-runner'],
    tests_require=['pytest', 'pytest-runner'],
    install_requires=['cffi>=1.0.0', 'pep272-encryption'],
    extras_require={
        'docs': ['sphinx', 'sphinx_rtd_theme'],
        'tests': ['coverage', 'pytest', 'pytest-runner'],
    }

)
