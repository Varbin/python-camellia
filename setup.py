#!/usr/bin/env python3

from __future__ import print_function

import sys
import os
import glob

try:
    from setuptools import setup, find_packages
except ImportError:    
    print('This module requires setuptools.')
    print('Please install setuptools with get-pip.py!')
    
    sys.exit(1)

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    
import camellia_build

description = 'Camellia-cipher in Python'


def long_description():
    try:
        return open('README.rst').read()
    except:
        return description


ext = camellia_build.ffi.distutils_extension()
ext.include_dirs.append(os.path.join(os.path.dirname(__file__), 'src', 'camellia_build'))


setup(
    name='python-camellia',
    version='1.0',
    description=description,
    long_description=long_description(),
    author='Simon Biewald',
    author_email='simon.biewald@homtail.de',
    url='https://github.com/var-sec/python-camellia',
    packages = ['camellia'],
    package_dir = {'camellia':'src/camellia'},

    license = 'MIT',
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],
    keywords = [
        'camellia', 'encryption', 'decryption', 'cipher',
    ],

    platforms = ['all'],

    ext_modules = [ext],
    setup_requires=['cffi>=1.0.0'],
    install_requires=['cffi>=1.0.0', 'pep272-encryption']

)
