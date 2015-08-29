from __future__ import print_function

import sys
import glob

try:
    from setuptools import setup, find_packages
except ImportError:    
    print("This module requires setuptools or (deprecated) distutils.")
    print("Please install setuptools with get-pip.py!")
    
    sys.exit(1)

setup(
    name="python-camellia",
    version="0.1",
    description="Camellia in Python",
    author="Simon Biewald",
    author_email="simon.biewald@homtail.de",
    url="https://github.com/var-sec/python-camellia",
    packages = find_packages(),
    package_data = {
        'camellia':['*.dll', '*.c'],
    },
    #include_package_data=True,
)
