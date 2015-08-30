from __future__ import print_function

import sys
import glob

try:
    from setuptools import setup, find_packages
except ImportError:    
    print("This module requires setuptools or (deprecated) distutils.")
    print("Please install setuptools with get-pip.py!")
    
    sys.exit(1)

description = "Camellia-cipher in Python"

def long_description():
    try:
        return open('README.rst').read()
    except:
        return description

setup(
    name="python-camellia",
    version="0.1",
    description=description,
    long_description=long_description(),
    author="Simon Biewald",
    author_email="simon.biewald@homtail.de",
    url="https://github.com/var-sec/python-camellia",
    packages = find_packages(),
    package_data = {
        'camellia':['*.dll', '*.c'],
    },
    license = "MIT",
    
    #include_package_data=True,
)

if "bdist_wheel" in sys.argv or "bdist_egg" in sys.argv or "install" in sys.argv:
    print()
    print("!!! IMPORTANT !!!")
    print()
    print("* After installing python-camellia do following: *")
    print("Remember to execute the installed script at least one time to compile "
          "the C extension. This requires gcc to work (or specify any other "
          "compiler via CC var). It may require superuser rights to work. "
          "It's not required on Windows!")
    print()
    print("!!! IMPORTANT !!!")
    print()
