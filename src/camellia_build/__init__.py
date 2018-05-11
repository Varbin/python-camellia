#!/usr/bin/env python3
"""Builder for the C-extension of python-camellia.

Usage:
    a) __init__.py     Build extension module inplace.

    b) Import camellia_build:

    >>> from camellia_build import ffi
    >>> extension = ffi.distutils_extension()
    >>> from setuptools import setup
    >>> setup(
        ext_modules = [ext],
        ...
        )

The extension will be built as camellia._camellia.
"""


import os
from ._build_utils import make_ffi

SOURCE_FILE = "camellia.c"
HEADER_FILE = "camellia.h"

source_file = os.path.join(os.path.dirname(__file__), SOURCE_FILE)
header_file = os.path.join(os.path.dirname(__file__), HEADER_FILE)

ffi = make_ffi(source_file, header_file, "camellia._camellia")


if __name__ == "__main__":
    ffi.compile()
