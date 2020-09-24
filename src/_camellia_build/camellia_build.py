#!/usr/bin/env python3
"""Builder for the C-extension of python-camellia.
"""

from distutils.ccompiler import new_compiler
from distutils.errors import DistutilsArgError

from cffi import FFI
from setuptools import Distribution

import os


HERE = os.path.dirname(__file__)

SOURCE_FILE = "camellia.c"
HEADER_FILE = "camellia.h"

ABSOLUTE_SOURCE_FILE = os.path.join(HERE, SOURCE_FILE)
ABSOLUTE_HEADER_FILE = os.path.join(HERE, HEADER_FILE)

with open(ABSOLUTE_HEADER_FILE) as f:
    header = f.read()

with open(ABSOLUTE_SOURCE_FILE) as f:
    source = f.read()


def extra_link_args():
    dist = Distribution()
    dist.parse_config_files()
    try:
        dist.parse_command_line()
    except (TypeError, DistutilsArgError):  # Happens with setup.py --help
        pass

    build = dist.get_command_obj('build')
    build.ensure_finalized()
    if new_compiler(compiler=build.compiler).compiler_type == 'msvc':
        return ["/NXCOMPAT", "/DYNAMICBASE"]
    else:
        return []


ffi = FFI()
ffi.cdef(header)
ffi.set_source("camellia._camellia", source,
               include_dirs=[HERE], extra_link_args=extra_link_args())
