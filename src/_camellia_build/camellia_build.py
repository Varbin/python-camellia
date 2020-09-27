#!/usr/bin/env python3
"""Builder for the C-extension of python-camellia.
"""

from distutils.ccompiler import new_compiler
from distutils.errors import DistutilsArgError

import os

from cffi import FFI
from setuptools import Distribution


HERE = os.path.dirname(__file__)

SOURCE_FILES = ["camellia.c", "camellia_modes.c"]
HEADER_FILES = ["camellia.h", "camellia_modes.h"]


header = ""
for header_file in HEADER_FILES:
    with open(os.path.join(HERE, header_file)) as f:
        header += "\n\n" + f.read()


sources = []
for source_file in SOURCE_FILES:
    sources.append(os.path.join(HERE, source_file))


def extra_link_args():
    """
    Add arguments for Data Execution Prevention and ASLR.
    This is only relevant for older Python versions.

    :return: `list` of arguments
    """
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

    return []


ffi = FFI()
ffi.cdef(header)
ffi.set_source("camellia._camellia", header, sources=sources,
               include_dirs=[HERE], extra_link_args=extra_link_args())
