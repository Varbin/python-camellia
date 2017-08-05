from cffi import FFI
from distutils.ccompiler import new_compiler
from distutils.dist import Distribution


def get_compiler():
    dist = Distribution()
    dist.parse_config_files()
    cmd = dist.get_command_obj('build')
    cmd.ensure_finalized()
    return new_compiler(compiler=cmd.compiler)


def make_ffi(source_file, header_file, name, extra_link_args=[]):
    with open(header_file) as f:
        header = f.read()

    with open(source_file) as f:
        source = f.read()
    
    ffi = FFI()
    ffi.cdef(header)

    extra_link_args = list(extra_link_args)
    
    if get_compiler().compiler_type == "msvc":
        # DEP + ASLR
        extra_link_args += ["/NXCOMPAT", "/DYNAMICBASE"]

    ffi.set_source(name, source, extra_link_args=extra_link_args)

    return ffi
