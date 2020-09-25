Installation
============

Install with `pip <https://pip.pypa.io/en/stable/installing/>`_: 

.. code:: shell

   $ pip install python-camellia
   $ # Or:
   $ python -m pip install python-camellia

Notes on the C extension
------------------------

The camellia implementation is written in C, it is glued to Python using `cffi`_.
*pip* tries to automatically install prebuilt packages.
Those are available for x86 and x64 Windows, recent MacOS (x64 only) and Linux.
Additionally prebuilt are available for Linux for ARMv8 (aarch64), z/Architecture (s390x) and 64-bit PowerPC (ppc64le).

When those prebuilt packages are not available, the C code is compiled at installation.
In this case a C compiler is required (usually gcc on Linux, XCode command line tools on MacOS,
Visual Studio on Windows).

.. _cffi: https://pypi.org/project/cffi

List of dependencies
--------------------

Dependencies are automatically installed during installation.

 - `pep272-encryption <https://pypi.org/project/pep272-encryption>`_ providing block cipher modes
 - `cffi`_