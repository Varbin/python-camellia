Changelog of python-camellia
============================

1.1.0 - TBD
------------

New
***

- Add `PEP-484`_ type hints

Changed
*******

- Adapt `Semantic Versioning`_
- The C extension is directly build using setuptools, this allows ABI3 wheels for multiple Python versions
- Documentation is at Readthedocs

.. _`Semantic Versioning`: https://semver.org/spec/v2.0.0.html
.. _PEP-484: https://www.python.org/dev/peps/pep-0484/

1.0 - 2018-05-11
----------------

New
***

Changed
*******

-  The "normal" camellia version is used instead of the mini or reference version.
-  Camellia is now loaded using CFFI. This improves speed and avoids shipped DLLs.
   It's better than the self-made-on-first-use compilation, faster and less error-prone.
-  Supports all standart modes of operation (ECB, CBC, CFB, OFB, CTR)
-  Electronic code book mode of operation is not implicit default anymore.
-  Now camellia.Camellia_Ekeygen returns a list instead of an CFFI array.

0.1.1 - 2015-09-05
------------------

New
***

- More metadata on PyPi

Changed
*******

0.1 - 2015-08-30
----------------

- Initial release
