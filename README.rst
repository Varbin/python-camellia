`Documentation`_ | `Source`_ | `Issue tracker`_

.. image:: https://github.com/varbin/python-camellia/workflows/QA/badge.svg
   :target: https://github.com/varbin/python-camellia/actions
   :alt: Github Actions: QA

.. image:: https://api.codeclimate.com/v1/badges/2cbeaf92fc287e038c13/maintainability
   :target: https://codeclimate.com/github/Varbin/python-camellia/maintainability
   :alt: Maintainability

.. image:: https://api.codeclimate.com/v1/badges/2cbeaf92fc287e038c13/test_coverage
   :target: https://codeclimate.com/github/Varbin/python-camellia/test_coverage
   :alt: Test Coverage

.. image:: https://readthedocs.org/projects/python-camellia/badge/?version=latest
   :target: https://python-camellia.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. _Documentation: https://python-camellia.readthedocs.io
.. _Source: https://github.com/Varbin/python-camellia
.. _Issue tracker: https://github.com/Varbin/python-camellia/issues

.. code:: python

   >>> import camellia
   >>> plain = b"This is a text. "
   >>> c1 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
   >>> encrypted = c1.encrypt(plain)
   >>> c2 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
   >>> c2.decrypt(encrypted)
   b'This is a text. '


Because it's build direct on top of the reference implementation, the python-camellia library provides direct 
access to extreme low-level functions like *Camellia-Ekeygen* but also provides a nearly PEP-272-compliant 
cryptographic interface. This semi low-level interface supports encryption (and decryption) in ECB, 
CBC, CFB, OFB and CTR modes of operation.

See the `installation instructions`_ for details regarding installation.

.. _`installation instructions`: https://python-camellia.readthedocs.io/en/latest/1_install.html

This software contains encryption algorithms, thus it may be restricted by law in some countries.


