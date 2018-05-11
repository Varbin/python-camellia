.. python-camellia documentation master file, created by
   sphinx-quickstart on Sun Oct 30 00:20:11 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to python-camellia's documentation!
===========================================

This is the documentation of python-camellia, 
a cryptographic library implementing the
`Camellia <https://tools.ietf.org/html/rfc3713>`_ cipher in python.

.. code:: python

   >>> import camellia
   >>> plain = b"This is a text. "
   >>> c1 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. xxxx', mode=camellia.MODE_CBC)
   >>> encrypted = c1.encrypt(plain)
   >>> c2 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. xxxx', mode=camellia.MODE_CBC)
   >>> c2.decrypt(encrypted)
   b'This is a text. '


.. toctree::
   :maxdepth: 2

   install
   license
   API


