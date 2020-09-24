API
===

.. warning::
   The documentations assumes you know the risks of using cryptography.
   This library is low level with all benefits and dangers.

   Here be dragons!


The *new* constructor
---------------------

.. autofunction:: camellia.new

Modes of operation
------------------

.. autodata:: camellia.MODE_ECB
.. autodata:: camellia.MODE_CBC
.. autodata:: camellia.MODE_CFB
.. autodata:: camellia.MODE_OFB
.. autodata:: camellia.MODE_CTR

The *CamelliaCipher* class
--------------------------

.. autoclass:: camellia.CamelliaCipher
    :members:
    
    .. automethod:: camellia.CamelliaCipher.encrypt
    .. automethod:: camellia.CamelliaCipher.decrypt
    
Low-level camellia functions
----------------------------

.. autofunction:: camellia.Camellia_Ekeygen
.. autofunction:: camellia.Camellia_Encrypt
.. autofunction:: camellia.Camellia_Decrypt
