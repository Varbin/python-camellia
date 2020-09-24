Examples
========


Authenticated encryption with password
--------------------------------------

Below is the source for a command line tool that can be used to encrypt and decrypt files with a password.
It derives key from a user supplied password, uses Camellia with a 256-bit key in CBC mode
and uses HMAC-SHA512 to authenticate the cipher text. The example is written for Python 3.5 or newer.

.. literalinclude:: _static/authenticated.py
   :linenos:

