===============
python-camellia
===============

This is a cryptographic library implementing the camellia cipher in python.

`API-reference`_

.. _API-reference: https://sbiewald.de/docs/python-camellia/

.. code:: python

   >>> import camellia
   >>> plain = b"This is a text. "
   >>> c1 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
   >>> encrypted = c1.encrypt(plain)
   >>> c2 = camellia.CamelliaCipher(key=b'16 byte long key', IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
   >>> c2.decrypt(encrypted)
   b'This is a text. '



Features
========

Because it's build direct on top of the reference implementation, the python-camellia library provides direct 
access to extreme low-level functions like *Camellia-Ekeygen* but also provides a nearly PEP-272-compliant 
cryptographic interface. This semi low-level interface supports encryption (and decryption) in ECB, 
CBC, CFB, OFB and CTR modes of operation.

Installation
============

Install with pip:

.. code:: shell

   $ pip install python-camellia



Licenses
========

.. code::

    Copyright (c) 2015 Simon Biewald

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.


This software uses the official camellia engine which is 2-clause-BSD licensed:

.. code::

     Copyright (c) 2006,2007
     NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
     
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer as
      the first lines of this file unmodified.
    2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Other things
============

This software contains encryption algorithms which is restricted by law in some countries. 


Changelog
=========

Version 1.0:
    -   The "normal" camellia version is used instead of the mini or reference version.
    -   Camellia is now loaded using CFFI. This improves speed and avoids shipped DLLs. It's better than the self-made-on-first-use compilation,
        which 
    -   Supports all standart modes of operation (ECB, CBC, CFB, OFB, CTR)
    -   Electronic code book mode of operation is not implicit default anymore.
    -   Now camellia.Camellia_Ekeygen returns a list instead of an CFFI array.
