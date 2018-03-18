#!/usr/bin/env python3

try:
    from ._camellia import lib, ffi
except (SystemError, ValueError):  # local tests
    from _camellia import lib, ffi

import sys

from pep272_encryption import PEP272Cipher

#: ECB mode of operation
MODE_ECB = 1
#: CBC mode of operation
MODE_CBC = 2
#: CFB mode of operation, currently not supported
MODE_CFB = 3
#: OFB mode of operation, currently not supported
MODE_OFB = 5
#: CTR mode of operation
MODE_CTR = 6

#: All currently supported blockcipher modes of operation
SUPPORTED_MODES = [MODE_ECB, MODE_CBC, MODE_CTR]

if sys.version_info.major <= 2:
    b = lambda b: "".join(map(chr, b))
else:
    b = bytes

def Camellia_Ekeygen(rawKey):
    """
    Make a keytable from a key.

    :param rawKey: raw encryption key, 16, 24 or 32 bytes long
    :type rawKey: bytestring
    
    :returns: `CFFI <https://cffi.readthedocs.io/en/latest/>`_ array
    """
    keyLength = len(rawKey)*8

    if keyLength not in [128, 192, 256]:
        raise ValueError("Invalid key length, "
                         "it must be 16, 24 or 32 bytes long!")

    raw_key = ffi.new("const unsigned char []", rawKey)
    keytable = ffi.new("KEY_TABLE_TYPE")

    lib.Camellia_Ekeygen(keyLength, raw_key, keytable)

    return keytable

def Camellia_Encrypt(keyLength, keytable, plainText):
    if keyLength not in [128, 192, 256]:
        raise ValueError("Invalid key length, "
                         "it must be 16, 24 or 32 bytes long!")

    if len(plainText) != 16:
        raise ValueError("Plain text length must be 16!")

    inp = ffi.new("const unsigned char []", plainText)
    out = ffi.new("unsigned char []", b"\00"*16)

    lib.Camellia_EncryptBlock(keyLength, inp, keytable, out)

    return b(out)[:-1]
    

def Camellia_Decrypt(keyLength, keytable, cipherText):
    if keyLength not in [128, 192, 256]:
        raise ValueError("Invalid key length, "
                         "it must be 16, 24 or 32 bytes long!")

    if len(cipherText) != 16:
        raise ValueError("Cipher text length must be 16!")

    inp = ffi.new("const unsigned char []", cipherText)
    out = ffi.new("unsigned char []", b"\00"*16)

    lib.Camellia_DecryptBlock(keyLength, inp, keytable, out)

    return b(out)[:-1]


def new(key, mode=MODE_ECB, **kwargs):
    """Create an "CamelliaCipher" object.
    The default mode is ECB.
    
    :param key: The key for encrytion/decryption. Must be 16/24/32 in length.
    :type key: bytestring

    :param mode: Mode of operation, only ECB (0) and CBC (1) are supported.
    :type mode: int, on of MODE_* constants

    :param IV: Initialisation vector for CBC/CFB/OFB, must be 16 in length.
    :type IV: bytestring

    :param counter: Counter for CTR.
    :type counter: callable, must return bytestrings 16 in length

    :returns: CamelliaCipher
    :raises: ValueError, NotImplementedError
    """
    return CamelliaCipher(key, mode, **kwargs)

key_size = None
block_size = 16

class CamelliaCipher(PEP272Cipher):
    """
    The CamelliaCipher object.
    """

    #: block size of the camellia cipher
    block_size = 16 

    def __init__(self, key, mode, **kwargs):
        """
        Constructer of Cipher class. See :func:`camellia.new`.
        """

        keytable = Camellia_Ekeygen(key)
        self.key_length = len(key)*8
            

        PEP272Cipher.__init__(self, keytable, mode, **kwargs)

    def encrypt_block(self, key, block, **kwargs):
        return Camellia_Encrypt(self.key_length, key, block)

    def decrypt_block(self, key, block, **kwargs):
        return Camellia_Decrypt(self.key_length, key, block)



CamelliaCipher.encrypt.__doc__ = """\
Encrypt string.

:param string:
    The data to encrypt.
    For the most modes of operation it must be a multiple
    of 16 in length.
:type string: bytestring
"""


CamelliaCipher.decrypt.__doc__ = """\
Decrypt string.

:param string:
    The data to decrypt.
    For the most modes of operation it must be a multiple
    of 16 in length.
:type string: bytestring
"""


def test(v=True):
    key = b"80000000000000000000000000000000"
    plain = b"00000000000000000000000000000000"
    cipher = b"6C227F749319A3AA7DA235A9BBA05A2C"

    import binascii

    c = CamelliaCipher(binascii.unhexlify(key), mode=MODE_ECB)

    ec = c.encrypt(binascii.unhexlify(plain))
    
    if not ec == binascii.unhexlify(cipher):
        if v:
            print("Result:\t\tcipher=%s" % binascii.hexlify(ec).decode())
            print("Required:\tcipher=%s" % cipher.decode())
            return "failed"
        else:
            raise

    dc = c.decrypt(ec)

    if not dc == binascii.unhexlify(plain):
        if v:
            print("Result:\t\tcipher=%s" % binascii.hexlify(dc).decode())
            print("Required:\tcipher=%s" % plain.decode())
            return "failed"
        else:
            raise

    return "passed"

if __name__ == "__main__":
    print("Test: "+test())
