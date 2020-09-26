#!/usr/bin/env python3
r"""Camellia implementation for Python.

Example:

    >>> import camellia
    >>> cipher = camellia.new(b'\x80'+b'\x00'*15, mode=camellia.MODE_ECB)
    >>> cipher.encrypt(b'\x00'*16)
    b'l"\x7ft\x93\x19\xa3\xaa}\xa25\xa9\xbb\xa0Z,'

"""

from ._camellia import lib, ffi

from binascii import unhexlify

import sys

from pep272_encryption import PEP272Cipher

#: ECB mode of operation
MODE_ECB = 1
#: CBC mode of operation
MODE_CBC = 2
#: CFB mode of operation
MODE_CFB = 3
#: OFB mode of operation
MODE_OFB = 5
#: CTR mode of operation
MODE_CTR = 6


if sys.version_info.major <= 2:

    def b(b):
        """Create bytes from a list of ints."""
        return "".join(map(chr, b))


else:
    b = bytes


_selftest_vectors = (
    (
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
    ),
    (
        "0123456789abcdeffedcba98765432100011223344556677",
        "0123456789abcdeffedcba9876543210",
        "b4993401b3e996f84ee5cee7d79b09b9",
    ),
    (
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0123456789abcdeffedcba9876543210",
        "9acc237dff16d76c20ef7c919e3a7509",
    ),
)


def Camellia_Ekeygen(rawKey):
    """
    Make a keytable from a key.

    :param rawKey: raw encryption key, 128, 192 or 256 bits long
    :type rawKey: bytes

    :returns: keytable
    """
    keyLength = len(rawKey) * 8

    if keyLength not in [128, 192, 256]:
        raise ValueError(
            "Invalid key length, " "it must be 128, 192 or 256 bits long!"
        )

    raw_key = ffi.new("const unsigned char []", rawKey)
    keytable = ffi.new("KEY_TABLE_TYPE")

    lib.Camellia_Ekeygen(keyLength, raw_key, keytable)

    return list(keytable)


def Camellia_Encrypt(keyLength, keytable, plainText):
    r"""Encrypt a plaintext block by given arguments.

    :param keyLength: key length (128, 192 or 256 bits)
    :type rawKey: int

    :param keytable: keytable returned by Camellia_Ekeygen
    :type keytable: list

    :param plainText: one plaintext block to encrypt (16 bytes in length)
    :type plainText: bytes

    :returns: ciphertext block
    """
    if keyLength not in [128, 192, 256]:
        raise ValueError(
            "Invalid key length, " "it must be 128, 192 or 256 bits long!"
        )

    if len(plainText) != 16:
        raise ValueError("Plain text length must be 16!")

    inp = ffi.new("const unsigned char []", plainText)
    out = ffi.new("unsigned char []", b"\00" * 16)

    lib.Camellia_EncryptBlock(keyLength, inp, keytable, out)

    return b(out)[:-1]


def Camellia_Decrypt(keyLength, keytable, cipherText):
    r"""Decrypt a plaintext block by given arguments.

    :param keyLength: key length (128, 192 or 256 bits)
    :type rawKey: int

    :param keytable: keytable returned by Camellia_Ekeygen
    :type keytable: list

    :param cipherText: one cipher block to decrypt (16 bytes in length)
    :type cipherText: bytes

    :returns: plaintext block
    """
    if keyLength not in [128, 192, 256]:
        raise ValueError(
            "Invalid key length, " "it must be 128, 192 or 256 bits long!"
        )

    if len(cipherText) != 16:
        raise ValueError("Cipher text length must be 16!")

    inp = ffi.new("const unsigned char []", cipherText)
    out = ffi.new("unsigned char []", b"\00" * 16)

    lib.Camellia_DecryptBlock(keyLength, inp, keytable, out)

    return b(out)[:-1]


def new(key, mode, IV=None, **kwargs):
    """Create an "CamelliaCipher" object.

    :param key: The key for encrytion/decryption. Must be 16/24/32 in length.
    :type key: bytes

    :param mode: Mode of operation.
    :type mode: int, one of MODE_* constants

    :param IV: Initialization vector for CBC/CFB/OFB blockcipher modes of
        operation, must be 16 bytes in length.
    :type IV: bytes

    :param counter: Counter for CTR blockcipher mode of operation.
        Each call must return 16 bytes.
    :type counter: callable

    :returns: CamelliaCipher
    :raises: ValueError, NotImplementedError
    """
    return CamelliaCipher(key, mode, IV=IV, **kwargs)


key_size = None
block_size = 16


class CamelliaCipher(PEP272Cipher):
    """The CamelliaCipher object."""

    #: block size of the camellia cipher
    block_size = 16

    def __init__(self, key, mode, **kwargs):
        """Constructer of Cipher class. See :func:`camellia.new`."""
        keytable = Camellia_Ekeygen(key)
        self.key_length = len(key) * 8

        PEP272Cipher.__init__(self, keytable, mode, **kwargs)

    def encrypt_block(self, key, block, **kwargs):
        """Encrypt a single block with camellia."""
        return Camellia_Encrypt(self.key_length, key, block)

    def decrypt_block(self, key, block, **kwargs):
        """Decrypt a single block with camellia."""
        return Camellia_Decrypt(self.key_length, key, block)


def self_test():
    """
    Run self-test.

    :raises RuntimeError:
    """
    for key, plain_hex, cipher_hex in _selftest_vectors:
        cam = new(unhexlify(key), MODE_ECB)
        plain, cipher = unhexlify(plain_hex), unhexlify(cipher_hex)
        if cam.encrypt(plain) != cipher or cam.decrypt(cipher) != plain:
            raise RuntimeError("Self-test of camellia failed")


self_test()
