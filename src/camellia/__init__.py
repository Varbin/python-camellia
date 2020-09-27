#!/usr/bin/env python3
r"""Camellia implementation for Python.

Example:

    >>> import camellia
    >>> cipher = camellia.new(b'\x80'+b'\x00'*15, mode=camellia.MODE_ECB)
    >>> cipher.encrypt(b'\x00'*16)
    b'l"\x7ft\x93\x19\xa3\xaa}\xa25\xa9\xbb\xa0Z,'

"""
import sys

from binascii import unhexlify

from pep272_encryption import PEP272Cipher

from ._camellia import lib, ffi  # pylint: disable=import-error

# pylint: disable=invalid-name


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
    def b(_b):
        """Create bytes from a list of ints."""
        return "".join(map(chr, _b))


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


def _check_keylength(length):
    if length not in [128, 192, 256]:
        raise ValueError(
            "Invalid key length, " "it must be 128, 192 or 256 bits long!"
        )


def Camellia_Ekeygen(rawKey):
    """
    Make a keytable from a key.

    :param rawKey: raw encryption key, 128, 192 or 256 bits long
    :type rawKey: bytes

    :returns: keytable
    """
    key_length = len(rawKey) * 8

    _check_keylength(key_length)

    raw_key = ffi.new("const unsigned char []", rawKey)
    keytable = ffi.new("KEY_TABLE_TYPE")

    lib.Camellia_Ekeygen(key_length, raw_key, keytable)

    return list(keytable)


def Camellia_Encrypt(keyLength, keytable, plainText):
    r"""Encrypt a plaintext block by given arguments.

    :param keyLength: key length (128, 192 or 256 bits
    :type rawKey: int

    :param keytable: keytable returned by Camellia_Ekeygen
    :type keytable: list

    :param plainText: one plaintext block to encrypt (16 bytes in length)
    :type plainText: bytes

    :returns: ciphertext block
    """
    _check_keylength(keyLength)

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
    _check_keylength(keyLength)

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
        _check_keylength(self.key_length)

        iv = kwargs.get('IV', kwargs.get('iv'))
        if iv is not None:
            # Force copy, IV may be interned or used elsewhere
            self._status_buffer = \
                ffi.new("unsigned char [CAMELLIA_BLOCK_SIZE]",
                        iv)

        PEP272Cipher.__init__(self, keytable, mode, **kwargs)

    def encrypt(self, string):
        """Encrypt data with the key and the parameters set at initialization.

        The cipher object is stateful; encryption of a long block
        of data can be broken up in two or more calls to `encrypt()`.
        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is always equivalent to:

             >>> c.encrypt(a+b)

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not perform any padding.

         - For `MODE_ECB`, `MODE_CBC` *string* length
           (in bytes) must be a multiple of *block_size*.

         - For `MODE_CFB`, *string* length (in bytes) must be a multiple
           of *segment_size*/8.

         - For `MODE_CTR` and `MODE_OFB`, *string* can be of any length.

        :param bytes string: The piece of data to encrypt.
        :raises ValueError:
            When a mode of operation has be requested this code cannot handle.
        :raises ValueError:
            When len(string) has a wrong length, as described above.
        :raises TypeError:
            When the counter callable in CTR returns data with the wrong
            length.

        :return:
            The encrypted data, as a byte string. It is as long as
            *string*.
        :rtype: bytes
        """

        if self.mode == MODE_ECB or self.mode == MODE_CBC:
            if len(string) % self.block_size:
                raise ValueError("Input must be a multiple of 16 in length")

        if self.mode == MODE_ECB:
            cipher_text = b"\x00"*len(string)
            lib.Camellia_EncryptEcb(
                self.key_length,
                string,
                self.key,
                cipher_text,
                len(string) // 16
            )
            return bytes(cipher_text)

        if self.mode == MODE_CBC:
            cipher_text = b"\x00"*len(string)

            lib.Camellia_EncryptCbc(
                self.key_length,
                string,
                self.key,
                cipher_text,
                len(string) // 16,
                self._status_buffer
            )
            return cipher_text

        return super(CamelliaCipher, self).encrypt(string)

    def decrypt(self, string):
        """Decrypt data with the key and the parameters set at initialization.

        The cipher object is stateful; decryption of a long block
        of data can be broken up in two or more calls to `decrypt()`.
        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is always equivalent to:

             >>> c.decrypt(a+b)

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not perform any padding.

         - For `MODE_ECB`, `MODE_CBC` *string* length
           (in bytes) must be a multiple of *block_size*.

         - For `MODE_CFB`, *string* length (in bytes) must be a multiple
           of *segment_size*/8.

         - For `MODE_CTR` and `MODE_OFB`, *string* can be of any length.

        :param bytes string: The piece of data to decrypt.
        :raises ValueError:
            When a mode of operation has be requested this code cannot handle.
        :raises ValueError:
            When len(string) has a wrong length, as described above.
        :raises TypeError:
            When the counter in CTR returns data of the wrong length.

        :return:
            The decrypted data, as a byte string. It is as long as
            *string*.
        :rtype: bytes
        """
        if self.mode == MODE_ECB or self.mode == MODE_CBC:
            if len(string) % self.block_size:
                raise ValueError("Input must be a multiple of 16 in length")

        if self.mode == MODE_ECB:
            plain_text = b"\x00"*len(string)
            lib.Camellia_DecryptEcb(
                self.key_length,
                string,
                self.key,
                plain_text,
                len(string) // 16
            )
            return plain_text

        if self.mode == MODE_CBC:
            print(self._status)
            plain_text = b"\x00"*len(string)

            lib.Camellia_DecryptCbc(
                self.key_length,
                string,
                self.key,
                plain_text,
                len(string) // 16,
                self._status_buffer
            )
            return plain_text

        return super(CamelliaCipher, self).encrypt(string)

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
