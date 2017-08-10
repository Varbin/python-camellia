#!/usr/bin/env python3

try:
    from ._camellia import lib, ffi
except (SystemError, ValueError):  # local tests
    from _camellia import lib, ffi

import sys

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
    It's not fully PEP-272 comliant (yet).
    The default mode is ECB.
    
    :param key: The key for encrytion/decryption. Must be 16/24/32 in length.
    :type key: bytestring

    :param mode: Mode of operation, only ECB (0) and CBC (1) are supported.
    :type mode: int, on of MODE_* constants

    :param IV: Initialisation vector for CBC/CFB/OFB, must be 16 in length.
    :type IV: bytestring

    :param counter: Counter for CTR.
    :type counter: callable, must return bytestrings

    :returns: CamelliaCipher
    :raises: ValueError, NotImplementedError
    """
    return CamelliaCipher(key, mode=mode, **kwargs)

key_size = None
block_size = 16

class CamelliaCipher(object):
    """
    The CamelliaCipher object.
    """

    #: block size of the camellia cipher
    block_size = 16 

    def __init__(self, key, **kwargs):
        """
        Constructer of Cipher class. See :func:`camellia.new`.

        *mode* and *IV* must be passed as keyword arguments.
        """
        self.__key_length = len(key) * 8
        self.__key = Camellia_Ekeygen(key)

        if len(key) not in (16,24,32):
            raise ValueError("Key must be 128, 192 or 256 bits long")

        keys = kwargs.keys()
        if "mode" in keys:
            self.mode = kwargs["mode"]
            if self.mode not in SUPPORTED_MODES:
                raise NotImplementedError("This mode is not supported!")
        else:
            self.mode = MODE_ECB

        if "IV" in keys:
            self.IV = kwargs["IV"]
            if len(self.IV) != self.block_size/8:
                raise ValueError("IV must be 16 bytes long")

            # self.IV = IV  # self.IV can be changed, but has no effect!

        if "counter" in keys:
            self.counter = kwargs["counter"]
        elif self.mode == MODE_CTR:
            raise ValueError("CTR needs a counter!")

    def encrypt(self, data):
        """
        Encrypt data.

        :param data:
            The data to encrypt.
            For the most modes of operation is must be a multiple
            of 16 in length.
        :type data: bytestring

        """
        blocks = self._block(data)

        if self.mode == MODE_ECB:
            if len(data) % (self.block_size/8):
                raise ValueError("Input string must be a multiple "
                                 "of blocksize in length")

            out = []
            for block in blocks:
                out.append(Camellia_Encrypt(self.__key_length, self.__key,
                                            block))

            return b''.join(out)

        elif self.mode == MODE_CBC:
            if len(data) % (self.block_size/8):
                raise ValueError("Input string must be a multiple "
                                 "of blocksize in length")

            out = []
            for block in blocks:
                xored = xor(block, self.IV)
                self.IV = (Camellia_Encrypt(self.__key_length, self.__key,
                                              xored))

                out.append(self.IV)

            return b''.join(out)

        elif self.mode == MODE_CTR:
            out = []

            for block in blocks:
                ctr = self.counter()
                if len(ctr) != self.blocksize:
                    raise ValueError("The counter function must return "
                                     "a bytestring of blocksize in length")

                encrypted_counter = Camellia_Encrypt(self.__key_length,
                                                     self.__key,
                                                     self.counter())
                encrypted_block = xor(block, encrypted_counter)
                out.append(encrypted_block)

            return b''.join(out)

        else:
            raise Exception("???")

    def decrypt(self, data):
        """
        Decrypt data.

        :param data:
            The data to decrypt.
            For the most modes of operation is must be a multiple
            of 16 in length.
        :type data: bytestring

        """
        blocks = self._block(data)

        if self.mode == MODE_ECB:
            if len(data) % (self.block_size/8):
                raise ValueError("Input string must be a multiple "
                                 "of blocksize in length")

            out = []
            for block in blocks:
                out.append(Camellia_Decrypt(self.__key_length, self.__key,
                                            block))

            return b''.join(out)

        elif self.mode == MODE_CBC:
            if len(data) % (self.block_size/8):
                raise ValueError("Input string must be a multiple "
                                 "of blocksize in length")

            out = []
            blocks = [self.IV] + blocks
            for i in range(1, len(blocks)):
                temp = Camellia_Decrypt(self.__key_length, self.__key,
                                        blocks[i])
                out.append(xor(temp, blocks[i-1]))

            self.IV = blocks[-1]

            return b''.join(out)

        elif self.mode == MODE_CTR:
            return self.encrypt(data)

        else:
            raise Exception("???")

    def _block(self, s):
        l = []
        rest_size = int(len(s) % (self.block_size))
        for i in range(int(len(s)/(self.block_size))):
            l.append(s[i*(self.block_size):((i+1)*(self.block_size))])
        if rest_size:
            # raise ValueError()
            l.append(s[-rest_size:])
        return l

if int(sys.version[0]) < 3:
    def xor(a, b):
        return "".join([chr(ord(c) ^ ord(d)) for c, d in zip(a, b)])
else:
    def xor(a, b):
        return bytes([c ^ d for c, d in zip(a, b)])


def test(v=True):
    key = b"80000000000000000000000000000000"
    plain = b"00000000000000000000000000000000"
    cipher = b"6C227F749319A3AA7DA235A9BBA05A2C"

    import binascii

    c = CamelliaCipher(binascii.unhexlify(key))

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
