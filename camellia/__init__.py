#!/usr/bin/python3

from ctypes import create_string_buffer, CDLL
import os
import sys
import platform

from .engines import reference as c_reference
from .engines import mini as c_mini

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6


d = dict(
    linux='.so',
    freebsd='.so',
    openbsd='.so',
    netbsd='.so',
    unix='.so',  # ???
    darwin='.so',
    win32='.dll',
    cygwin='.dll',
)

d['Pocket PC'] = '.dll'

try:
    __file__
except NameError:
    __file__ == "."


class camelliaException(Exception):
    pass

__version__ = "0.2"


def version_string():
    plat = sys.platform.replace('linux2', 'linux').replace('linux3', 'linux')

    base = "camellia-{}-{}-{}"+d.get(plat, '.shared')

    proc = platform.machine() if platform.machine else "unknown"
    arch = platform.architecture()[1]

    return base.format(__version__, plat, proc)


ADD = "./" if not os.path.dirname(__file__) else ""

IN = os.path.join(os.path.dirname(__file__), "camellia.c")
OUT = os.path.join(os.path.dirname(__file__), version_string())

ucc = os.environ.get('CC', 'cc')

acc = ["cc", "gcc", "clang", "tcc"]

if ucc in acc:
    i = acc.index(ucc)
    acc.pop(i)
else:
    acc = [UCC] + acc
#CMD = "%s %s -shared -fPIC -O3 -o%s" % (GCC, IN, OUT)

def try_compiler(cc, inf, outf):
    cmd = "%s %s -shared -fPIC -O3 -o%s" % (cc, inf, outf)
    print (cmd)
    try:
        assert not os.system(cmd)
    except:
        print("Compiler %s failed! Not existend or no permission?" % cc)
        return 1
    else:
        return 0

if not os.path.exists(OUT) and sys.platform != "win32":  # win32 is precompiled
    for cc in acc:
        print("Compiling camellia with %s..." % cc)
        if not try_compiler(cc, IN, OUT):
            break
        
    else:
        raise Exception("Please install gcc, clang or tcc and include "
                        "\"camellia.c\" with this file, then run with "
                        "sudo to compile!")
    print("Done!")


try:
    camlib = CDLL(ADD+OUT)
except:
    print("Please install gcc and include camellia.c with this file, "
          "then run with sudo to compile!")
    raise camelliaException(version_string()+" not found. Please install gcc "
                            "and include camellia.c with this file, then run "
                            "with sudo to compile!")


##def Camellia_Ekeygen(rawKey):
##    assert (len(rawKey) * 8) in [128, 192, 256]
##
##    keytable = create_string_buffer(272)  # create buffer to write in
##    camlib.Camellia_Ekeygen(len(rawKey)*8, rawKey, keytable)
##
##    return keytable.raw  # return as bytes
##
##
##def Camellia_Encrypt(keyLength, keytable, plainText):
##    assert keyLength in [128, 192, 256]
##    assert len(plainText) == 16
##
##    cipher = create_string_buffer(16)
##    camlib.Camellia_Encrypt(keyLength, plainText, keytable, cipher)
##
##    return cipher.raw
##
##
##def Camellia_Decrypt(keyLength, keytable, cipherText):
##    assert keyLength in [128, 192, 256]
##    assert len(cipherText) == 16
##
##    clear = create_string_buffer(16)
##    camlib.Camellia_Decrypt(keyLength, cipherText, keytable, clear)
##
##    return clear.raw


if sys.platform == "win32":
    crypto_engine = c_reference.Engine(camlib)
else:
    crypto_engine = c_mini.Engine(camlib)

Camellia_Ekeygen = crypto_engine.Camellia_Ekeygen
Camellia_Encrypt = crypto_engine.Camellia_Encrypt
Camellia_Decrypt = crypto_engine.Camellia_Decrypt

class CamelliaCipher(object):
    block_size = 16*8

    def __init__(self, key, **kwargs):
        self.__key_length = len(key) * 8
        self.__key = Camellia_Ekeygen(key)

        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 128, 192 or 256 bits long")

        keys = kwargs.keys()
        if "mode" in keys:
            self.mode = kwargs["mode"]
            if self.mode not in [MODE_ECB, MODE_CBC]:
                raise NotImplementedError("This mode is not supported!")
        else:
            self.mode = MODE_ECB

        if "IV" in keys:
            self.__IV = kwargs["IV"]
            if len(self.__IV) != self.block_size/8:
                raise ValueError("IV must be 16 bytes long")

        if "counter" in keys:
            self.__counter = kwargs["counter"]
        elif self.mode == MODE_CTR:
            raise ValueError("CTR needs a counter!")

    def encrypt(self, data):
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
                xored = xor(block, self.__IV)
                self.__IV = (Camellia_Encrypt(self.__key_length, self.__key,
                                              xored))

                out.append(self.__IV)

            return b''.join(out)

        else:
            raise Exception("???")

    def decrypt(self, data):
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
            blocks = [self.__IV] + blocks
            for i in range(1, len(blocks)):
                temp = Camellia_Decrypt(self.__key_length, self.__key,
                                        blocks[i])
                out.append(xor(temp, blocks[i-1]))

            self.__IV = blocks[-1]

            return b''.join(out)

        else:
            raise Exception("???")

    def _block(self, s):
        l = []
        rest_size = int(len(s) % (self.block_size/8))
        for i in range(int(len(s)/(self.block_size/8))):
            l.append(s[i*(self.block_size//8):((i+1)*(self.block_size//8))])
        if rest_size:
            # raise ValueError()
            l.append(s[-rest_size:])
        return l


def xor(a, b):
    if int(sys.version[0]) < 3:
        return "".join([chr(ord(c) ^ ord(d)) for c, d in zip(a, b)])
    return bytes([c ^ d for c, d in zip(a, b)])


def test(v=True):
    key = b"80000000000000000000000000000000"
    plain = b"00000000000000000000000000000000"
    cipher = b"6C227F749319A3AA7DA235A9BBA05A2C"

    import binascii

    c = CamelliaCipher(binascii.unhexlify(key))

    ec = c.encrypt(binascii.unhexlify(plain))
    try:
        assert ec == binascii.unhexlify(cipher)
    except AssertionError:
        if v:
            print("Result:\t\tcipher=%s" % binascii.hexlify(ec).decode())
            print("Required:\tcipher=%s" % cipher.decode())
            return "failed"
        else:
            raise

    dc = c.decrypt(ec)
    try:
        assert dc == binascii.unhexlify(plain)
    except AssertionError:
        if v:
            print("Result:\t\tcipher=%s" % binascii.hexlify(dc).decode())
            print("Required:\tcipher=%s" % plain.decode())
            return "failed"
        else:
            raise

    return "passed"

test(0)  # Selftest

if __name__ == "__main__":
    print("Test: "+test())
