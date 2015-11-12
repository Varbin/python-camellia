
from ctypes import CDLL, create_string_buffer

class Engine:
    def __init__(self, cdll):
        self.lib = cdll

    def Camellia_Ekeygen(self, rawKey):
        assert (len(rawKey) * 8) in [128, 192, 256]

        keytable = create_string_buffer(272)  # create buffer to write in
        self.lib.Camellia_Ekeygen(len(rawKey)*8, rawKey, keytable)

        return keytable.raw  # return as bytes

    def Camellia_Encrypt(self, keyLength, keytable, plainText):
        assert keyLength in [128, 192, 256]
        assert len(plainText) == 16

        cipher = create_string_buffer(16)
        self.lib.Camellia_Encrypt(keyLength, plainText, keytable, cipher)

        return cipher.raw

    def Camellia_Decrypt(self, keyLength, keytable, cipherText):
        assert keyLength in [128, 192, 256]
        assert len(cipherText) == 16

        clear = create_string_buffer(16)
        self.lib.Camellia_Decrypt(keyLength, cipherText, keytable, clear)

        return clear.raw
