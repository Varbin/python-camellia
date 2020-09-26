from typing import ByteString, List, NoReturn, Optional, Union

from pep272_encryption import PEP272Cipher

MODE_ECB: int
MODE_CBC: int
MODE_CFB: int
MODE_PGP: int
MODE_OFB: int
MODE_CTR: int


def Camellia_Ekeygen(rawKey: ByteString) -> List[int]:
    ...


def Camellia_Encrypt(keyLength: int, keytable: List[int],
                     plainText: ByteString) -> bytes:
    ...


def Camellia_Decrypt(keyLength: int, keytable: List[int],
                     plainText: ByteString) -> bytes:
    ...


def new(key: ByteString, mode: int, IV: Optional[ByteString]=None, **kwargs) \
        -> CamelliaCipher:
    ...


class CamelliaCipher(PEP272Cipher):
    key_length: int

    def __init__(self, key: ByteString, mode: int, **kwargs):
        PEP272Cipher.__init__(self, ..., mode, **kwargs)

    def encrypt_block(self, key, block: ByteString, **kwargs) -> ByteString:
        ...

    def decrypt_block(self, key, block: ByteString, **kwargs) -> ByteString:
        ...


def self_test() -> Union[None, NoReturn]:
    ...