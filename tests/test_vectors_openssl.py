#!/usr/local/bin/env python3
"""Test python-camellia against test vectors from OpenSSL.

As vectors are read from are read from a file
(test_vectors_openssl.txt) this is required to be in
the same folder.

This script defines tests in the pytest format.
It may be run standalone or by a testrunner (nose, pytest).
"""


import binascii
import collections
import os

import camellia

VECTOR_FILENAME = os.path.join(
    os.path.dirname(__file__),
    "test_vectors_openssl.txt")

ACTION_DECRYPT = 0
ACTION_ENCRYPT = 1
ACTION_BOTH = 2

MODES = {
    "ECB": camellia.MODE_ECB,
    "CBC": camellia.MODE_CBC,
    "CFB": camellia.MODE_CFB,
    "OFB": camellia.MODE_OFB
}

TestvectorOpenSSL = collections.namedtuple(
    "TestvectorOpenSSL",
    ["mode", "key", "iv", "plain", "cipher", "encdec"])


def _get_vectors_openssl(
        filename=VECTOR_FILENAME,
        algo="camellia",
        mode="ECB"):

    data = []
    with open(filename) as vectors:
        for line in vectors:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                desc, key, iv, plain, cipher = line.split(":")
                encdec = ACTION_BOTH
            except ValueError:
                (desc, key, iv,
                 plain, cipher, encdec) = line.split(":")
                encdec = int(encdec)

            if not (algo.upper() in desc and
                    mode.upper() in desc):
                continue

            data.append(
                TestvectorOpenSSL(
                    mode,
                    key,
                    iv,
                    plain,
                    cipher,
                    encdec))

    return data


def _do_tests(mode):
    vectors = _get_vectors_openssl(mode=mode)
    for vector in vectors:
        key, iv, plain_text, cipher_text = map(
            binascii.unhexlify, (
                vector.key, vector.iv or b'00'*16,
                vector.plain, vector.cipher))

        if mode == "ECB":
            iv = None

        cipher_kwargs = dict(key=key, mode=MODES[mode])
        if mode != "ECB":
            cipher_kwargs["IV"] = iv
        if mode == "CFB":
            cipher_kwargs["segment_size"] = 128

        if vector.encdec in (ACTION_ENCRYPT, ACTION_BOTH):
            cipher = camellia.new(**cipher_kwargs)
            try:
                assert cipher.encrypt(plain_text) == cipher_text
            except AssertionError:
                print("Key:\t\t\t", vector.key)
                if mode != "ECB":
                    print("Initialization vector:\t", vector.iv)
                print()
                print("Plaintext:\t\t", vector.plain)
                print("Ciphertext (result):\t",
                      binascii.hexlify(
                        cipher.encrypt(plain_text)).decode())
                print("Ciphertext (expected):\t", vector.cipher)
                raise

        if vector.encdec in (ACTION_DECRYPT, ACTION_BOTH):
            cipher = camellia.new(**cipher_kwargs)
            try:
                assert cipher.decrypt(cipher_text) == plain_text
            except AssertionError:
                print("Key:\t\t\t", vector.key)
                if mode != "ECB":
                    print("Initialization vector:\t", vector.iv)
                print()
                print("Ciphertext:\t\t", vector.cipher)
                print("Plaintext (result):\t",
                      binascii.hexlify(
                        cipher.decrypt(cipher_text)).decode())
                print("Plaintext (expected):\t", vector.plain)
                raise


def test_ecb():
    """Test python-camellia's ECB mode against OpenSSL tests."""
    _do_tests("ECB")


def test_cbc():
    """Test python-camellia's CBC mode against OpenSSL tests."""
    _do_tests("CBC")


def test_cfb():
    """Test python-camellia's CFB mode against OpenSSL tests."""
    _do_tests("CFB")


def test_ofb():
    """Test python-camellia's OFB mode against OpenSSL tests."""
    _do_tests("OFB")


if __name__ == '__main__':
    import __main__
    for name in dir(__main__):
        if name.startswith("test_") and callable(eval(name)):
            print(name, end=': ')
            try:
                eval(name)()
            except AssertionError:
                print("failed")
                raise
            print("ok")
