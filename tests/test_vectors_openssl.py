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
import pytest

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

_TestvectorOpenSSL = collections.namedtuple(
    "TestvectorOpenSSL",
    ["mode", "key", "iv", "plain", "cipher", "encdec"])


def _get_vectors_openssl(
        filename=VECTOR_FILENAME,
        algo="camellia",
        mode="ECB"):

    parsed_vectors = {}
    lineno = 0
    with open(filename) as vectors:
        for line in vectors:
            line = line.strip()
            lineno += 1

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

            parsed_vectors[lineno] = _TestvectorOpenSSL(
                mode,
                key,
                iv,
                plain,
                cipher,
                encdec)

    return parsed_vectors


@pytest.mark.parametrize("lineno, vector", _get_vectors_openssl().items())
def test_vectors_openssl(lineno, vector):
    mode = vector.mode
    key, iv, plain_text, cipher_text = map(
        binascii.unhexlify, (
            vector.key, vector.iv or b'00' * 16,
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

        assert cipher.encrypt(plain_text) == cipher_text

    if vector.encdec in (ACTION_DECRYPT, ACTION_BOTH):
        cipher = camellia.new(**cipher_kwargs)

        assert cipher.decrypt(cipher_text) == plain_text
