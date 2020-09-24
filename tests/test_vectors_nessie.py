#!/usr/local/bin/env python3
"""Test python-camellia against test vectors from NESSIE.

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

VECTOR_FILENAME = os.path.join(os.path.dirname(__file__),
                               "test_vectors_nessie.txt")

_TestvectorNessie = collections.namedtuple(
    "TestvectorNessie",
    ["name", "key", "plain", "cipher", "decrypted", "i100", "i1000"])


def _get_test_vectors_nessie(filename=VECTOR_FILENAME):
    vectors = {}
    with open(VECTOR_FILENAME) as vector_file:
        for line in vector_file:
            line = line.strip()
            if "Set " in line:
                name = line[:-1]  # colone at lineend
            if "key=" in line:
                _, key = line.split("=")
            if "plain=" in line:
                _, plain = line.split("=")
            if "cipher=" in line:
                _, cipher = line.split("=")
            if "decrypted=" in line:
                _, decrypted = line.split("=")
            if "Iterated 100 times=" in line:
                _, i100 = line.split("=")
            if "Iterated 1000 times=" in line:
                _, i1000 = line.split("=")
                vectors[name] = _TestvectorNessie(
                    name, key, plain, cipher, decrypted, i100, i1000)

    return vectors


@pytest.mark.parametrize("name, vector", _get_test_vectors_nessie().items())
def test_vectors_nessie(name, vector):
    (key, plain, cipher, decrypted, i100, i1000) = map(
        binascii.unhexlify, vector[1:])

    cam = camellia.new(key, camellia.MODE_ECB)

    cipher_result = cam.encrypt(plain)
    decrypted_result = cam.decrypt(cipher)

    i100_result = plain
    for i in range(100):
        i100_result = cam.encrypt(i100_result)

    i1000_result = plain
    for i in range(1000):
        i1000_result = cam.encrypt(i1000_result)

    assert cipher == cipher_result
    assert decrypted == decrypted_result
    assert i100 == i100_result
    assert i1000 == i1000_result
