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

VECTOR_FILENAME = os.path.join(os.path.dirname(__file__),
                               "test_vectors_nessie.txt")


TestvectorNessie = collections.namedtuple(
    "TestvectorNessie",
    ["name", "key", "plain", "cipher", "decrypted", "i100", "i1000"])


def _get_test_vectors_nessie(filename=VECTOR_FILENAME):
    vectors = []
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
                vectors.append(
                    TestvectorNessie(
                        name, key, plain, cipher, decrypted, i100,
                        i1000))
    return vectors


CODE_TEST = """\
def test_set{set}_vector{vector}():
    \"""Test python-camellia against Set \
{set}, vector# {vector} of NESSIE tests.

    This function is dynamically created - the vectors file
    is required to be in the same folder as the the script.\"""
    vector = {tuple}
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

    try:
        assert cipher == cipher_result
        assert decrypted == decrypted_result
        assert i100 == i100_result
        assert i1000 == i1000_result
    except AssertionError:
        print(vector.name, "failed")
        print()
        print("Key:")
        print(vector.key)
        print()

        print("Ciphertext (expected, result):")
        print(vector.cipher)
        print(binascii.hexlify(cipher_result).upper().decode())
        print()

        print("Decrypted ciphertext (expected, result):")
        print(vector.decrypted)
        print(binascii.hexlify(
            decrypted_result).upper().decode())
        print()

        print("Iterated 100 times (expected, result):")
        print(vector.i100)
        print(binascii.hexlify(
            i100_result).upper().decode())
        print()

        print("Ciphertext (expected, result):")
        print(vector.i1000)
        print(binascii.hexlify(
            i1000_result).upper().decode())
        print()

        raise"""

# Quick and dirty test generation for progress
# in test runners (nose, pytest), allows easier debugging

for vector in _get_test_vectors_nessie():
    split = vector.name.split(", ")
    set_n = split[0].split(" ")[-1]
    vector_n = split[-1].split("#")[-1].split(" ")[-1]

    code = CODE_TEST.format(
        set=set_n,
        vector=vector_n,
        tuple=repr(tuple(vector)))

    exec(code)


if __name__ == '__main__':
    import __main__
    for name in dir(__main__):
        if name.startswith("test_") and callable(eval(name)):
            print(name, end=': ')
            eval(name)()
            print("ok")
