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
import string
import struct

import camellia

VECTOR_FILENAME = os.path.join(os.path.dirname(__file__),
                               "test_vectors_rfc5528.txt")


TestvectorRFC5528 = collections.namedtuple(
    "TestvectorRFC5528",
    ["n", "desc", "key", "iv", "nonce", "plain", "cipher"])

TestvectorRFC5528Counter = collections.namedtuple(
    "TestvectorRFC5528Counter",
    ["n", "iv", "nonce", "counter_block"])


class Counter:
    """Simple counter for testing against RFC5528 vectors."""
    def __init__(self, nonce, iv):
        """Init method."""
        self.prefix = nonce+iv
        self.counter = 0

    def __call__(self):
        """Returns bytes"""
        self.counter += 1
        return self.prefix+struct.pack("!I", self.counter)


def _get_test_vectors_rfc5228(filename=VECTOR_FILENAME):
    vectors_cipher = []
    vectors_counter = []
    with open(VECTOR_FILENAME) as vector_file:
        for line in vector_file:
            line = line.strip()

            if not line:
                key, iv, nonce, plain, cipher, counter = map(
                    lambda x: x.replace(" ", ""),
                    (key, iv, nonce, plain, cipher, counter))
                vectors_cipher.append(TestvectorRFC5528(
                    n, desc, key, iv, nonce, plain, cipher))
                vectors_counter.append(TestvectorRFC5528Counter(
                    n, iv, nonce, counter))

                continue

            elif line.startswith("TV #"):
                n = line[4]
                desc = line
                continue

            title, value = line.split(":")
            title, value = title.strip(), value.strip()

            if title == "Camellia Key":
                key = value
                last = "key"

            elif title == "Camellia-CTR IV":
                iv = value

            elif title == "Nonce":
                nonce = value

            elif title == "Plaintext":
                plain = value
                last = "plain"

            elif title == "Counter Block (1)":
                counter = value

            elif title.startswith("Counter Block"):
                # But not ends with (1)
                counter += value

            elif title.startswith("Ciphertext"):
                cipher = value
                last = "cipher"

            elif ":" in line and not title:
                if last == "key":
                    key += value
                elif last == "plain":
                    plain += value
                elif last == "cipher":
                    cipher += value


    return vectors_cipher, vectors_counter



vectors_cipher, vectors_counter = _get_test_vectors_rfc5228()

CODE_TEST_COUNTER = r'''def test_rfc5228_counter_{n}():
    """Test counter against returns of TV# {n} in RFC5228."""
    c = Counter({nonce}, {iv})
    t = "{counter_block}"

    v = b"".join([c() for i in range(len(t)//32)])

    try:
        assert v == binascii.unhexlify(t)
    except AssertionError:
        print("Expected:\t", t)
        print("Got:\t\t", binascii.hexlify(v).decode())
        raise
'''

CODE_TEST_CTR = r'''
def test_rfc5228_ctr_{n}():
    """{desc}"""
    vector = {vector}

    key, nonce, iv = map(
        binascii.unhexlify,
        (vector.key, vector.nonce, vector.iv))

    cipher = camellia.new(
        key, mode=camellia.MODE_CTR,
        counter=Counter(nonce, iv))

    plain_bytes = binascii.unhexlify(vector.plain)
    cipher_bytes = binascii.unhexlify(vector.cipher)

    cipher_result = binascii.hexlify(
        cipher.encrypt(plain_bytes)).decode().upper()

    cipher = camellia.new(
        key, mode=camellia.MODE_CTR,
        counter=Counter(nonce, iv))

    plain_result = binascii.hexlify(
        cipher.decrypt(cipher_bytes)).decode().upper()    

    try:
        assert cipher_result == vector.cipher
        assert plain_result == vector.plain
    except AssertionError:
        print("failed")
        print("Key:")
        print(vector.key)
        print("Nonce+IV:")
        print(vector.nonce+vector.iv)
        print()
        print("Plaintext (expected, result):")
        print(vector.plain, plain_result)
        print()
        print("Ciphertext (expected, result):")
        print(vector.cipher, cipher_result)

        raise
'''

for vector in vectors_counter:
    exec(CODE_TEST_COUNTER.format(
        n=vector.n,
        nonce=binascii.unhexlify(vector.nonce),
        iv=binascii.unhexlify(vector.iv),
        counter_block=vector.counter_block))

for vector in vectors_cipher:
    exec(CODE_TEST_CTR.format(
        n=vector.n,
        desc=vector.desc,
        vector=repr(vector)))


if __name__ == '__main__':
    import __main__
    for name in dir(__main__):
        if name.startswith("test_") and callable(eval(name)):
            print(name, end=': ')
            eval(name)()
            print("ok")