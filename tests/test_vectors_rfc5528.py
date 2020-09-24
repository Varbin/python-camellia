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
import struct

import camellia
import pytest

VECTOR_FILENAME = os.path.join(os.path.dirname(__file__),
                               "test_vectors_rfc5528.txt")


_TestvectorRFC5528 = collections.namedtuple(
    "TestvectorRFC5528",
    ["n", "desc", "key", "iv", "nonce", "plain", "cipher"])

_TestvectorRFC5528Counter = collections.namedtuple(
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
    vectors = {}

    with open(VECTOR_FILENAME) as vector_file:
        for line in vector_file:
            line = line.strip()

            if not line:
                key, iv, nonce, plain, cipher, counter = map(
                    lambda x: x.replace(" ", ""),
                    (key, iv, nonce, plain, cipher, counter))
                vectors[n] = (
                    _TestvectorRFC5528(
                        n, desc, key, iv, nonce, plain, cipher),
                    _TestvectorRFC5528Counter(
                        n, iv, nonce, counter)
                )

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

    return vectors


VECTORS = _get_test_vectors_rfc5228()


@pytest.mark.parametrize("n, vector_and_counter", VECTORS.items())
def test_vectors_rfc5228_counter(n, vector_and_counter):
    """Test counters of RFC5228."""
    counter = vector_and_counter[1]
    c = Counter(binascii.unhexlify(counter.nonce),
                binascii.unhexlify(counter.iv))
    t = counter.counter_block

    v = b"".join([c() for i in range(len(t)//32)])

    try:
        assert v == binascii.unhexlify(t)
    except AssertionError:
        print("Expected:\t", t)
        print("Got:\t\t", binascii.hexlify(v).decode())
        raise


@pytest.mark.parametrize("n, vector_and_counter", VECTORS.items())
def test_vectors_rfc5228_ctr(n, vector_and_counter):
    vector = vector_and_counter[0]

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

    assert cipher_result == vector.cipher
    assert plain_result == vector.plain
