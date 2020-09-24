
import binascii
import collections
import os

import camellia
import pytest

# Source:
# https://info.isl.ntt.co.jp/crypt/eng/camellia/dl/cryptrec/t_camellia.txt
VECTOR_FILENAME = os.path.join(os.path.dirname(__file__),
                               "test_vectors_ntt.txt")

_TestvectorCryptrec = collections.namedtuple(
    "_TestvectorCryptrec",
    ["k_no", "key", "t_no", "plain", "cipher"])


def _get_test_vectors_ntt(filename=VECTOR_FILENAME):
    vectors = []

    key = ""
    plain = ""
    cipher = ""

    k_no = ""
    t_no = ""

    with open(VECTOR_FILENAME) as vector_file:
        vector_file.readline()

        for line in vector_file:
            line = line.strip()

            k, _, v = line.partition(":")

            if not v:
                continue
            elif k[0] == 'K':
                key = v.replace(' ', '')
                k_no = k[2:]
            elif k[0] == 'P':
                plain = v.replace(' ', '')
                t_no = k[2:]
            elif k[0] == 'C':
                cipher = v.replace(' ', '')
                vectors.append(_TestvectorCryptrec(
                    k_no, key, t_no, plain, cipher
                ))

    return vectors


@pytest.mark.parametrize("vector", _get_test_vectors_ntt())
def test_vectors_ntt(vector):
    key = binascii.unhexlify(vector.key)
    plain = binascii.unhexlify(vector.plain)
    cipher = binascii.unhexlify(vector.cipher)

    cam = camellia.new(key, camellia.MODE_ECB)

    cipher_result = cam.encrypt(plain)
    plain_result = cam.decrypt(cipher)

    assert cipher_result == cipher
    assert plain_result == plain
