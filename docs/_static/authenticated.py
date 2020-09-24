import base64
import getpass
import hashlib
import hmac
import os
import sys

import camellia

HMAC_ALGO = "sha512"

PBKDF_ROUNDS = 10000000  # Larger = better but slower
PBKDF_HASH = "sha512"


def _print_usage():
    print("Usage: {} --encrypt|--decrypt INFILE OUTFILE".format(sys.argv[0]))


def _pad(data):
    byte_and_len = camellia.block_size - len(data) % camellia.block_size
    return data + bytes([byte_and_len] * byte_and_len)


def _unpad(data):
    return data[0:-data[-1]]


def encrypt(password: str, plaintext: bytes) -> str:
    salt = os.urandom(16)  # Random salt each time
    # Derive key from password, to compensate weaker passwords
    key = hashlib.pbkdf2_hmac(PBKDF_HASH, password.encode(), salt,
                              PBKDF_ROUNDS, dklen=64)
    # Use individual keys for encryption and authentication
    key_encryption, key_authentication = key[:32], key[32:]

    iv = os.urandom(16)  # Random IV, this is important
    encrypter = camellia.new(key_encryption, camellia.MODE_CBC, IV=iv)

    # The data is padded with PKCS#5
    cipher_text = encrypter.encrypt(_pad(plaintext))

    # Authentication tag
    mac = hmac.new(key_authentication, iv + cipher_text, HMAC_ALGO).digest()

    # Rounds are serialized to potentially increase it for new files
    return "{}.{}.{}.{}".format(
        base64.b64encode(salt).decode(),
        PBKDF_ROUNDS,
        base64.b64encode(iv + cipher_text).decode(),
        base64.b64encode(mac).decode()
    )


def decrypt(password: str, encrypted: str) -> bytes:
    encoded_salt, rounds, encoded_iv_cipher, encoded_mac = encrypted.split(".")
    rounds = int(rounds)

    # Generate key
    key = hashlib.pbkdf2_hmac(PBKDF_HASH, password.encode(),
                              base64.b64decode(encoded_salt),
                              rounds, dklen=64)

    key_encryption, key_authentication = key[:32], key[32:]

    iv_cipher = base64.b64decode(encoded_iv_cipher)

    # Compare in time-safe manner, to prevent an attacker learning
    # about the newly computed MAC.
    if not hmac.compare_digest(hmac.new(key_authentication,
                                        iv_cipher, HMAC_ALGO).digest(),
                               base64.b64decode(encoded_mac)):
        raise ValueError("mac does not match, invalid password or data")

    iv, cipher_text = iv_cipher[:16], iv_cipher[16:]

    decrypter = camellia.new(key_encryption, mode=camellia.MODE_CBC, IV=iv)

    # Decrypt and remove padding
    return _unpad(decrypter.decrypt(cipher_text))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        _print_usage()
        exit(1)

    if not os.path.isfile(sys.argv[2]):
        print("Not found: {}".format(sys.argv[2]))
        exit(2)

    password = getpass.getpass()

    try:
        if sys.argv[1] == "--encrypt":
            with open(sys.argv[2], 'rb') as infile:
                with open(sys.argv[3], 'wt') as outfile:
                    outfile.write(encrypt(password, infile.read()))
        elif sys.argv[1] == "--decrypt":
            with open(sys.argv[2], 'rt') as infile:
                with open(sys.argv[3], 'wb') as outfile:
                    outfile.write(decrypt(password, infile.read()))
        else:
            _print_usage()
            exit(1)
    except (IOError, ValueError) as e:
        print(e)
        exit(4)
