#include <stddef.h>
#include <string.h>

#include "camellia.h"
#include "camellia_modes.h"


void Camellia_EncryptEcb(
    const int keyBitLength,
    const unsigned char *plaintext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *ciphertext,
    size_t blocks
) {
    for (size_t i=0; i<blocks; i++) {
        Camellia_EncryptBlock(
            keyBitLength,
            plaintext + CAMELLIA_BLOCK_SIZE * i,
            keyTable,
            ciphertext + CAMELLIA_BLOCK_SIZE * i
        );
    }
}


void Camellia_DecryptEcb(
    const int keyBitLength,
    const unsigned char *ciphertext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *plaintext,
    size_t blocks
) {
    for (size_t i=0; i<blocks; i++) {
        Camellia_DecryptBlock(
            keyBitLength,
            ciphertext + CAMELLIA_BLOCK_SIZE * i,
            keyTable,
            plaintext + CAMELLIA_BLOCK_SIZE * i
        );
    }
}


void Camellia_EncryptCbc(
    const int keyBitLength,
    const unsigned char *plaintext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *ciphertext,
    size_t blocks,
    unsigned char *iv
) {
    for (size_t i=0; i<blocks; i++) {
        for (int j=0; j < CAMELLIA_BLOCK_SIZE; j++) {
            iv[j] ^= *(plaintext++);
        }

        Camellia_EncryptBlock(
            keyBitLength,
            iv,
            keyTable,
            ciphertext
        );

        memcpy(iv, ciphertext, CAMELLIA_BLOCK_SIZE);
        ciphertext += CAMELLIA_BLOCK_SIZE;
    }
}


void Camellia_DecryptCbc(
    const int keyBitLength,
    const unsigned char *ciphertext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *plaintext,
    size_t blocks,
    unsigned char *iv
) {
    for (size_t i=0; i<blocks; i++) {
        Camellia_DecryptBlock(
            keyBitLength,
            ciphertext,
            keyTable,
            plaintext
        );

        for (int j=0; j < CAMELLIA_BLOCK_SIZE; j++) {
            plaintext[j] ^= iv[j];
        }

        memcpy(iv, ciphertext, CAMELLIA_BLOCK_SIZE);
        ciphertext += CAMELLIA_BLOCK_SIZE;
        plaintext += CAMELLIA_BLOCK_SIZE;
    }
}