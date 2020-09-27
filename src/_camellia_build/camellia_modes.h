void Camellia_EncryptEcb(
    const int keyBitLength,
    const unsigned char *plaintext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *ciphertext,
    size_t blocks
);

void Camellia_DecryptEcb(
    const int keyBitLength,
    const unsigned char *ciphertext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *plaintext,
    size_t blocks
);

void Camellia_EncryptCbc(
    const int keyBitLength,
    const unsigned char *plaintext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *ciphertext,
    size_t blocks,
    unsigned char *iv
);

void Camellia_DecryptCbc(
    const int keyBitLength,
    const unsigned char *ciphertext,
    const KEY_TABLE_TYPE keyTable,
    unsigned char *plaintext,
    size_t blocks,
    unsigned char *iv
);