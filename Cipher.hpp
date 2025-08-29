#pragma once

#include <vector>

typedef unsigned char byte;

class Cipher
{
public:
    void encode();
    void decode();

    void transposition_encode(const std::vector<unsigned int> &key,
        const std::vector<byte> &plaintext, std::vector<byte> &ciphertext);
    void transposition_decode(const std::vector<unsigned int> &key,
        const std::vector<byte> &ciphertext, std::vector<byte> &decryptedtext);

    void aes256_encode(const byte key[32], const byte iv[16], 
        const std::vector<byte> &plaintext, std::vector<byte> &ciphertext);
    void aes256_decode(const byte key[32], const byte iv[16],
        const std::vector<byte> &ciphertext, std::vector<byte> &decryptedtext);
};