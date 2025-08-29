#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include "Cipher.hpp"

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

void Cipher::encode()
{
    std::cout << "Encoding..." << std::endl;
}

void Cipher::decode()
{
    std::cout << "Decoding..." << std::endl;
}

/**
 * Faz a criptografia do texto claro usando AES gerando texto criptografado em hex
 * 
 * key        Chave de 256bits (32 bytes)
 * iv         Vetor de inicialização (16 bytes)
 * plaintext  Buffer de entrada (texto claro)
 * ciphertext Buffer de saída (texto criptografado)
 */
void Cipher::aes256_encode(const byte key[32],
                        const byte iv[16], 
                        const std::vector<byte> &plaintext, 
                        std::vector<byte> &ciphertext)
{
    // inicializacoes de contexto e init
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    // pre-dimensiona plaintext +1 bloco para paddings
    ciphertext.resize(plaintext.size() + 16); // 16 eh o tamanho do bloco AES
    
    int out_len1 = 0;
    const byte *in_ptr = plaintext.empty() ? nullptr : (const byte *)&plaintext[0];

    rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ciphertext[0], &out_len1, 
                            in_ptr, (int)plaintext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptUpdate failed");
   
    int out_len2 = (int)ciphertext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ciphertext[0]+out_len1, &out_len2);
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // ajusta tamanho final do texto cifrado
    ciphertext.resize(out_len1 + out_len2);
}

/**
 * Faz a descriptografia do texto cifrado usando AES gerando texto decifrado
 * 
 * key           Chave de 256bits (32 bytes)
 * iv            Vetor de inicialização (16 bytes)
 * ciphertext    Buffer de entrada (texto criptografado)
 * decryptedtext Buffer de saída (texto decifrado)
 */
void Cipher::aes256_decode(const byte key[32], 
                        const byte iv[16],
                        const std::vector<byte> &ciphertext, 
                        std::vector<byte> &decryptedtext)
{
    // inicializacoes de contexto e init
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    // decryptedtext <= ciphertext (padding sera removido no final)
    decryptedtext.resize(ciphertext.size());

    int out_len1 = 0;
    const byte* in_ptr = ciphertext.empty() ? nullptr : (const byte*)&ciphertext[0];

    rc = EVP_DecryptUpdate(ctx.get(),
                           (byte*)&decryptedtext[0], &out_len1,
                           in_ptr, (int)ciphertext.size());
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = (int)decryptedtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(),
                             (byte*)&decryptedtext[0] + out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // ajusta tamanho final do texto plano (pos-remocao do padding)
    decryptedtext.resize(out_len1 + out_len2);
}
