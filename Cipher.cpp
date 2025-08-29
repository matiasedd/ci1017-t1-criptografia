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

/**
 * Criptografa o texto claro por transposição gerando texto criptografado
 * 
 * key        Ordem das colunas a escrever
 * plaintext  Buffer de entrada (texto claro)
 * ciphertext Buffer de saída (texto criptografado)
 */
void Cipher::transposition_encode(
    const std::vector<unsigned int> &key,
    const std::vector<byte> &plaintext,
    std::vector<byte> &ciphertext)
{
    const size_t cols = key.size(); // num de colunas
    const size_t rows = (plaintext.size() + cols - 1) / cols; // num de linhas

    std::vector<std::vector<byte>> mat(rows, std::vector<byte>(cols));

    // Preenche a matriz com o texto claro, linha por linha
    unsigned int cont=0; // iterador do plaintext
    for (size_t i=0; i< rows; ++i) {
        for (size_t j=0; j< cols; ++j) {
            if (cont < plaintext.size()) {
                mat[i][j] = plaintext[cont];
                cont++;
            } else
                mat[i][j] = 'X';
        }
    }

    // std::cout << "Matriz gerada:\n";
    // for (size_t i=0; i< rows; ++i) {
    //     for (size_t j=0; j< cols; ++j) {
    //         std::cout << mat[i][j] << " ";
    //     }
    //     std::cout << "\n";
    // }
    // std::cout << "\n";

    ciphertext.resize(rows * cols);

    // Gera o texto cifrado, coluna por coluna, na ordem de key
    cont=0; // iterador do ciphertext
    for (unsigned int j : key) {
        for (size_t i=0; i < rows; ++i) {
            ciphertext[cont] = mat[i][j];
            cont++;
        }
    }

    // std::cout << "Texto cifrado: ";
    // for (size_t i=0; i< ciphertext.size(); ++i)
    //     std::cout << ciphertext[i];
    // std::cout << "\n";
}

/**
 * Descriptografa o texto cifrado por transposição gerando texto decifrado
 * 
 * key           Ordem das colunas a serem lidas
 * ciphertext    Buffer de entrada (texto criptografado)
 * decryptedtext Buffer de saída (texto decifrado)
 */
void Cipher::transposition_decode(
    const std::vector<unsigned int> &key,
    const std::vector<byte> &ciphertext,
    std::vector<byte> &decryptedtext)
{
    const size_t cols = key.size(); // num de colunas
    const size_t rows = ciphertext.size() / cols; // num de linhas

    std::vector<std::vector<byte>> mat(rows, std::vector<byte>(cols));

    // Preenche a matriz com o texto cifrado, na ordem da key
    unsigned int cont = 0; // iterador do ciphertext
    for (unsigned int j : key) {
        for (size_t i=0; i< rows; ++i) {
            mat[i][j] = ciphertext[cont];
            cont++;
        }
    }

    // std::cout << "Matriz gerada no decode:\n";
    // for (size_t i=0; i< rows; ++i) {
    //     for (size_t j=0; j< cols; ++j) {
    //         std::cout << mat[i][j] << " ";
    //     }
    //     std::cout << "\n";
    // }
    // std::cout << "\n";

    decryptedtext.resize(rows * cols);

    // organiza o texto decifrado
    cont=0;
    for (size_t i=0; i< rows; ++i) {
        for (size_t j=0; j< cols; ++j) {
            if (mat[i][j] != 'X') {
                decryptedtext[cont] = mat[i][j];
                cont++;
            }                   
        }            
    }

    // std::cout << "Texto decifrado: ";
    // for (size_t i=0; i< decryptedtext.size(); ++i)
    //     std::cout << decryptedtext[i];
    // std::cout << "\n";
}

/**
 * Criptografa o texto claro usando AES gerando texto criptografado em hex
 * 
 * key        Chave de 256bits (32 bytes)
 * iv         Vetor de inicialização (16 bytes)
 * plaintext  Buffer de entrada (texto claro)
 * ciphertext Buffer de saída (texto criptografado)
 */
void Cipher::aes256_encode(
    const byte key[32],
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
 * Descriptografa o texto cifrado usando AES gerando texto decifrado
 * 
 * key           Chave de 256bits (32 bytes)
 * iv            Vetor de inicialização (16 bytes)
 * ciphertext    Buffer de entrada (texto criptografado)
 * decryptedtext Buffer de saída (texto decifrado)
 */
void Cipher::aes256_decode(
    const byte key[32], 
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
