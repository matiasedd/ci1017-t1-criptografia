#include <iostream>
#include <vector>
#include <iomanip>
#include <string>
#include <fstream>
#include "Cipher.hpp"

#define TESTE 1

void test_aes256(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Uso correto: teste <arquivo.txt>\n";
        return;
    }

    const char *input_path = argv[1];

    // Leitura do arquivo de entrada para plaintext
    std::vector<unsigned char> plaintext;
    {
        std::ifstream fin(input_path, std::ios::binary);
        if (!fin) {
            std::cerr << "Erro ao abrir arquivo " << input_path << "\n";
            return;
        }

        fin.seekg(0, std::ios::end);
        std::streamsize size = fin.tellg();
        fin.seekg(0, std::ios::beg);

        if (size <= 0) {
            std::cerr << "Arquivo vazio ou erro ao medir o tamanho.\n";
            return;
        }

        plaintext.resize(size);
        if (!fin.read(reinterpret_cast<char*>(plaintext.data()), size)) {
            std::cerr << "Erro ao ler o arquivo.\n";
            return;
        }
    }

    // chave de 256 bits
    const unsigned char key[32] = { 
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
    };

    // IV(vetor de inicialização) de 128 bits
    const unsigned char iv[16] = { 
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
    };

    Cipher c;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> decryptedtext;

    // criptografa e descriptografa
    c.aes256_encode(key, iv, plaintext, ciphertext);
    c.aes256_decode(key, iv, ciphertext, decryptedtext);

    const char *enc_path = "output_encrypted.bin"; // bytes cifrados (binário)
    const char* dec_path = "output_decrypted.txt"; // texto decifrado

    // escreve dados cifrados no arq
    {
        std::ofstream fout(enc_path, std::ios::binary);
        if (!fout) {
            std::cerr << "Erro ao criar arquivo de saída: " << enc_path << "\n";
            return;
        }
        if (!ciphertext.empty()) {
            fout.write(reinterpret_cast<const char*>(ciphertext.data()),
                       static_cast<std::streamsize>(ciphertext.size()));
        }
        if (!fout.good()) {
            std::cerr << "Erro ao escrever no arquivo: " << enc_path << "\n";
            return;
        }
    }
    // escreve dados decifrados no arq
    {
        std::ofstream fout(dec_path, std::ios::binary);
        if (!fout) {
            std::cerr << "Erro ao criar arquivo de saída: " << dec_path << "\n";
            return;
        }
        if (!decryptedtext.empty()) {
            fout.write(reinterpret_cast<const char*>(decryptedtext.data()),
                       static_cast<std::streamsize>(decryptedtext.size()));
        }
        if (!fout.good()) {
            std::cerr << "Erro ao escrever no arquivo: " << dec_path << "\n";
            return;
        }
    }

    // info extra
    std::cout << "Tamanho do plaintext: " << plaintext.size() << " bytes\n";
    std::cout << "Tamanho do ciphertext: " << ciphertext.size() << " bytes\n";
}

void test_transposition()
{

}

int main(int argc, char *argv[])
{
    #if TESTE == 1 // aes256
        test_aes256(argc, argv);
    #elif TESTE == 2 // transposicao
        test_transposition();
    #endif

    return 0;
}