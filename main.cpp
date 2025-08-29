#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>
#include "Cipher.hpp"

int main()
{
    Cipher c;

    std::vector<unsigned int> key = { 3, 4, 1, 0, 2 };
    std::string msg = "UNIVERSIDADE FEDERAL DO PARANA";

    // remove os espaços
    msg.erase(std::remove_if(msg.begin(), msg.end(),
                [](unsigned char c) { return std::isspace(c); }),
            msg.end());
    std::vector<unsigned char> plaintext(msg.begin(), msg.end());

    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> decryptedtext;

    c.transposition_encode(key, plaintext, ciphertext);
    c.transposition_decode(key, ciphertext, decryptedtext);
    
    return 0;
}
