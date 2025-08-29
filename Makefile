CC=g++
CFLAGS=-Wall -Wextra

all: cipher

cipher: main.cpp Cipher.o
	$(CC) $(CFLAGS) main.cpp Cipher.o -o cipher

Cipher.o: Cipher.hpp Cipher.cpp
	$(CC) $(CFLAGS) -c Cipher.cpp

aes-teste: aes-teste.cpp Cipher.o
	$(CC) -std=c++11 aes-teste.cpp Cipher.o -Wall -Wextra -O2 -lcrypto -o aes-teste

clean:
	rm -f Cipher.o

purge: clean
	rm -f cipher aes-teste output_decrypted.txt output_encrypted.bin