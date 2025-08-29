CC=g++
CFLAGS=-std=c++11 -Wall -Wextra -O2
LDLIBS=-lcrypto

all: cipher

cipher: main.o Cipher.o
	$(CC) $(CFLAGS) main.o Cipher.o -o $@ $(LDLIBS)

main.o: main.cpp Cipher.hpp
	$(CC) $(CFLAGS) -c main.cpp

Cipher.o: Cipher.cpp Cipher.hpp
	$(CC) $(CFLAGS) -c Cipher.cpp

teste: teste.cpp Cipher.o
	$(CC) $(CFLAGS) teste.cpp Cipher.o $(LDLIBS) -o teste

clean:
	rm -f *.o

purge: clean
	rm -f cipher aes-teste output_decrypted.txt output_encrypted.bin