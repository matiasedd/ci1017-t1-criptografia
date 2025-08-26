CC=g++
CFLAGS=-Wall

all: cipher

cipher: main.cpp Cipher.o
	$(CC) $(CFLAGS) main.cpp Cipher.o -o cipher

Cipher.o: Cipher.hpp Cipher.cpp
	$(CC) $(CFLAGS) -c Cipher.cpp

clean:
	rm -f Cipher.o

purge: clean
	rm -f cipher
