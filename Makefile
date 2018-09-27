CC=gcc
CFLAGS=-c -Wall
TARGET=sniffer

sniffer: src/sniffer.c
	gcc -o sniffer src/sniffer.c

clean:
	rm -rf *.o sniffer
run: sniffer
	./sniffer
