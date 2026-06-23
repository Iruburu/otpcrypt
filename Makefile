CC = gcc
CFLAGS = -g -Wall -I libraries/findargs 
CUTILSCRYPT = -g -Wall -I libraries/utilscrypt
FINDARGS = libraries/findargs/findargs.c
UTILSCRYPT = libraries/utilscrypt/utilscrypt.c

all: otpcrypt

otpcrypt: main.c
	$(CC) $(CFLAGS) $(CUTILSCRYPT) main.c $(FINDARGS) $(UTILSCRYPT) -o ./build/otpcrypt

clean:
	rm -f otpcrypt
