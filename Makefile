CC = gcc
CFLAGS = -Wall \
				 -I libraries/findargs \
				 -I libraries/utilscrypt

SRC = main.c \
				 libraries/findargs/findargs.c \
				 libraries/utilscrypt/utilscrypt.c

SRC_BUILD = build
TARGET = $(SRC_BUILD)/otpcrypt


all: $(TARGET)

$(TARGET): $(SRC)
				 mkdir -p build
				 $(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

cleanAll:
	rm -f $(SRC_BUILD)/*
