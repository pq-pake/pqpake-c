CFLAGS = -Wall -Werror -std=c99 -lcrypto -lgmp -L../lib -lcake -locake

all: alice_bob idealcipher

alice_bob: alice_bob.c benchmark.c benchmark.h
	$(CC) -o alice_bob alice_bob.c benchmark.c $(CFLAGS) -I../include

idealcipher: idealcipher.c benchmark.c benchmark.h
	$(CC) -o idealcipher idealcipher.c benchmark.c $(CFLAGS) -I../src

clean:
	$(RM) alice_bob
	$(RM) idealcipher
