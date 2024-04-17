CFLAGS = -Wall -Werror -std=c99 -lcrypto -lgmp -L../lib -lcake -locake -I../include

all: test_cake_alice_bob test_ocake_alice_bob

test_cake_alice_bob: test_cake_alice_bob.c
	$(CC) -o test_cake_alice_bob test_cake_alice_bob.c $(CFLAGS)

test_ocake_alice_bob: test_ocake_alice_bob.c
	$(CC) -o test_ocake_alice_bob test_ocake_alice_bob.c $(CFLAGS)

clean:
	$(RM) test_cake_alice_bob
	$(RM) test_ocake_alice_bob
