MKDIR=mkdir -p

LIB_CAKE = libcake.a
LIB_OCAKE = libocake.a

HEADERS = src/feistel.h src/commons.h src/cake.h src/ocake.h src/encode.h src/ciphertext.h src/publickey.h
OBJECTS = bin/feistel.o bin/commons.o bin/cake.o bin/ocake.o bin/encode.o bin/ciphertext.o bin/publickey.o
FOREIGN_OBJECTS = PQClean/common/randombytes.o PQClean/common/fips202.o

LIB_KYBER=PQClean/crypto_kem/kyber1024/clean/libkyber1024_clean.a

# CFLAGS = -Wall -Werror -std=c99 -lcrypto -lgmp -IPQClean/common -IPQClean/crypto_kem/kyber1024/clean -LPQClean/crypto_kem/kyber1024/clean -lkyber1024_clean
CFLAGS = -Wall -Werror -std=c99

all: $(LIB_CAKE) $(LIB_OCAKE)

$(LIB_CAKE): $(OBJECTS) $(FOREIGN_OBJECTS) $(LIB_KYBER)
	$(MKDIR) kyber-dump && cd kyber-dump && ar -x ../$(LIB_KYBER) && cd ..
	$(MKDIR) lib
	$(AR) -r lib/$@ $(OBJECTS) $(FOREIGN_OBJECTS) kyber-dump/*.o
	$(RM) -r kyber-dump

$(LIB_OCAKE): $(OBJECTS) $(FOREIGN_OBJECTS) $(LIB_KYBER)
	$(MKDIR) kyber-dump && cd kyber-dump && ar -x ../$(LIB_KYBER) && cd ..
	$(MKDIR) lib
	$(AR) -r lib/$@ $(OBJECTS) $(FOREIGN_OBJECTS) kyber-dump/*.o
	$(RM) -r kyber-dump

$(LIB_KYBER):
	$(MAKE) -C PQClean/crypto_kem/kyber1024/clean -j 4

bin/%.o: src/%.c
	$(MKDIR) $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: $(HEADERS)

clean:
	$(RM) -r bin
	$(RM) -r lib
	$(RM) $(FOREIGN_OBJECTS)
	$(MAKE) -C PQClean/crypto_kem/kyber1024/clean clean







# OPENSSL ?= /usr/local/opt/openssl@3.1/lib

# CFLAGS = -Wall -Werror -std=c99 -lcrypto -lgmp -LPQClean/crypto_kem/kyber1024/clean -lkyber1024_clean

# PAKE_HEADERS = feistel.h commons.h cake.h ocake.h encode.h ciphertext.h publickey.h PQClean/common/randombytes.c PQClean/common/fips202.c
# PAKE_SOURCES = feistel.c commons.c cake.c ocake.c encode.c ciphertext.c publickey.c PQClean/common/randombytes.c PQClean/common/fips202.c

# AUX_HEADERS = aes.h communicate.h
# AUX_SOURCES = aes.c communicate.c

# all: test_feistel test_alice_bob test_pk_encoder

# test_feistel: test_feistel.c feistel.h feistel.c commons.h commons.c
# 	$(CC) -o test_feistel test_feistel.c feistel.c commons.c $(CFLAGS)

# test_cake_alice_bob: test_cake_alice_bob.c $(PAKE_HEADERS) $(PAKE_SOURCES)
# 	$(CC) -o test_cake_alice_bob test_cake_alice_bob.c $(PAKE_SOURCES) $(CFLAGS)

# test_ocake_alice_bob: test_ocake_alice_bob.c $(PAKE_HEADERS) $(PAKE_SOURCES)
# 	$(CC) -o test_ocake_alice_bob test_ocake_alice_bob.c $(PAKE_SOURCES) $(CFLAGS)

# test_encoder: test_encoder.c $(PAKE_HEADERS) $(PAKE_SOURCES)
# 	$(CC) -o test_encoder test_encoder.c $(PAKE_SOURCES) $(CFLAGS)

# test_pk_encrypt: test_pk_encrypt.c $(PAKE_HEADERS) $(PAKE_SOURCES)
# 	$(CC) -o test_pk_encrypt test_pk_encrypt.c $(PAKE_SOURCES) $(CFLAGS)

# psc_cake_tcp: psc_cake_alice_tcp psc_cake_bob_tcp
# psc_cake_alice_tcp: psc_cake_alice.c $(PAKE_HEADERS) $(PAKE_SOURCES) $(AUX_HEADERS) $(AUX_SOURCES)
# 	$(CC) -o psc_cake_alice psc_cake_alice.c $(PAKE_SOURCES) $(AUX_SOURCES) $(CFLAGS)
# psc_cake_bob_tcp: psc_cake_bob.c $(PAKE_HEADERS) $(PAKE_SOURCES) $(AUX_HEADERS) $(AUX_SOURCES)
# 	$(CC) -o psc_cake_bob psc_cake_bob.c $(PAKE_SOURCES) $(AUX_SOURCES) $(CFLAGS)

# psc_cake_bt: psc_cake_alice_bt psc_cake_bob_bt
# psc_cake_alice_bt: psc_cake_alice.c $(PAKE_HEADERS) $(PAKE_SOURCES) $(AUX_HEADERS) $(AUX_SOURCES) bluetooth.c bluetooth.h
# 	$(CC) -o psc_cake_alice psc_cake_alice.c $(PAKE_SOURCES) $(AUX_SOURCES) bluetooth.c -DPSC_COMM_LAYER_BLUETOOTH -lbluetooth $(CFLAGS)
# psc_cake_bob_bt: psc_cake_bob.c $(PAKE_HEADERS) $(PAKE_SOURCES) $(AUX_HEADERS) $(AUX_SOURCES) bluetooth.c bluetooth.h
# 	$(CC) -o psc_cake_bob psc_cake_bob.c $(PAKE_SOURCES) $(AUX_SOURCES) bluetooth.c -DPSC_COMM_LAYER_BLUETOOTH -lbluetooth $(CFLAGS)

# clean:
# 	$(RM) test_feistel
# 	$(RM) test_alice_bob
# 	$(RM) test_pk_encoder
