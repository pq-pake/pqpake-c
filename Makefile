MKDIR=mkdir -p

LIB_CAKE = libcake.a
LIB_OCAKE = libocake.a

HEADERS = src/feistel.h src/commons.h src/cake.h src/ocake.h src/encode.h src/ciphertext.h src/publickey.h
OBJECTS = bin/feistel.o bin/commons.o bin/cake.o bin/ocake.o bin/encode.o bin/ciphertext.o bin/publickey.o
FOREIGN_OBJECTS = PQClean/common/randombytes.o PQClean/common/fips202.o

LIB_KYBER=PQClean/crypto_kem/kyber1024/clean/libkyber1024_clean.a

CFLAGS = -Wall -Werror -std=c99 -O3

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
