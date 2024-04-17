#include "commons.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "feistel.h"

void print_bytes(const uint8_t* buffer, int size) {
  for (int i = 0; i < size; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void generate_symmetric_key(uint8_t* sym_key,
                            uint32_t ssid,
                            const uint8_t* password,
                            size_t password_size) {
  int ssid_size = sizeof(ssid);

  uint8_t base_string[password_size + ssid_size];

  memcpy(base_string, &ssid, ssid_size);
  memcpy(base_string + ssid_size, password, password_size);

  SHA512(base_string, password_size + ssid_size, sym_key);
}

void pake_assert_constants(void) {
  assert(PAKE_SYM_KEY_SIZE == SHA512_DIGEST_LENGTH &&
         "symmetric key size mismatch");
  assert(PAKE_CT_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES &&
         "ciphertext size mismatch");
  assert(PAKE_PK_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES &&
         "public key size mismatch");
  assert(PAKE_SK_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES &&
         "secret key size mismatch");
  assert(PAKE_ECT_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES &&
         "encrypted ciphertext size mismatch");
  assert(PAKE_SHARED_SECRET_SIZE == SHA256_DIGEST_LENGTH &&
         "shared secret size mismatch");
}
