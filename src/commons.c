#include "commons.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "feistel.h"

void pqpake_generate_symmetric_key(uint8_t* sym_key,
                                   uint32_t ssid,
                                   const uint8_t* password,
                                   size_t password_size) {
  int ssid_size = sizeof(ssid);

  uint8_t base_string[password_size + ssid_size];

  memcpy(base_string, &ssid, ssid_size);
  memcpy(base_string + ssid_size, password, password_size);

  SHA512(base_string, password_size + ssid_size, sym_key);
}

void pqpake_assert_constants(void) {
  assert(PQPAKE_SYM_KEY_SIZE == SHA512_DIGEST_LENGTH &&
         "symmetric key size mismatch");
  assert(PQPAKE_CT_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES &&
         "ciphertext size mismatch");
  assert(PQPAKE_PK_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES &&
         "public key size mismatch");
  assert(PQPAKE_SK_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES &&
         "secret key size mismatch");
  assert(PQPAKE_ECT_SIZE == PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES &&
         "encrypted ciphertext size mismatch");
  assert(PQPAKE_SHARED_SECRET_SIZE == SHA256_DIGEST_LENGTH &&
         "shared secret size mismatch");
}
