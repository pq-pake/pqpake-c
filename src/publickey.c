#include "publickey.h"
#include <string.h>
#include "constants.h"
#include "encode.h"
#include "feistel.h"
#define SEED_SIZE 32
#define VALUE_SIZE (PQPAKE_EPK_SIZE - SEED_SIZE)
// 54 rounds is enough to have a 2^-128 probability of
// finding a valid public key
#define ROUNDS 54

int pqpake_ic_publickey_encrypt(const uint8_t* sym_key,
                                const uint8_t* pk,
                                uint8_t* epk) {
  // memset(epk, 0, PQPAKE_EPK_SIZE);

  uint8_t temp_epk[PQPAKE_EPK_SIZE];
  pqpake_ic_encode(pk, temp_epk);

  int finished_encryption = 0;

  for (int i = 0; i < ROUNDS; i++) {
    // note: this is a bit dangerous given that we assume that we assume
    // feistel_encrypt doesn't read the input buffer after writing to the
    // output buffer however it avoids having to allocate a new buffer
    pqpake_ic_feistel_encrypt(sym_key, VALUE_SIZE, temp_epk, temp_epk);

    int is_in_range = !pqpake_ic_value_is_not_in_range(temp_epk);

    int epk_mask = (~finished_encryption & is_in_range) ? 0xff : 0x00;
    for (int j = 0; j < PQPAKE_EPK_SIZE; j++) {
      epk[j] = (epk[j] & epk_mask) | (temp_epk[j] & ~epk_mask);
    }

    finished_encryption |= is_in_range;
  }

  if (!finished_encryption) {
    return -1;
  }

  const uint8_t* seed = pk + PQPAKE_PK_SIZE - SEED_SIZE;
  uint8_t* epk_seed = epk + PQPAKE_EPK_SIZE - SEED_SIZE;
  pqpake_ic_feistel_encrypt(sym_key, SEED_SIZE, seed, epk_seed);

  return 0;
}

int pqpake_ic_publickey_decrypt(const uint8_t* sym_key,
                                const uint8_t* epk,
                                uint8_t* pk) {
  // memset(pk, 0, PQPAKE_PK_SIZE);

  uint8_t temp_pk[PQPAKE_PK_SIZE];
  memcpy(temp_pk, epk, PQPAKE_PK_SIZE);

  int finished_encryption = 0;

  for (int i = 0; i < ROUNDS; i++) {
    // note: this is a bit dangerous given that we assume that we assume
    // feistel_decrypt doesn't read the input buffer after writing to the output
    // buffer
    // however it avoids having to allocate a new buffer
    pqpake_ic_feistel_decrypt(sym_key, VALUE_SIZE, temp_pk, temp_pk);

    int is_in_range = !pqpake_ic_value_is_not_in_range(temp_pk);

    int pk_mask = (~finished_encryption & is_in_range) ? 0xff : 0x00;

    for (int j = 0; j < PQPAKE_PK_SIZE; j++) {
      pk[j] = (pk[j] & pk_mask) | (temp_pk[j] & ~pk_mask);
    }

    finished_encryption |= is_in_range;
  }

  if (!finished_encryption) {
    return -1;
  }

  const uint8_t* epk_seed = epk + PQPAKE_EPK_SIZE - SEED_SIZE;
  uint8_t* seed = pk + PQPAKE_PK_SIZE - SEED_SIZE;
  pqpake_ic_feistel_decrypt(sym_key, SEED_SIZE, epk_seed, seed);

  // same remarks
  pqpake_ic_decode(pk, pk);

  return 0;
}
