#include "publickey.h"
#include <stdio.h>
#include <string.h>
#include "constants.h"
#include "encode.h"
#include "feistel.h"
#define SEED_SIZE 32
#define VALUE_SIZE (PAKE_EPK_SIZE - SEED_SIZE)
// 54 rounds is enough to have a 2^-128 probability of
// finding a valid public key
#define ROUNDS 54

int pake_ic_publickey_encrypt(const uint8_t* sym_key,
                              const uint8_t* pk,
                              uint8_t* epk) {
  // memset(epk, 0, PAKE_EPK_SIZE);

  uint8_t temp_epk[PAKE_EPK_SIZE];
  pake_ic_encode(pk, temp_epk);

  int found_in_range = 0;

  for (int i = 0; i < ROUNDS; i++) {
    // note: this is a bit dangerous given that we assume that we assume
    // feistel_encrypt doesn't read the input buffer after writing to the
    // output buffer however it avoids having to allocate a new buffer
    pake_ic_feistel_encrypt(sym_key, VALUE_SIZE, temp_epk, temp_epk);

    if (!pake_ic_value_is_not_in_range(temp_epk) && !found_in_range) {
      found_in_range = 1;
      memcpy(epk, temp_epk, PAKE_EPK_SIZE);
    }
  }

  if (!found_in_range) {
    return -1;
  }

  const uint8_t* seed = pk + PAKE_PK_SIZE - SEED_SIZE;
  uint8_t* epk_seed = epk + PAKE_EPK_SIZE - SEED_SIZE;
  pake_ic_feistel_encrypt(sym_key, SEED_SIZE, seed, epk_seed);

  return 0;
}

int pake_ic_publickey_decrypt(const uint8_t* sym_key,
                              const uint8_t* epk,
                              uint8_t* pk) {
  // memset(pk, 0, PAKE_PK_SIZE);

  uint8_t temp_pk[PAKE_PK_SIZE];
  memcpy(temp_pk, epk, PQPAKE_PK_SIZE);

  int found_in_range = 0;

  for (int i = 0; i < ROUNDS; i++) {
    // note: this is a bit dangerous given that we assume that we assume
    // feistel_decrypt doesn't read the input buffer after writing to the output
    // buffer
    // however it avoids having to allocate a new buffer
    pqpake_ic_feistel_decrypt(sym_key, VALUE_SIZE, temp_pk, temp_pk);

    if (!pake_ic_value_is_not_in_range(temp_pk) && !found_in_range) {
      found_in_range = 1;
      memcpy(pk, temp_pk, PAKE_PK_SIZE);
    }
  }

  if (!found_in_range) {
    return -1;
  }

  const uint8_t* epk_seed = epk + PAKE_EPK_SIZE - SEED_SIZE;
  uint8_t* seed = pk + PAKE_PK_SIZE - SEED_SIZE;
  pake_ic_feistel_decrypt(sym_key, SEED_SIZE, epk_seed, seed);

  // same remarks
  pake_ic_decode(pk, pk);

  return 0;
}
