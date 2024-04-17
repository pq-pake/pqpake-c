#include "publickey.h"
#include <stdio.h>
#include <string.h>
#include "constants.h"
#include "encode.h"
#include "feistel.h"
#define SEED_SIZE 32
#define VALUE_SIZE (PAKE_EPK_SIZE - SEED_SIZE)

void pake_ic_publickey_encrypt(const uint8_t* sym_key,
                               const uint8_t* pk,
                               uint8_t* epk) {
  // memset(epk, 0, PAKE_EPK_SIZE);

  const uint8_t* seed = pk + PAKE_PK_SIZE - SEED_SIZE;
  uint8_t* epk_seed = epk + PAKE_EPK_SIZE - SEED_SIZE;
  pake_ic_feistel_encrypt(sym_key, SEED_SIZE, seed, epk_seed);

  pake_ic_encode(pk, epk);

  do {
    // note: this is a bit dangerous given that we assume that we assume
    // feistel_encrypt doesn't read the input buffer after writing to the
    // output buffer however it avoids having to allocate a new buffer
    pake_ic_feistel_encrypt(sym_key, VALUE_SIZE, epk, epk);
  } while (pake_ic_value_is_not_in_range(epk));
}

void pake_ic_publickey_decrypt(const uint8_t* sym_key,
                               const uint8_t* epk,
                               uint8_t* pk) {
  // memset(pk, 0, PAKE_PK_SIZE);

  const uint8_t* epk_seed = epk + PAKE_EPK_SIZE - SEED_SIZE;
  uint8_t* seed = pk + PAKE_PK_SIZE - SEED_SIZE;
  pake_ic_feistel_decrypt(sym_key, SEED_SIZE, epk_seed, seed);

  pake_ic_feistel_decrypt(sym_key, VALUE_SIZE, epk, pk);

  while (pake_ic_value_is_not_in_range(pk)) {
    // note: this is a bit dangerous given that we assume that we assume
    // feistel_decrypt doesn't read the input buffer after writing to the output
    // buffer
    // however it avoids having to allocate a new buffer
    pake_ic_feistel_decrypt(sym_key, VALUE_SIZE, pk, pk);
  }

  // same remarks
  pake_ic_decode(pk, pk);
}
