#ifndef PAKE_IC_PUBLICKEY_H
#define PAKE_IC_PUBLICKEY_H

#include <stdint.h>

void pake_ic_publickey_encrypt(const uint8_t* sym_key,
                               const uint8_t* pk,
                               uint8_t* epk);

void pake_ic_publickey_decrypt(const uint8_t* sym_key,
                               const uint8_t* epk,
                               uint8_t* pk);

#endif  // PAKE_IC_PUBLICKEY_H
