#ifndef PQPAKE_IC_CIPHERTEXT_H
#define PQPAKE_IC_CIPHERTEXT_H

#include <stdint.h>

void pqpake_ic_ciphertext_encrypt(const uint8_t* sym_key,
                                  const uint8_t* ct,
                                  uint8_t* ect);

void pqpake_ic_ciphertext_decrypt(const uint8_t* sym_key,
                                  const uint8_t* ect,
                                  uint8_t* ct);

#endif  // PQPAKE_IC_CIPHERTEXT_H
