#ifndef PAKE_IC_CIPHERTEXT_H
#define PAKE_IC_CIPHERTEXT_H

#include <stdint.h>

void pake_ic_ciphertext_encrypt(const uint8_t* sym_key,
                                const uint8_t* ct,
                                uint8_t* ect);

void pake_ic_ciphertext_decrypt(const uint8_t* sym_key,
                                const uint8_t* ect,
                                uint8_t* ct);

#endif  // PAKE_IC_CIPHERTEXT_H
