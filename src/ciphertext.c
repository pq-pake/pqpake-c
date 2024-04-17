#include "ciphertext.h"
#include "constants.h"
#include "feistel.h"

void pake_ic_ciphertext_encrypt(const uint8_t* sym_key,
                                const uint8_t* ct,
                                uint8_t* ect) {
  pake_ic_feistel_encrypt(sym_key, PAKE_CT_SIZE, ct, ect);
}

void pake_ic_ciphertext_decrypt(const uint8_t* sym_key,
                                const uint8_t* ect,
                                uint8_t* ct) {
  pake_ic_feistel_decrypt(sym_key, PAKE_CT_SIZE, ect, ct);
}
