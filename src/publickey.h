#ifndef PQPAKE_IC_PUBLICKEY_H
#define PQPAKE_IC_PUBLICKEY_H

#include <stdint.h>

/**
 * @param sym_key Symmetric key of size PQPAKE_SYM_KEY_SIZE
 * @param pk Public key of size PQPAKE_PK_SIZE
 * @param epk Encrypted public key of size PQPAKE_EPK_SIZE
 * @returns 0 if the operation was successful, -1 otherwise
 */
int pqpake_ic_publickey_encrypt(const uint8_t* sym_key,
                                const uint8_t* pk,
                                uint8_t* epk);

/**
 * @param sym_key Symmetric key of size PQPAKE_SYM_KEY_SIZE
 * @param epk Encrypted public key of size PQPAKE_EPK_SIZE
 * @param pk Public key of size PQPAKE_PK_SIZE
 * @returns 0 if the operation was successful, -1 otherwise
 */
int pqpake_ic_publickey_decrypt(const uint8_t* sym_key,
                                const uint8_t* epk,
                                uint8_t* pk);

#endif  // PQPAKE_IC_PUBLICKEY_H
