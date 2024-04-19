#ifndef PQPAKE_IC_FEISTEL_H
#define PQPAKE_IC_FEISTEL_H
#include <stddef.h>
#include <stdint.h>
#include "kyber1024.h"

/**
 * @param sym_key Symmetric key of size PQPAKE_SYM_KEY_SIZE (64 bytes)
 * @param message_size Size of the message to encrypt. Must be even !
 * @param clear_message Buffer to decrypt. Size is {message_size}
 * @param encrypted_message Operation result. Size is {message_size}
 */
void pqpake_ic_feistel_encrypt(const uint8_t* sym_key,
                               size_t message_size,
                               const uint8_t* clear_message,
                               uint8_t* encrypted_message);

/**
 * @param sym_key Symmetric key of size PQPAKE_SYM_KEY_SIZE (64 bytes)
 * @param message_size Size of the message to decrypt. Must be even !
 * @param encrypted_message Buffer to decrypt. Size is {message_size}
 * @param clear_message Operation result. Size is {message_size}
 */
void pqpake_ic_feistel_decrypt(const uint8_t* sym_key,
                               size_t message_size,
                               const uint8_t* encrypted_message,
                               uint8_t* clear_message);

#endif  // PQPAKE_IC_FEISTEL_H
