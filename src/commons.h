#ifndef PQPAKE_COMMONS_H
#define PQPAKE_COMMONS_H

#include <stdint.h>
#include <stdlib.h>

/**
 * Resulting symmetric key size should be SHA512_DIGEST_LENGTH
 * SSID + password should be less than 1024 characters for ideal performance
 */
void pqpake_generate_symmetric_key(uint8_t* sym_key,
                                   uint32_t ssid,
                                   const uint8_t* password,
                                   size_t password_size);

/**
 * Assert that all constants are correctly defined
 */
void pqpake_assert_constants(void);

#endif  // PQPAKE_COMMONS_H
