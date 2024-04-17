#ifndef PSC_COMMONS_H
#define PSC_COMMONS_H

#include <stdint.h>
#include <stdlib.h>

/**
 * Print a buffer of bytes in hexadecimal format
 */
void print_bytes(const uint8_t* buffer, int size);

/**
 * Resulting symmetric key size should be SHA512_DIGEST_LENGTH
 * SSID + password should be less than 1024 characters for ideal performance
 */
void generate_symmetric_key(uint8_t* sym_key,
                            uint32_t ssid,
                            const uint8_t* password,
                            size_t password_size);

/**
 * Assert that all constants are correctly defined
 */
void pake_assert_constants(void);

#endif  // PSC_COMMONS_H
