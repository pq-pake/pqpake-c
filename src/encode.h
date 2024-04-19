#include <stdint.h>
#ifndef PQPAKE_IC_ENCODE_H
#define PQPAKE_IC_ENCODE_H
#define PQPAKE_IC_ENC_INPUT_SIZE 1536
#define PQPAKE_IC_ENC_OUTPUT_SIZE 1498

/**
 * @param input size : PQPAKE_IC_ENC_INPUT_SIZE (1536)
 * @param output size : PQPAKE_IC_ENC_OUTPUT_SIZE (1498)
 * @note The encoding is actually done on 12238 bits (1529.75 bytes)
 *
 * @note Unlike in the Python implementation, the encoding is not parameterized
 * with the number of coefficients and the coefficient max size. It is assumed
 * that the encoding is done on 1024 coefficients, 12 bits each, and with base
 * 3329. This allows us to use some bit tricks to efficiently encode and decode
 * the coefficients.
 */
void pqpake_ic_encode(const uint8_t* input, uint8_t* output);

/**
 * @param input size : PQPAKE_IC_ENC_OUTPUT_SIZE (1498)
 * @param output size : PQPAKE_IC_ENC_INPUT_SIZE (1536)
 * @note the decoding is actually done on 11982 bits (1497.75 bytes)
 */
void pqpake_ic_decode(const uint8_t* input, uint8_t* output);

/**
 * @param value Value to check
 * @return 1 if the value is greater than or equal to 3329**1024, 0 otherwise
 */
int pqpake_ic_value_is_not_in_range(const uint8_t* value);

#endif  // PQPAKE_IC_ENCODE_H
