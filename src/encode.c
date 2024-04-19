#include "encode.h"
#include <assert.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 3329
#define COEFF_SIZE 1024
#define COEFF_HALF_SIZE (COEFF_SIZE / 2)

void pqpake_ic_encode(const uint8_t* input, uint8_t* output) {
  uint16_t coefficients[COEFF_SIZE] = {0};  // 12 bits per coefficient
  mpz_t total, pow_base;
  mpz_init(total);
  mpz_init(pow_base);
  mpz_set_ui(pow_base, 1);

  /* coefficients[i] = bits 12i to 12i+11 */
  for (int i = 0; i < COEFF_HALF_SIZE; i++) {
    coefficients[2 * i] =
        (uint16_t)input[3 * i] | ((uint16_t)(input[3 * i + 1] & 0x0F) << 8);
    coefficients[2 * i + 1] =
        (uint16_t)(input[3 * i + 1] >> 4) | (uint16_t)input[3 * i + 2] << 4;
  }

  /* total = \sum_{i=0}^{1023} coeffs[i] * base^i */
  for (int i = 0; i < COEFF_SIZE; i++) {
    mpz_addmul_ui(total, pow_base, coefficients[i]);

    mpz_mul_ui(pow_base, pow_base, BASE);
  }

  /** @note the number is stored in reverse-order bytes */
  memset(output, 0, PQPAKE_IC_ENC_OUTPUT_SIZE);
  mpz_export(output, NULL, -1, 1, 0, 0, total);

  mpz_clear(total);
  mpz_clear(pow_base);
}

void pqpake_ic_decode(const uint8_t* input, uint8_t* output) {
  uint16_t coefficients[COEFF_SIZE] = {0};
  mpz_t total;
  mpz_init(total);

  mpz_import(total, PQPAKE_IC_ENC_OUTPUT_SIZE, -1, 1, 0, 0, input);

  for (int i = 0; i < COEFF_SIZE; i++) {
    coefficients[i] = mpz_fdiv_ui(total, BASE);
    mpz_fdiv_q_ui(total, total, BASE);
  }
  for (int i = 0; i < COEFF_HALF_SIZE; i++) {
    output[3 * i] = coefficients[2 * i] & 0xFF;
    output[3 * i + 1] =
        (coefficients[2 * i] >> 8) | ((coefficients[2 * i + 1] & 0x0F) << 4);
    output[3 * i + 2] = (coefficients[2 * i + 1] >> 4) & 0xFF;
  }

  mpz_clear(total);
}

int pqpake_ic_value_is_not_in_range(const uint8_t* value) {
  mpz_t total, max_pow_base;
  mpz_init(total);
  mpz_init(max_pow_base);

  mpz_init_set_ui(max_pow_base, BASE);
  mpz_pow_ui(max_pow_base, max_pow_base, COEFF_SIZE);

  mpz_import(total, PQPAKE_IC_ENC_OUTPUT_SIZE, -1, 1, 0, 0, value);

  int res = mpz_cmp(total, max_pow_base) >= 0;

  mpz_clear(total);
  mpz_clear(max_pow_base);

  return res;
}
