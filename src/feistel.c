#include "feistel.h"
#include <assert.h>
#include <math.h>
#include <openssl/sha.h>
#include <string.h>
#include "constants.h"
#define FEISTEL_ROUNDS 14

/**
 * @param sym_key Symmetric key of size PAKE_SYM_KEY_SIZE (64 bytes)
 * @param message_size Size of the message to hash
 * @param message Buffer to hash. Size is {message_size}
 * @param hashed_message Operation result. Size is FEISTEL_HALF_MESSAGE_SIZE
 * @note hashed_message must be allocated by the caller
 */
void hash(const uint8_t* sym_key,
          size_t message_size,
          const uint8_t* message,
          uint8_t* hashed_message) {
  const int hash_count = (int)ceil((float)message_size / SHA512_DIGEST_LENGTH);
  const int input_string_size = 1 + PAKE_SYM_KEY_SIZE + message_size;

  uint8_t hashing_result[hash_count * SHA512_DIGEST_LENGTH];
  memset(hashing_result, 0, hash_count * SHA512_DIGEST_LENGTH);

  uint8_t input_string[input_string_size];
  memset(input_string, 0, input_string_size);

  memcpy(input_string + 1, sym_key, PAKE_SYM_KEY_SIZE);
  memcpy(input_string + 1 + PAKE_SYM_KEY_SIZE, message, message_size);

  for (int round = 0; round < hash_count; round++) {
    input_string[0] = round;

    SHA512(input_string, input_string_size,
           hashing_result + round * SHA512_DIGEST_LENGTH);
  }

  memcpy(hashed_message, hashing_result, message_size);
}

void pake_ic_feistel_encrypt(const uint8_t* sym_key,
                             size_t message_size,
                             const uint8_t* clear_message,
                             uint8_t* encrypted_message) {
  assert(message_size % 2 == 0 && "message_size must be even");

  const size_t half_size = message_size / 2;

  uint8_t left[half_size];
  uint8_t right[half_size];

  memcpy(left, clear_message, half_size);
  memcpy(right, clear_message + half_size, half_size);

  for (int i = 0; i < FEISTEL_ROUNDS; i++) {
    uint8_t hashed_right[half_size];
    hash(sym_key, half_size, right, hashed_right);
    uint8_t new_left[half_size];
    for (int j = 0; j < half_size; j++) {
      new_left[j] = left[j] ^ hashed_right[j];
    }

    uint8_t hashed_new_left[half_size];
    hash(sym_key, half_size, new_left, hashed_new_left);
    uint8_t new_right[half_size];
    for (int j = 0; j < half_size; j++) {
      new_right[j] = right[j] ^ hashed_new_left[j];
    }

    memcpy(right, new_right, half_size);
    memcpy(left, new_left, half_size);
  }

  memcpy(encrypted_message, left, half_size);
  memcpy(encrypted_message + half_size, right, half_size);
}

void pake_ic_feistel_decrypt(const uint8_t* sym_key,
                             size_t message_size,
                             const uint8_t* encrypted_message,
                             uint8_t* clear_message) {
  assert(message_size % 2 == 0 && "message_size must be even");

  const size_t half_size = message_size / 2;

  uint8_t left[half_size];
  uint8_t right[half_size];

  memcpy(left, encrypted_message, half_size);
  memcpy(right, encrypted_message + half_size, half_size);

  for (int i = 0; i < FEISTEL_ROUNDS; i++) {
    uint8_t hashed_left[half_size];
    hash(sym_key, half_size, left, hashed_left);
    uint8_t new_right[half_size];
    for (int j = 0; j < half_size; j++) {
      new_right[j] = right[j] ^ hashed_left[j];
    }

    uint8_t hashed_new_right[half_size];
    hash(sym_key, half_size, new_right, hashed_new_right);
    uint8_t new_left[half_size];
    for (int j = 0; j < half_size; j++) {
      new_left[j] = left[j] ^ hashed_new_right[j];
    }

    memcpy(left, new_left, half_size);
    memcpy(right, new_right, half_size);
  }

  memcpy(clear_message, left, half_size);
  memcpy(clear_message + half_size, right, half_size);
}
