#include "cake.h"
#include <openssl/sha.h>
#include "ciphertext.h"
#include "commons.h"
#include "kyber1024.h"
#include "pake.h"
#include "publickey.h"
#define ROUND1_MESSAGE_SIZE PAKE_EPK_SIZE
#define ROUND2_MESSAGE_SIZE PAKE_ECT_SIZE

/**
 * Generate the final secret from the CAKE protocol parameters
 *
 * @param final_secret output buffer
 * @param ssid Common session ID
 * @param epk Alice's encrypted public key. Size is PAKE_EPK_SIZE
 * @param ect Bob's encrypted cipher text. Size is PAKE_ECT_SIZE
 * @param secret Common Kyber caps/decaps secret.
 *               Size is PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES
 * @param alice_name Initiator agent name
 * @param alice_size Initiator agent name's size
 * @param bob_name Responder agent name
 * @param bob_size Responder agent name's size
 */
void cake_generate_final_secret(uint8_t* final_secret,
                                uint32_t ssid,
                                const uint8_t* epk,
                                const uint8_t* ect,
                                const uint8_t* secret,
                                const uint8_t* alice_name,
                                size_t alice_size,
                                const uint8_t* bob_name,
                                size_t bob_size) {
  size_t max_buffer_size = sizeof(ssid) + PAKE_EPK_SIZE + PAKE_ECT_SIZE +
                           PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES + alice_size +
                           bob_size;

  uint8_t base_string[max_buffer_size];

  uint8_t* head = base_string;

  memcpy(head, &ssid, sizeof(ssid));
  head += sizeof(ssid);

  memcpy(head, alice_name, alice_size);
  head += alice_size;

  memcpy(head, bob_name, bob_size);
  head += bob_size;

  memcpy(head, epk, PAKE_EPK_SIZE);
  head += PAKE_EPK_SIZE;

  memcpy(head, ect, PAKE_ECT_SIZE);
  head += PAKE_ECT_SIZE;

  memcpy(head, secret, PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES);
  head += PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES;

  int result_size = head - base_string;

  SHA256(base_string, result_size, final_secret);
}

cake_agent* cake_create_alice(uint32_t session_id,
                              const uint8_t* password,
                              size_t password_size,
                              const uint8_t* alice_name,
                              size_t alice_size) {
  pake_assert_constants();

  cake_agent* agent = malloc(sizeof(cake_agent));
  if (agent == NULL) {
    return NULL;
  }
  memset(agent, 0, sizeof(cake_agent));

  agent->session_id = session_id;
  generate_symmetric_key(agent->sym_key, session_id, password, password_size);

  agent->alice_size = alice_size;
  agent->alice_name = malloc(alice_size);
  if (agent->alice_name == NULL) {
    free(agent);
    return NULL;
  }
  memcpy(agent->alice_name, alice_name, alice_size);

  agent->bob_size = 0;
  agent->bob_name = NULL;

  return agent;
}

cake_agent* cake_create_bob(uint32_t session_id,
                            const uint8_t* password,
                            size_t password_size,
                            const uint8_t* bob_name,
                            size_t bob_size) {
  pake_assert_constants();

  cake_agent* agent = malloc(sizeof(cake_agent));
  if (agent == NULL) {
    return NULL;
  }
  memset(agent, 0, sizeof(cake_agent));

  agent->session_id = session_id;
  generate_symmetric_key(agent->sym_key, session_id, password, password_size);

  agent->alice_size = 0;
  agent->alice_name = NULL;

  agent->bob_size = bob_size;
  agent->bob_name = malloc(bob_size);
  if (agent->bob_name == NULL) {
    free(agent);
    return NULL;
  }
  memcpy(agent->bob_name, bob_name, bob_size);

  return agent;
}

void cake_free_agent(cake_agent* agent) {
  if (agent->alice_name != NULL) {
    free(agent->alice_name);
  }

  if (agent->bob_name != NULL) {
    free(agent->bob_name);
  }

  free(agent);
}

typedef struct cake_header {
  uint8_t round;
  uint8_t name_size;
  // the following {#message_size} bytes are the message (pk or ec)
  // the message size depends on the round :
  //   - round 1: ROUND1_MESSAGE_SIZE
  //   - round 2: ROUND2_MESSAGE_SIZE
  // the remaining {name_size} bytes are the name of the sender
} cake_header;

void cake_create_message_round1(cake_agent* alice,
                                uint8_t** out,
                                size_t* out_size) {
  /** alice cryptography */

  PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(alice->pk, alice->sk);
  pake_ic_publickey_encrypt(alice->sym_key, alice->pk, alice->epk);

  /** alice --> bob : encrypted pk and alice's name */

  *out_size = sizeof(pake_header) + sizeof(cake_header) + ROUND1_MESSAGE_SIZE +
              alice->alice_size;
  *out = malloc(*out_size);
  if (*out == NULL) {
    *out_size = 0;
    return;
  }
  memset(*out, 0, *out_size);

  pake_header* pheader = (pake_header*)*out;
  pheader->protocol = PAKE_PROTO_CAKE_KYBER1024;

  cake_header* cheader = (cake_header*)(*out + sizeof(pake_header));
  cheader->round = 1;
  cheader->name_size = alice->alice_size;

  uint8_t* epk = (uint8_t*)cheader + sizeof(cake_header);
  memcpy(epk, alice->epk, ROUND1_MESSAGE_SIZE);

  uint8_t* name = epk + ROUND1_MESSAGE_SIZE;
  memcpy(name, alice->alice_name, alice->alice_size);
}

void cake_create_message_round2(cake_agent* bob,
                                const uint8_t* in,
                                uint8_t** out,
                                size_t* out_size) {
  /** parsing incoming message */

  const pake_header* in_pheader = (pake_header*)in;
  if (in_pheader->protocol != PAKE_PROTO_CAKE_KYBER1024) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  const cake_header* in_cheader = (cake_header*)(in + sizeof(pake_header));
  if (in_cheader->round != 1) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  const uint8_t* in_epk = (uint8_t*)in_cheader + sizeof(cake_header);
  pake_ic_publickey_decrypt(bob->sym_key, in_epk, bob->pk);

  bob->alice_size = in_cheader->name_size;
  bob->alice_name = malloc(bob->alice_size);
  if (bob->alice_name == NULL) {
    *out_size = 0;
    *out = NULL;
    return;
  }
  const uint8_t* in_name = in_epk + ROUND1_MESSAGE_SIZE;
  memcpy(bob->alice_name, in_name, bob->alice_size);

  /** bob cryptography */

  uint8_t bob_ss[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES] = {0};
  uint8_t bob_ct[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES] = {0};
  PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(bob_ct, bob_ss, bob->pk);

  uint8_t ect[ROUND2_MESSAGE_SIZE] = {0};
  pake_ic_ciphertext_encrypt(bob->sym_key, bob_ct, ect);

  cake_generate_final_secret(bob->ss, bob->session_id, in_epk, ect, bob_ss,
                             bob->alice_name, bob->alice_size, bob->bob_name,
                             bob->bob_size);

  /** bob --> alice : encrypted ct and bob's name */

  *out_size = sizeof(pake_header) + sizeof(cake_header) + ROUND2_MESSAGE_SIZE +
              bob->bob_size;
  *out = malloc(*out_size);
  if (*out == NULL) {
    *out_size = 0;
    return;
  }
  memset(*out, 0, *out_size);

  pake_header* out_pheader = (pake_header*)*out;
  out_pheader->protocol = PAKE_PROTO_CAKE_KYBER1024;

  cake_header* out_cheader = (cake_header*)(*out + sizeof(pake_header));
  out_cheader->round = 2;
  out_cheader->name_size = bob->bob_size;

  uint8_t* out_ect = (uint8_t*)out_cheader + sizeof(cake_header);
  memcpy(out_ect, ect, ROUND2_MESSAGE_SIZE);

  uint8_t* out_name = out_ect + ROUND2_MESSAGE_SIZE;
  memcpy(out_name, bob->bob_name, bob->bob_size);
}

void cake_create_message_round3(cake_agent* alice, const uint8_t* in) {
  const pake_header* pheader = (pake_header*)in;
  if (pheader->protocol != PAKE_PROTO_CAKE_KYBER1024) {
    return;
  }

  const cake_header* cheader = (cake_header*)(in + sizeof(pake_header));
  if (cheader->round != 2) {
    return;
  }

  const uint8_t* ect = (uint8_t*)cheader + sizeof(cake_header);
  uint8_t alice_ct[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES] = {0};
  pake_ic_ciphertext_decrypt(alice->sym_key, ect, alice_ct);

  alice->bob_size = cheader->name_size;
  alice->bob_name = malloc(alice->bob_size);
  if (alice->bob_name == NULL) {
    return;
  }
  const uint8_t* name = ect + ROUND2_MESSAGE_SIZE;
  memcpy(alice->bob_name, name, alice->bob_size);

  uint8_t alice_ss[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
  PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(alice_ss, alice_ct, alice->sk);

  cake_generate_final_secret(alice->ss, alice->session_id, alice->epk, ect,
                             alice_ss, alice->alice_name, alice->alice_size,
                             alice->bob_name, alice->bob_size);
}

const uint8_t* cake_get_shared_secret(const cake_agent* agent) {
  return agent->ss;
}
