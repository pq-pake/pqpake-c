#include "ocake.h"
#include <assert.h>
#include <openssl/sha.h>
#include "commons.h"
#include "kyber1024.h"
#include "pake.h"
#include "publickey.h"
#define ROUND1_MESSAGE_SIZE PAKE_EPK_SIZE
#define ROUND2_MESSAGE_SIZE PAKE_CT_SIZE
#define OCAKE_AUTH_SIZE 32

/**
 * Generate the final secret from the OCAKE protocol parameters
 *
 * @param final_secret output buffer
 * @param ssid Common session ID
 * @param epk Alice's encrypted public key. Size is PAKE_EPK_SIZE
 * @param ct Bob's cipher text. Size is PAKE_CT_SIZE
 * @param secret Common Kyber caps/decaps secret.
 *               Size is PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES
 * @param auth Authentication tag. Size is OCAKE_AUTH_SIZE
 * @param alice_name Initiator agent name
 * @param alice_size Initiator agent name's size
 * @param bob_name Responder agent name
 * @param bob_size Responder agent name's size
 */
void ocake_generate_final_secret(uint8_t* final_secret,
                                 uint32_t ssid,
                                 const uint8_t* epk,
                                 const uint8_t* ct,
                                 const uint8_t* secret,
                                 const uint8_t* auth,
                                 const uint8_t* alice_name,
                                 size_t alice_size,
                                 const uint8_t* bob_name,
                                 size_t bob_size) {
  size_t max_buffer_size = sizeof(ssid) + PAKE_EPK_SIZE + PAKE_CT_SIZE +
                           PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES +
                           OCAKE_AUTH_SIZE + alice_size + bob_size;

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

  memcpy(head, ct, PAKE_CT_SIZE);
  head += PAKE_CT_SIZE;

  memcpy(head, auth, OCAKE_AUTH_SIZE);
  head += OCAKE_AUTH_SIZE;

  memcpy(head, secret, PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES);
  head += PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES;

  int result_size = head - base_string;

  SHA256(base_string, result_size, final_secret);
}

/**
 * Generate Bob's authentication tag
 *
 * @param auth_tag output buffer
 * @param ssid Common session ID
 * @param password Password
 * @param password_size Password size
 * @param epk Alice's encrypted public key. Size is PAKE_EPK_SIZE
 * @param ct Bob's cipher text. Size is PAKE_CT_SIZE
 * @param secret Common Kyber caps/decaps secret.
 *               Size is PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES
 * @param alice_name Initiator agent name
 * @param alice_size Initiator agent name's size
 * @param bob_name Responder agent name
 * @param bob_size Responder agent name's size
 */
void generate_auth_tag(uint8_t* auth_tag,
                       uint32_t ssid,
                       const uint8_t* password,
                       size_t password_size,
                       const uint8_t* epk,
                       const uint8_t* ct,
                       const uint8_t* secret,
                       const uint8_t* alice_name,
                       size_t alice_size,
                       const uint8_t* bob_name,
                       size_t bob_size) {
  size_t max_buffer_size = sizeof(ssid) + password_size + PAKE_EPK_SIZE +
                           PAKE_CT_SIZE + PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES +
                           alice_size + bob_size;

  uint8_t base_string[max_buffer_size];

  uint8_t* head = base_string;

  memcpy(head, &ssid, sizeof(ssid));
  head += sizeof(ssid);

  memcpy(head, alice_name, alice_size);
  head += alice_size;

  memcpy(head, bob_name, bob_size);
  head += bob_size;

  memcpy(head, password, password_size);
  head += password_size;

  memcpy(head, epk, PAKE_EPK_SIZE);
  head += PAKE_EPK_SIZE;

  memcpy(head, ct, PAKE_CT_SIZE);
  head += PAKE_CT_SIZE;

  memcpy(head, secret, PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES);
  head += PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES;

  int result_size = head - base_string;

  SHA256(base_string, result_size, auth_tag);
}

ocake_agent* ocake_create_alice(uint32_t session_id,
                                const uint8_t* password,
                                size_t password_size,
                                const uint8_t* alice_name,
                                size_t alice_size) {
  pake_assert_constants();

  ocake_agent* agent = malloc(sizeof(ocake_agent));
  if (agent == NULL) {
    return NULL;
  }
  memset(agent, 0, sizeof(ocake_agent));

  agent->session_id = session_id;
  generate_symmetric_key(agent->sym_key, session_id, password, password_size);

  agent->password_size = password_size;
  agent->password = malloc(password_size);
  if (agent->password == NULL) {
    free(agent);
    return NULL;
  }
  memcpy(agent->password, password, password_size);

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

ocake_agent* ocake_create_bob(uint32_t session_id,
                              const uint8_t* password,
                              size_t password_size,
                              const uint8_t* bob_name,
                              size_t bob_size) {
  pake_assert_constants();

  ocake_agent* agent = malloc(sizeof(ocake_agent));
  if (agent == NULL) {
    return NULL;
  }
  memset(agent, 0, sizeof(ocake_agent));

  agent->session_id = session_id;
  generate_symmetric_key(agent->sym_key, session_id, password, password_size);

  agent->password_size = password_size;
  agent->password = malloc(password_size);
  if (agent->password == NULL) {
    free(agent);
    return NULL;
  }
  memcpy(agent->password, password, password_size);

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

void ocake_free_agent(ocake_agent* agent) {
  if (agent->password != NULL) {
    free(agent->password);
  }

  if (agent->alice_name != NULL) {
    free(agent->alice_name);
  }

  if (agent->bob_name != NULL) {
    free(agent->bob_name);
  }

  free(agent);
}

typedef struct ocake_header {
  uint8_t round;
  uint8_t name_size;
  // 1. the following {#message_size} bytes are the message (pk or ec)
  //    the message size depends on the round :
  //    - round 1: ROUND1_MESSAGE_SIZE
  //    - round 2: ROUND2_MESSAGE_SIZE
  // 2. the next {name_size} bytes are the name of the sender
  // 3. if round is 2, the remaining {OCAKE_AUTH_SIZE} bytes are the
  //    authentication tag
} ocake_header;

void ocake_create_message_round1(ocake_agent* alice,
                                 uint8_t** out,
                                 size_t* out_size) {
  /** alice cryptography */

  PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(alice->pk, alice->sk);
  pake_ic_publickey_encrypt(alice->sym_key, alice->pk, alice->epk);

  /** alice --> bob : encrypted pk and alice's name */

  *out_size = sizeof(pake_header) + sizeof(ocake_header) + ROUND1_MESSAGE_SIZE +
              alice->alice_size;
  *out = malloc(*out_size);
  if (*out == NULL) {
    *out_size = 0;
    return;
  }
  memset(*out, 0, *out_size);

  pake_header* pheader = (pake_header*)*out;
  pheader->protocol = PAKE_PROTO_OCAKE_KYBER1024;

  ocake_header* cheader = (ocake_header*)(*out + sizeof(pake_header));
  cheader->round = 1;
  cheader->name_size = alice->alice_size;

  uint8_t* epk = (uint8_t*)cheader + sizeof(ocake_header);
  memcpy(epk, alice->epk, ROUND1_MESSAGE_SIZE);

  uint8_t* name = epk + ROUND1_MESSAGE_SIZE;
  memcpy(name, alice->alice_name, alice->alice_size);
}

void ocake_create_message_round2(ocake_agent* bob,
                                 const uint8_t* in,
                                 uint8_t** out,
                                 size_t* out_size) {
  /** parsing incoming message */

  const pake_header* in_pheader = (pake_header*)in;
  if (in_pheader->protocol != PAKE_PROTO_OCAKE_KYBER1024) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  const ocake_header* in_cheader = (ocake_header*)(in + sizeof(pake_header));
  if (in_cheader->round != 1) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  const uint8_t* in_epk = (uint8_t*)in_cheader + sizeof(ocake_header);
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

  uint8_t auth[OCAKE_AUTH_SIZE] = {0};
  generate_auth_tag(auth, bob->session_id, bob->password, bob->password_size,
                    in_epk, bob_ct, bob_ss, bob->alice_name, bob->alice_size,
                    bob->bob_name, bob->bob_size);

  ocake_generate_final_secret(bob->ss, bob->session_id, in_epk, bob_ct, bob_ss,
                              auth, bob->alice_name, bob->alice_size,
                              bob->bob_name, bob->bob_size);

  /** bob --> alice : encrypted ct and bob's name */

  *out_size = sizeof(pake_header) + sizeof(ocake_header) + ROUND2_MESSAGE_SIZE +
              bob->bob_size + OCAKE_AUTH_SIZE;
  *out = malloc(*out_size);
  if (*out == NULL) {
    *out_size = 0;
    return;
  }
  memset(*out, 0, *out_size);

  pake_header* out_pheader = (pake_header*)*out;
  out_pheader->protocol = PAKE_PROTO_OCAKE_KYBER1024;

  ocake_header* out_cheader = (ocake_header*)(*out + sizeof(pake_header));
  out_cheader->round = 2;
  out_cheader->name_size = bob->bob_size;

  uint8_t* out_ct = (uint8_t*)out_cheader + sizeof(ocake_header);
  memcpy(out_ct, bob_ct, ROUND2_MESSAGE_SIZE);

  uint8_t* out_name = out_ct + ROUND2_MESSAGE_SIZE;
  memcpy(out_name, bob->bob_name, bob->bob_size);

  uint8_t* out_auth = out_name + bob->bob_size;
  memcpy(out_auth, auth, OCAKE_AUTH_SIZE);
}

void ocake_create_message_round3(ocake_agent* alice, const uint8_t* in) {
  const pake_header* pheader = (pake_header*)in;
  if (pheader->protocol != PAKE_PROTO_OCAKE_KYBER1024) {
    return;
  }

  const ocake_header* cheader = (ocake_header*)(in + sizeof(pake_header));
  if (cheader->round != 2) {
    return;
  }

  const uint8_t* ct = (uint8_t*)cheader + sizeof(ocake_header);

  alice->bob_size = cheader->name_size;
  alice->bob_name = malloc(alice->bob_size);
  if (alice->bob_name == NULL) {
    return;
  }
  const uint8_t* name = ct + ROUND2_MESSAGE_SIZE;
  memcpy(alice->bob_name, name, alice->bob_size);

  uint8_t alice_ss[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
  PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(alice_ss, ct, alice->sk);

  const uint8_t* bob_auth = name + alice->bob_size;

  uint8_t auth[OCAKE_AUTH_SIZE] = {0};
  generate_auth_tag(auth, alice->session_id, alice->password,
                    alice->password_size, alice->epk, ct, alice_ss,
                    alice->alice_name, alice->alice_size, alice->bob_name,
                    alice->bob_size);

  if (memcmp(auth, bob_auth, OCAKE_AUTH_SIZE) != 0) {
    return;
  }

  ocake_generate_final_secret(
      alice->ss, alice->session_id, alice->epk, ct, alice_ss, bob_auth,
      alice->alice_name, alice->alice_size, alice->bob_name, alice->bob_size);
}

const uint8_t* ocake_get_shared_secret(const ocake_agent* agent) {
  return agent->ss;
}
