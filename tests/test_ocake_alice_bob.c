#include <pake/ocake.h>
#include <stdio.h>
#include <stdlib.h>

void print_buffer(const uint8_t* buffer, int size) {
  for (int i = 0; i < size; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void ocake_alice_bob_test() {
  uint32_t ssid = 424242;
  char password[] = "password1234";

  char alice_name[] = "finch";
  ocake_agent* alice =
      ocake_create_alice(ssid, (uint8_t*)password, strlen(password),
                         (uint8_t*)alice_name, strlen(alice_name));
  char bob_name[] = "reese";
  ocake_agent* bob =
      ocake_create_bob(ssid, (uint8_t*)password, strlen(password),
                       (uint8_t*)bob_name, strlen(bob_name));

  uint8_t* alice_message;
  size_t alice_message_size;
  ocake_create_message_round1(alice, &alice_message, &alice_message_size);

  if (alice_message_size == 0) {
    printf("alice_message_size == 0\n");
    exit(1);
  }

  uint8_t* bob_message;
  size_t bob_message_size;
  ocake_create_message_round2(bob, alice_message, &bob_message,
                              &bob_message_size);

  if (bob_message_size == 0) {
    printf("bob_message_size == 0\n");
    exit(1);
  }

  ocake_create_message_round3(alice, bob_message);

  // printf("alice pk: ");
  // print_buffer(alice->pk, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
  // printf("  bob pk: ");
  // print_buffer(bob->pk, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);

  const uint8_t* alice_ss = ocake_get_shared_secret(alice);
  const uint8_t* bob_ss = ocake_get_shared_secret(bob);

  printf("Alice: ");
  print_buffer(alice_ss, PAKE_SHARED_SECRET_SIZE);

  printf("  Bob: ");
  print_buffer(bob_ss, PAKE_SHARED_SECRET_SIZE);

  for (int i = 0; i < PAKE_SHARED_SECRET_SIZE; i++) {
    if (alice_ss[i] != bob_ss[i]) {
      printf("alice_ss[%d] != bob_ss[%d]\n", i, i);
      exit(1);
    }
  }

  printf("ocake_alice_bob_test passed\n");

  ocake_free_agent(alice);
  ocake_free_agent(bob);
}

int main(void) {
  ocake_alice_bob_test();

  return 0;
}
