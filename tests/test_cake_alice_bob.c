#include <pake/cake.h>
#include <stdio.h>
#include <stdlib.h>

void print_buffer(const uint8_t* buffer, int size) {
  for (int i = 0; i < size; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void cake_alice_bob_test() {
  uint32_t ssid = 424242;
  char password[] = "password1234";

  char alice_name[] = "finch";
  cake_agent* alice =
      cake_create_alice(ssid, (uint8_t*)password, strlen(password),
                        (uint8_t*)alice_name, strlen(alice_name));
  char bob_name[] = "reese";
  cake_agent* bob = cake_create_bob(ssid, (uint8_t*)password, strlen(password),
                                    (uint8_t*)bob_name, strlen(bob_name));

  uint8_t* alice_message;
  size_t alice_message_size;
  cake_create_message_round1(alice, &alice_message, &alice_message_size);

  if (alice_message_size == 0) {
    printf("alice_message_size == 0\n");
    exit(1);
  }

  uint8_t* bob_message;
  size_t bob_message_size;
  cake_create_message_round2(bob, alice_message, &bob_message,
                             &bob_message_size);

  if (bob_message_size == 0) {
    printf("bob_message_size == 0\n");
    exit(1);
  }

  cake_create_message_round3(alice, bob_message);

  // printf("alice pk: ");
  // print_buffer(alice->pk, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
  // printf("  bob pk: ");
  // print_buffer(bob->pk, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);

  const uint8_t* alice_ss = cake_get_shared_secret(alice);
  const uint8_t* bob_ss = cake_get_shared_secret(bob);

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

  printf("cake_alice_bob_test passed\n");

  cake_free_agent(alice);
  cake_free_agent(bob);
}

int main(void) {
  cake_alice_bob_test();

  return 0;
}
