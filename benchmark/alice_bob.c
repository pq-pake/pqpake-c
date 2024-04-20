#include <pqpake/cake.h>
#include <pqpake/ocake.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "benchmark.h"

int run_alice_bob_cake(uint32_t ssid,
                       char* password,
                       char* alice_name,
                       char* bob_name) {
  cake_agent* alice =
      cake_create_alice(ssid, (uint8_t*)password, strlen(password),
                        (uint8_t*)alice_name, strlen(alice_name));
  cake_agent* bob = cake_create_bob(ssid, (uint8_t*)password, strlen(password),
                                    (uint8_t*)bob_name, strlen(bob_name));

  uint8_t* alice_message;
  size_t alice_message_size;
  cake_create_message_round1(alice, &alice_message, &alice_message_size);

  if (alice_message_size == 0) {
    return -1;
  }

  uint8_t* bob_message;
  size_t bob_message_size;
  cake_create_message_round2(bob, alice_message, &bob_message,
                             &bob_message_size);

  if (bob_message_size == 0) {
    return -2;
  }

  cake_create_message_round3(alice, bob_message);

  const uint8_t* alice_ss = cake_get_shared_secret(alice);
  const uint8_t* bob_ss = cake_get_shared_secret(bob);

  for (int i = 0; i < PQPAKE_SHARED_SECRET_SIZE; i++) {
    if (alice_ss[i] != bob_ss[i]) {
      return -3 - i;
    }
  }

  cake_free_agent(alice);
  cake_free_agent(bob);

  return 0;
}

int run_alice_bob_ocake(uint32_t ssid,
                        char* password,
                        char* alice_name,
                        char* bob_name) {
  ocake_agent* alice =
      ocake_create_alice(ssid, (uint8_t*)password, strlen(password),
                         (uint8_t*)alice_name, strlen(alice_name));
  ocake_agent* bob =
      ocake_create_bob(ssid, (uint8_t*)password, strlen(password),
                       (uint8_t*)bob_name, strlen(bob_name));

  uint8_t* alice_message;
  size_t alice_message_size;
  ocake_create_message_round1(alice, &alice_message, &alice_message_size);

  if (alice_message_size == 0) {
    return -1;
  }

  uint8_t* bob_message;
  size_t bob_message_size;
  ocake_create_message_round2(bob, alice_message, &bob_message,
                              &bob_message_size);

  if (bob_message_size == 0) {
    return -2;
  }

  ocake_create_message_round3(alice, bob_message);

  const uint8_t* alice_ss = ocake_get_shared_secret(alice);
  const uint8_t* bob_ss = ocake_get_shared_secret(bob);

  for (int i = 0; i < PQPAKE_SHARED_SECRET_SIZE; i++) {
    if (alice_ss[i] != bob_ss[i]) {
      return -3 - i;
    }
  }

  ocake_free_agent(alice);
  ocake_free_agent(bob);

  return 0;
}

void benchmark_cake(int n) {
  benchmark_result* result = malloc(sizeof(benchmark_result));
  result->mean = 0;
  result->median = 0;
  result->min = 0;
  result->max = 0;
  result->std_dev = 0;
  result->fail_count = 0;

  char password[] = "password1234";
  char alice_name[] = "finch";
  char bob_name[] = "reese";

  double* times = malloc(sizeof(double) * n);
  for (int i = 0; i < n; i++) {
    uint32_t ssid = rand();

    clock_t start = clock();
    int ret = run_alice_bob_cake(ssid, password, alice_name, bob_name);
    clock_t end = clock();

    if (ret < 0) {
      times[i] = -1;
      fprintf(stderr, "run_alice_bob_cake failed with %d\n", ret);
      continue;
    }

    times[i] = (double)(end - start) / CLOCKS_PER_SEC * 1000;
  }

  compute_statistics(times, n, result);

  free(times);

  printf("Benchmark results for pake/cake (n=%d):\n", n);
  printf("\tmean: %f ms\n", result->mean);
  printf("\tmedian: %f ms\n", result->median);
  printf("\tmin: %f ms\n", result->min);
  printf("\tmax: %f ms\n", result->max);
  printf("\tstd dev: %f ms\n", result->std_dev);
  printf("\tfail count: %d\n", result->fail_count);
}

void benchmark_ocake(int n) {
  benchmark_result* result = malloc(sizeof(benchmark_result));
  result->mean = 0;
  result->median = 0;
  result->min = 0;
  result->max = 0;
  result->std_dev = 0;
  result->fail_count = 0;

  char password[] = "password1234";
  char alice_name[] = "finch";
  char bob_name[] = "reese";

  double* times = malloc(sizeof(double) * n);
  for (int i = 0; i < n; i++) {
    uint32_t ssid = rand();

    clock_t start = clock();
    int ret = run_alice_bob_ocake(ssid, password, alice_name, bob_name);
    clock_t end = clock();

    if (ret < 0) {
      times[i] = -1;
      fprintf(stderr, "run_alice_bob_ocake failed with %d\n", ret);
      continue;
    }

    times[i] = (double)(end - start) / CLOCKS_PER_SEC * 1000;
  }

  compute_statistics(times, n, result);

  free(times);

  printf("Benchmark results for pake/ocake (n=%d):\n", n);
  printf("\tmean: %f ms\n", result->mean);
  printf("\tmedian: %f ms\n", result->median);
  printf("\tmin: %f ms\n", result->min);
  printf("\tmax: %f ms\n", result->max);
  printf("\tstd dev: %f ms\n", result->std_dev);
  printf("\tfail count: %d\n", result->fail_count);
}

int main(int argc, char** argv) {
  srand(time(NULL));

  if (argc != 2) {
    fprintf(stderr, "usage: %s n\n", argv[0]);
    return 1;
  }

  int n = atoi(argv[1]);

  if (n == 0) {
    fprintf(stderr, "invalid argument n\n");
    return 1;
  }

  benchmark_cake(n);
  benchmark_ocake(n);

  return 0;
}
