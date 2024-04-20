#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "benchmark.h"
#include "ciphertext.h"
#include "constants.h"
#include "kyber1024.h"
#include "publickey.h"

int run_ic_ciphertext(const uint8_t* sym_key, const uint8_t* ct) {
  uint8_t ect[PQPAKE_ECT_SIZE];
  pqpake_ic_ciphertext_encrypt(sym_key, ct, ect);

  uint8_t ct2[PQPAKE_CT_SIZE];
  pqpake_ic_ciphertext_decrypt(sym_key, ect, ct2);

  return 0;
}

int run_ic_publickey(const uint8_t* sym_key, const uint8_t* pk) {
  uint8_t epk[PQPAKE_EPK_SIZE];
  if (pqpake_ic_publickey_encrypt(sym_key, pk, epk) < 0) {
    return -1;
  }

  uint8_t pk2[PQPAKE_PK_SIZE];
  if (pqpake_ic_publickey_decrypt(sym_key, epk, pk2) < 0) {
    return -2;
  }

  return 0;
}

void benchmark_ciphertext(int n) {
  benchmark_result* result = malloc(sizeof(benchmark_result));
  result->mean = 0;
  result->median = 0;
  result->min = 0;
  result->max = 0;
  result->std_dev = 0;
  result->fail_count = 0;

  uint8_t sym_key[PQPAKE_SYM_KEY_SIZE];
  uint8_t ct[PQPAKE_CT_SIZE];

  double* times = malloc(sizeof(double) * n);
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < PQPAKE_SYM_KEY_SIZE; j++) {
      sym_key[j] = rand();
    }

    for (int j = 0; j < PQPAKE_CT_SIZE; j++) {
      ct[j] = rand();
    }

    clock_t start = clock();
    int ret = run_ic_ciphertext(sym_key, ct);
    clock_t end = clock();

    if (ret < 0) {
      times[i] = -1;
      fprintf(stderr, "run_ic_ciphertext failed with %d\n", ret);
      continue;
    }

    times[i] = (double)(end - start) / CLOCKS_PER_SEC * 1000;
  }

  compute_statistics(times, n, result);

  free(times);

  printf("Benchmark results for ciphertext encrypt/decrypt (n=%d):\n", n);
  printf("\tmean: %f ms\n", result->mean);
  printf("\tmedian: %f ms\n", result->median);
  printf("\tmin: %f ms\n", result->min);
  printf("\tmax: %f ms\n", result->max);
  printf("\tstd dev: %f ms\n", result->std_dev);
  printf("\tfail count: %d\n", result->fail_count);
}

void benchmark_publickey(int n) {
  benchmark_result* result = malloc(sizeof(benchmark_result));
  result->mean = 0;
  result->median = 0;
  result->min = 0;
  result->max = 0;
  result->std_dev = 0;
  result->fail_count = 0;

  uint8_t sym_key[PQPAKE_SYM_KEY_SIZE];
  uint8_t pk[PQPAKE_PK_SIZE];
  uint8_t sk[PQPAKE_SK_SIZE];

  double* times = malloc(sizeof(double) * n);
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < PQPAKE_SYM_KEY_SIZE; j++) {
      sym_key[j] = rand();
    }

    PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(pk, sk);

    clock_t start = clock();
    int ret = run_ic_publickey(sym_key, pk);
    clock_t end = clock();

    if (ret < 0) {
      times[i] = -1;
      fprintf(stderr, "run_ic_publickey failed with %d\n", ret);
      continue;
    }

    times[i] = (double)(end - start) / CLOCKS_PER_SEC * 1000;
  }

  compute_statistics(times, n, result);

  free(times);

  printf("Benchmark results for publickey encrypt/decrypt (n=%d):\n", n);
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

  benchmark_ciphertext(n);
  benchmark_publickey(n);

  return 0;
}
