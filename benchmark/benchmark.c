#include "benchmark.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

int compare_double(const void* a, const void* b) {
  return (*(double*)a > *(double*)b) - (*(double*)a < *(double*)b);
}

void compute_statistics(const double* times, int n, benchmark_result* result) {
  double sum = 0;
  double sum_squared = 0;
  double min = times[0];
  double max = times[0];
  int fail_count = 0;

  for (int i = 0; i < n; i++) {
    if (times[i] < 0) {
      fail_count++;
      continue;
    }

    sum += times[i];
    sum_squared += times[i] * times[i];

    if (times[i] < min) {
      min = times[i];
    }

    if (times[i] > max) {
      max = times[i];
    }
  }

  result->mean = sum / (n - fail_count);
  result->min = min;
  result->max = max;
  result->fail_count = fail_count;

  if (fail_count == n) {
    result->median = -1;
    result->std_dev = -1;
    return;
  }

  double mean_squared = result->mean * result->mean;
  double variance = (sum_squared / (n - fail_count)) - mean_squared;
  result->std_dev = sqrt(variance);

  double* times_copy = malloc(sizeof(double) * n);
  memcpy(times_copy, times, sizeof(double) * n);
  qsort(times_copy, n, sizeof(double), compare_double);

  if ((n - fail_count) % 2 == 0) {
    result->median = (times_copy[(n - fail_count) / 2 - 1] +
                      times_copy[(n - fail_count) / 2]) /
                     2;
  } else {
    result->median = times_copy[(n - fail_count) / 2];
  }

  free(times_copy);
}
