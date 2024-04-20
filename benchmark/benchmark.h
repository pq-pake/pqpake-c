#ifndef PQPAKE_BENCHMARK_H
#define PQPAKE_BENCHMARK_H

typedef struct benchmark_result {
  double mean;
  double median;
  double min;
  double max;
  double std_dev;
  int fail_count;
} benchmark_result;

void compute_statistics(const double* times, int n, benchmark_result* result);

#endif  // PQPAKE_BENCHMARK_H
