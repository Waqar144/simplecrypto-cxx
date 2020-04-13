#include <benchmark/benchmark.h>

#include "sha2.hpp"

static void BM_SHA256_C(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(32);
    for (auto _ : state)
        sha256_Raw(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
}

static void BM_SHA512_C(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA512_DIGEST_LENGTH);
    for (auto _ : state)
        sha512_Raw(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
}


// Register the function as a benchmark
BENCHMARK(BM_SHA256_C);
BENCHMARK(BM_SHA512_C);

BENCHMARK_MAIN();
