#include <benchmark/benchmark.h>

#include "sha256.h"
#include "sha512.h"

static void BM_SHA256(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA256_RAW_BYTES_LENGTH);
    for (auto _ : state)
        sha256(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
}

static void BM_SHA512(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state)
        sha512(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
}


BENCHMARK(BM_SHA256);
BENCHMARK(BM_SHA512);

BENCHMARK_MAIN();
