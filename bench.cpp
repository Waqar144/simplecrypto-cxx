#include <benchmark/benchmark.h>

#include "sha256.h"

static void BM_SHA256(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(32);
    for (auto _ : state)
        sha256(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
}


BENCHMARK(BM_SHA256);

BENCHMARK_MAIN();
