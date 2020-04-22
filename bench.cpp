#include <benchmark/benchmark.h>

#include "hmac.h"
#include "pbkdf2.h"
#include "sha256.h"
#include "sha512.h"

std::vector<uint8_t> strToVec(const std::string& s)
{
    return std::vector<uint8_t>{s.begin(), s.end()};
}

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

static void BM_SHA256CPP(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA256_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        sha256(s);
    }
}

static void BM_SHA512CPP(benchmark::State& state)
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        sha512(s);
    }
}

static void BM_SHA256CPP_VEC(benchmark::State& state)
{
    auto s = strToVec("hello");
    std::vector<uint8_t> out(SHA256_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        sha256(s);
    }
}

static void BM_SHA512CPP_VEC(benchmark::State& state)
{
    auto s = strToVec("hello");
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        sha512(s);
    }
}

static void BM_HMACSHA512(benchmark::State& state)
{
    std::string key = "abc";
    std::string msg = "abc";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        hmac_sha512(
            reinterpret_cast<const uint8_t*>(key.c_str()),
            key.size(),
            reinterpret_cast<const uint8_t*>(msg.c_str()),
            msg.size(),
            &out[0]);
    }
}

static void BM_HMACSHA256(benchmark::State& state)
{
    std::string key = "abc";
    std::string msg = "abc";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        hmac_sha256(
            reinterpret_cast<const uint8_t*>(key.c_str()),
            key.size(),
            reinterpret_cast<const uint8_t*>(msg.c_str()),
            msg.size(),
            &out[0]);
    }
}

static void BM_HMACSHA512CPP(benchmark::State& state)
{
    std::string key = "abc";
    std::string msg = "abc";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        hashHmac(HMAC_ALGO::Sha512, key, msg);
    }
}

static void BM_HMACSHA256CPP(benchmark::State& state)
{
    std::string key = "abc";
    std::string msg = "abc";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        hashHmac(HMAC_ALGO::Sha256, key, msg);
    }
}


static void BM_HMACSHA512CPP_VEC(benchmark::State& state)
{
    auto key = strToVec("abc");
    auto msg = strToVec("abc");
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        hashHmac(HMAC_ALGO::Sha512, key, msg);
    }
}

static void BM_HMACSHA256CPP_VEC(benchmark::State& state)
{
    auto key = strToVec("abc");
    auto msg = strToVec("abc");
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    for (auto _ : state) {
        hashHmac(HMAC_ALGO::Sha256, key, msg);
    }
}


BENCHMARK(BM_SHA256);
BENCHMARK(BM_SHA512);
BENCHMARK(BM_SHA256CPP);
BENCHMARK(BM_SHA512CPP);
BENCHMARK(BM_SHA256CPP_VEC);
BENCHMARK(BM_SHA512CPP_VEC);
BENCHMARK(BM_HMACSHA512);
BENCHMARK(BM_HMACSHA256);
BENCHMARK(BM_HMACSHA512CPP);
BENCHMARK(BM_HMACSHA256CPP);
BENCHMARK(BM_HMACSHA512CPP_VEC);
BENCHMARK(BM_HMACSHA256CPP_VEC);

BENCHMARK_MAIN();
