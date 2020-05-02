#ifndef BLAKE3_CXX_H
#define BLAKE3_CXX_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "blake3/blake3.h"

template <typename Container>
void hashBlake3(const Container& in, std::vector<uint8_t>& out)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, in.data(), in.size());

    if (out.empty() || out.size() < BLAKE3_OUT_LEN)
        out.resize(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, &out[0], BLAKE3_OUT_LEN);
}

template <>
void hashBlake3(const std::string& in, std::vector<uint8_t>& out);

template <typename Container>
void hashBlake3_keyed(const Container& data, const Container& key, std::vector<uint8_t>& out)
{
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key.data());
    blake3_hasher_update(&hasher, data.data(), data.size());

    if (out.empty() || out.size() < BLAKE3_OUT_LEN)
        out.resize(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, &out[0], BLAKE3_OUT_LEN);
}

template <>
void hashBlake3_keyed(const std::string& data, const std::string& key, std::vector<uint8_t>& out);

template <typename Container>
void hashBlake3_deriveKey(const Container& data, const std::string& context, std::vector<uint8_t>& out)
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, context.data());
    blake3_hasher_update(&hasher, data.data(), data.size());

    if (out.empty() || out.size() < BLAKE3_OUT_LEN)
        out.resize(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, &out[0], BLAKE3_OUT_LEN);
}

template <>
void hashBlake3_deriveKey(const std::string& data, const std::string& context, std::vector<uint8_t>& out);

#endif    // BLAKE3_H
