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

#endif    // BLAKE3_H
