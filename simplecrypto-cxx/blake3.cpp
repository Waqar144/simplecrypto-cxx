#include "blake3.h"

template <>
void hashBlake3(const std::string& in, std::vector<uint8_t>& out)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t*)in.data(), in.size());

    if (out.empty() || out.size() < BLAKE3_OUT_LEN)
        out.resize(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, &out[0], BLAKE3_OUT_LEN);
}
