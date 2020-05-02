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

template <>
void hashBlake3_keyed(const std::string& data, const std::string& key, std::vector<uint8_t>& out)
{
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, (const uint8_t*)key.data());
    blake3_hasher_update(&hasher, (const uint8_t*)data.data(), data.size());

    if (out.empty() || out.size() < BLAKE3_OUT_LEN)
        out.resize(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, &out[0], BLAKE3_OUT_LEN);
}

template <>
void hashBlake3_deriveKey(const std::string& data, const std::string& context, std::vector<uint8_t>& out)
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, context.data());
    blake3_hasher_update(&hasher, (const uint8_t*)data.data(), data.size());

    if (out.empty() || out.size() < BLAKE3_OUT_LEN)
        out.resize(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, &out[0], BLAKE3_OUT_LEN);
}
