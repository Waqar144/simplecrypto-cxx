#ifndef SHA256_H
#define SHA256_H

#include <array>
#include <cstdint>

static constexpr size_t SHA256_BLOCK_LENGTH = 64;
static constexpr size_t SHA256_RAW_BYTES_LENGTH = 32;
static constexpr size_t SHA256_HEX_STRING_LENGTH = (SHA256_RAW_BYTES_LENGTH * 2 + 1);

struct SHA256_CTX {
    std::array<uint32_t, SHA256_BLOCK_LENGTH / sizeof(uint32_t)> buffer = {0};
    std::array<uint32_t, 8> state;
    uint64_t bitcount = 0;
};

void sha256_Init(SHA256_CTX* context);
void sha256_Update(SHA256_CTX* context, const uint8_t* data, size_t len);
void sha256_Final(SHA256_CTX* context, uint8_t digest[]);

void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_RAW_BYTES_LENGTH]);

#endif // SHA256_H
