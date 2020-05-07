#ifndef SHA224_H
#define SHA224_H

#include <array>
#include <cstdint>
#include <vector>

static constexpr size_t SHA224_BLOCK_LENGTH = 64;
static constexpr size_t SHA224_RAW_BYTES_LENGTH = 28;
static constexpr size_t SHA224_HEX_STRING_LENGTH = (SHA224_RAW_BYTES_LENGTH * 2 + 1);

struct SHA224_CTX {
    std::array<uint32_t, SHA224_BLOCK_LENGTH / sizeof(uint32_t)> buffer = {0};
    std::array<uint32_t, 8> state;
    uint64_t bitcount = 0;
};

void sha224_Init(SHA224_CTX* context);
void sha224_Transform(
    const std::array<uint32_t, 8>& state_in,
    const std::array<uint32_t, SHA224_BLOCK_LENGTH / sizeof(uint32_t)>& data,
    uint32_t* state_out);
// void sha256_Transform(const uint32_t* state_in, const uint32_t* data, uint32_t* state_out);
void sha224_Update(SHA224_CTX* context, const uint8_t* data, size_t len);
void sha224_Final(SHA224_CTX* context, uint8_t digest[]);

/**
 * @brief takes `data` as input and outputs `digest` as hash
 * @param data
 * @param len
 * @param digest
 */
void sha224(const uint8_t* data, size_t len, uint8_t digest[SHA224_RAW_BYTES_LENGTH]);

/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <typename In>
std::vector<uint8_t> sha224(const In& data)
{
    std::vector<uint8_t> output(SHA224_RAW_BYTES_LENGTH);

    using Type = typename std::decay<decltype(*data.begin())>::type;
    static_assert(std::is_same<Type, uint8_t>::value, "Container should have uint8_t value type");

    sha224(data.data(), data.size(), &output[0]);

    return output;
}

/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <>
std::vector<uint8_t> sha224<std::string>(const std::string& data);

#endif // SHA224_H
