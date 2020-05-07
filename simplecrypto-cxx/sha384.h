#ifndef SHA384_H
#define SHA384_H

#include <array>
#include <cstdint>
#include <vector>

static constexpr size_t SHA384_BLOCK_LENGTH = 128;
static constexpr size_t SHA384_RAW_BYTES_LENGTH = 48;
static constexpr size_t SHA384_DIGEST_STRING_LENGTH = SHA384_RAW_BYTES_LENGTH * 2 + 1;

struct SHA384_CTX {
    std::array<uint64_t, 8> state = {0};
    std::array<uint64_t, 2> bitcount = {0};
    std::array<uint64_t, SHA384_BLOCK_LENGTH / sizeof(uint64_t)> buffer = {0};
};

void sha384_Init(SHA384_CTX* context);
void sha384_Transform(
    const std::array<uint64_t, 8>& state_in,
    const std::array<uint64_t, SHA384_BLOCK_LENGTH / sizeof(uint64_t)>& data,
    uint64_t* state_out);
void sha384_Update(SHA384_CTX* context, const uint8_t*, size_t);
void sha384_Final(SHA384_CTX* context, uint8_t out[SHA384_RAW_BYTES_LENGTH]);

/**
 * @brief takes `data` as input and outputs `out` as hash in raw bytes
 * @param data
 * @param len
 * @param out
 */
void sha384(const uint8_t* in, size_t inSize, uint8_t out[SHA384_RAW_BYTES_LENGTH]);


/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <typename In>
std::vector<uint8_t> sha384(const In& data)
{
    std::vector<uint8_t> output(SHA384_RAW_BYTES_LENGTH);

    using Type = typename std::decay<decltype(*data.begin())>::type;
    static_assert(std::is_same<Type, uint8_t>::value, "Container should have uint8_t value type");

    sha384(data.data(), data.size(), &output[0]);

    return output;
}

/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <>
std::vector<uint8_t> sha384<std::string>(const std::string& data);

#endif // SHA384_H
