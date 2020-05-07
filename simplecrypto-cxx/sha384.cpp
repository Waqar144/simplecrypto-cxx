#include "sha384.h"

#include <cstring>
#include <string>

static constexpr size_t SHA384_SHORT_BLOCK_LENGTH = SHA384_BLOCK_LENGTH - 16;

static constexpr std::array<uint64_t, 80> K512 = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#if BYTE_ORDER == LITTLE_ENDIAN
static constexpr uint64_t inline reverse64(uint64_t w)
{
    w = (w >> 32) | (w << 32);
    w = ((w & 0xff00ff00ff00ff00ULL) >> 8) | ((w & 0x00ff00ff00ff00ffULL) << 8);
    w = ((w & 0xffff0000ffff0000ULL) >> 16) | ((w & 0x0000ffff0000ffffULL) << 16);
    return w;
}
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

/*
 * Function for incrementally adding the unsigned 64-bit integer n to the
 * unsigned 128-bit integer (represented using a two-element array of
 * 64-bit words):
 */
static inline void addInc128(std::array<uint64_t, 2>& t_128, uint64_t n)
{
    t_128[0] += n;
    if (t_128.at(0) < n) {
        ++t_128[1];
    }
}

// clang-format off
static constexpr uint64_t inline Ch(uint64_t x, uint64_t y, uint64_t z) { return z ^ (x & (y ^ z)); }
static constexpr uint64_t inline Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (z & (x | y)); }
static constexpr uint64_t inline Sigma0(uint64_t x) { return (x >> 28 | x << 36) ^ (x >> 34 | x << 30) ^ (x >> 39 | x << 25); }
static constexpr uint64_t inline Sigma1(uint64_t x) { return (x >> 14 | x << 50) ^ (x >> 18 | x << 46) ^ (x >> 41 | x << 23); }
static constexpr uint64_t inline sigma0(uint64_t x) { return (x >> 1 | x << 63) ^ (x >> 8 | x << 56) ^ (x >> 7); }
static constexpr uint64_t inline sigma1(uint64_t x) { return (x >> 19 | x << 45) ^ (x >> 61 | x << 3) ^ (x >> 6); }
// clang-format on

void sha384_Init(SHA384_CTX* context)
{
    if (context == nullptr) {
        return;
    }
    context->state[0] = 0xcbbb9d5dc1059ed8ULL;
    context->state[1] = 0x629a292a367cd507ULL;
    context->state[2] = 0x9159015a3070dd17ULL;
    context->state[3] = 0x152fecd8f70e5939ULL;
    context->state[4] = 0x67332667ffc00b31ULL;
    context->state[5] = 0x8eb44a8768581511ULL;
    context->state[6] = 0xdb0c2e0d64f98fa7ULL;
    context->state[7] = 0x47b5481dbefa4fa4ULL;
}

void sha384_Transform(
    const std::array<uint64_t, 8>& state_in,
    const std::array<uint64_t, SHA384_BLOCK_LENGTH / sizeof(uint64_t)>& data,
    //                      std::array<uint64_t, 8>& state_out)
    uint64_t* state_out)
{
    /* Initialize registers with the prev. intermediate value */
    uint64_t a = state_in[0];
    uint64_t b = state_in[1];
    uint64_t c = state_in[2];
    uint64_t d = state_in[3];
    uint64_t e = state_in[4];
    uint64_t f = state_in[5];
    uint64_t g = state_in[6];
    uint64_t h = state_in[7];

    std::array<uint64_t, 16> W512;
    std::copy(data.cbegin(), data.cbegin() + 16, W512.begin());

    uint64_t T1{}, T2{};

    int j = 0;
    do {
        /* Apply the SHA-512 compression function to update a..h with copy */
        T1 = h + Sigma1(e) + Ch(e, f, g) + K512[j] + W512.at(j);
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        ++j;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        uint64_t s0 = W512[(j + 1) & 0x0f];
        s0 = sigma0(s0);
        uint64_t s1 = W512[(j + 14) & 0x0f];
        s1 = sigma1(s1);

        /* Apply the SHA-512 compression function to update a..h */
        T1 = h + Sigma1(e) + Ch(e, f, g) + K512[j] +
            (W512[j & 0x0f] += s1 + W512[(j + 9) & 0x0f] + s0);
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        ++j;
    } while (j < 80);

    /* Compute the current intermediate hash value */
    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
    state_out[5] = state_in[5] + f;
    state_out[6] = state_in[6] + g;
    state_out[7] = state_in[7] + h;
}

void sha384_Update(SHA384_CTX* context, const uint8_t* data, size_t len)
{
    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    uint32_t usedspace = (context->bitcount[0] >> 3) % SHA384_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        unsigned int freespace = SHA384_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            std::memcpy(
                reinterpret_cast<uint8_t*>(context->buffer.data()) + usedspace, data, freespace);
            addInc128(context->bitcount, freespace << 3);
            len -= freespace;
            data += freespace;
#if BYTE_ORDER == LITTLE_ENDIAN
            /* Convert TO host byte order */
            for (int j = 0; j < 16; ++j) {
                context->buffer[j] = reverse64(context->buffer[j]);
            }
#endif
            sha384_Transform(context->state, context->buffer, context->state.data());
        } else {
            /* The buffer is not yet full */
            std::memcpy(reinterpret_cast<uint8_t*>(context->buffer.data()) + usedspace, data, len);
            addInc128(context->bitcount, len << 3);
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA384_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        std::memcpy(context->buffer.data(), data, SHA384_BLOCK_LENGTH);
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 16; ++j) {
            context->buffer[j] = reverse64(context->buffer[j]);
        }
#endif
        sha384_Transform(context->state, context->buffer, context->state.data());
        addInc128(context->bitcount, SHA384_BLOCK_LENGTH << 3);
        len -= SHA384_BLOCK_LENGTH;
        data += SHA384_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        std::memcpy(context->buffer.data(), data, len);
        addInc128(context->bitcount, len << 3);
    }
}

static void sha384_Last(SHA384_CTX* context)
{
    unsigned int usedspace = (context->bitcount[0] >> 3) % SHA384_BLOCK_LENGTH;
    /* Begin padding with a 1 bit: */
    reinterpret_cast<uint8_t*>(context->buffer.data())[usedspace++] = 0x80;

    if (usedspace > SHA384_SHORT_BLOCK_LENGTH) {
        std::memset(
            reinterpret_cast<uint8_t*>(context->buffer.data()) + usedspace,
            0,
            SHA384_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 16; ++j) {
            context->buffer[j] = reverse64(context->buffer[j]);
        }
#endif
        /* Do second-to-last transform: */
        sha384_Transform(context->state, context->buffer, context->state.data());

        /* And prepare the last transform: */
        usedspace = 0;
    }
    /* Set-up for the last transform: */
    std::memset(
        reinterpret_cast<uint8_t*>(context->buffer.data()) + usedspace,
        0,
        SHA384_SHORT_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
    /* Convert TO host byte order */
    for (int j = 0; j < 14; ++j) {
        context->buffer[j] = reverse64(context->buffer[j]);
    }
#endif
    /* Store the length of input data (in bits): */
    context->buffer[14] = context->bitcount[1];
    context->buffer[15] = context->bitcount[0];

    /* Final transform: */
    sha384_Transform(context->state, context->buffer, context->state.data());
}

void sha384_Final(SHA384_CTX* context, uint8_t digest[])
{
    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != nullptr) {
        sha384_Last(context);

        /* Save the hash data for output: */
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert FROM host byte order */
        for (int j = 0; j < 8; ++j) {
            context->state[j] = reverse64(context->state[j]);
        }
#endif
        std::memcpy(digest, context->state.data(), SHA384_RAW_BYTES_LENGTH);
    }

    /* Zero out state data */
    std::memset(context, 0, sizeof(SHA384_CTX));
}

void sha384(const uint8_t* data, size_t len, uint8_t digest[SHA384_RAW_BYTES_LENGTH])
{
    SHA384_CTX context;
    sha384_Init(&context);
    sha384_Update(&context, data, len);
    sha384_Final(&context, digest);
}

template <>
std::vector<uint8_t> sha384<std::string>(const std::string& data)
{
    std::vector<uint8_t> output(SHA384_RAW_BYTES_LENGTH);
    sha384(reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), &output[0]);
    return output;
}
