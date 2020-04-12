#include "sha256.h"

#include <cstring>

static constexpr size_t SHA256_SHORT_BLOCK_LENGTH = SHA256_BLOCK_LENGTH - 8;

/* Hash constant words K for SHA-256: */
static constexpr std::array<uint32_t, 64> K256 = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL,
    0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL,
    0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL,
    0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL,
    0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

#if BYTE_ORDER == LITTLE_ENDIAN
static constexpr inline uint32_t Reverse32(uint32_t w)
{
    w = (w >> 16) | (w << 16);
    return (w & 0xff00ff00UL) >> 8 | (w & 0x00ff00ffUL) << 8;
}
#endif

// clang-format off
uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
uint32_t inline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
uint32_t inline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
uint32_t inline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }
// clang-format on


void sha256_Init(SHA256_CTX* context)
{
    if (context == nullptr) {
        return;
    }
    context->state[0] = 0x6a09e667ul;
    context->state[1] = 0xbb67ae85ul;
    context->state[2] = 0x3c6ef372ul;
    context->state[3] = 0xa54ff53aul;
    context->state[4] = 0x510e527ful;
    context->state[5] = 0x9b05688cul;
    context->state[6] = 0x1f83d9abul;
    context->state[7] = 0x5be0cd19ul;
}

void sha256_Transform(const uint32_t* state_in, const uint32_t* data, uint32_t* state_out)
{
    uint32_t a, b, c, d, e, f, g, h, s0, s1;
    uint32_t T1, T2, W256[16];
    int j;

    /* Initialize registers with the prev. intermediate value */
    a = state_in[0];
    b = state_in[1];
    c = state_in[2];
    d = state_in[3];
    e = state_in[4];
    f = state_in[5];
    g = state_in[6];
    h = state_in[7];

    j = 0;
    do {
        /* Apply the SHA-256 compression function to update a..h with copy */
        T1 = h + Sigma1(e) + Ch(e, f, g) + K256[j] + (W256[j] = *data++);
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W256[(j + 1) & 0x0f];
        s0 = sigma0(s0);
        s1 = W256[(j + 14) & 0x0f];
        s1 = sigma1(s1);

        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1(e) + Ch(e, f, g) + K256[j] +
            (W256[j & 0x0f] += s1 + W256[(j + 9) & 0x0f] + s0);
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 64);

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

void sha256_Update(SHA256_CTX* context, const uint8_t* data, size_t len)
{
    unsigned int freespace, usedspace;

    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA256_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            std::memcpy(((uint8_t*)context->buffer) + usedspace, data, freespace);
            context->bitcount += freespace << 3;
            len -= freespace;
            data += freespace;
#if BYTE_ORDER == LITTLE_ENDIAN
            /* Convert TO host byte order */
            for (int j = 0; j < 16; j++) {
                context->buffer[j] = Reverse32(context->buffer[j]);
            }
#endif
            sha256_Transform(context->state, context->buffer, context->state);
        } else {
            /* The buffer is not yet full */
            std::memcpy(((uint8_t*)context->buffer) + usedspace, data, len);
            context->bitcount += len << 3;
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA256_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        std::memcpy(context->buffer, data, SHA256_BLOCK_LENGTH);
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 16; j++) {
            context->buffer[j] = Reverse32(context->buffer[j]);
        }
#endif
        sha256_Transform(context->state, context->buffer, context->state);
        context->bitcount += SHA256_BLOCK_LENGTH << 3;
        len -= SHA256_BLOCK_LENGTH;
        data += SHA256_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        std::memcpy(context->buffer, data, len);
        context->bitcount += len << 3;
    }
}

void sha256_Final(SHA256_CTX* context, uint8_t digest[])
{
    unsigned int usedspace;

    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != nullptr) {
        usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
        /* Begin padding with a 1 bit: */
        ((uint8_t*)context->buffer)[usedspace++] = 0x80;

        if (usedspace > SHA256_SHORT_BLOCK_LENGTH) {
            std::memset(((uint8_t*)context->buffer) + usedspace, 0, SHA256_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
            /* Convert TO host byte order */
            for (int j = 0; j < 16; j++) {
                context->buffer[j] = Reverse32(context->buffer[j]);
            }
#endif
            /* Do second-to-last transform: */
            sha256_Transform(context->state, context->buffer, context->state);

            /* And prepare the last transform: */
            usedspace = 0;
        }
        /* Set-up for the last transform: */
        std::memset(
            ((uint8_t*)context->buffer) + usedspace, 0, SHA256_SHORT_BLOCK_LENGTH - usedspace);

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert TO host byte order */
        for (int j = 0; j < 14; j++) {
            context->buffer[j] = Reverse32(context->buffer[j]);
        }
#endif
        /* Set the bit count: */
        context->buffer[14] = context->bitcount >> 32;
        context->buffer[15] = context->bitcount & 0xffffffff;

        /* Final transform: */
        sha256_Transform(context->state, context->buffer, context->state);

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert FROM host byte order */
        for (int j = 0; j < 8; j++) {
            context->state[j] = Reverse32(context->state[j]);
        }
#endif
        std::memcpy(digest, context->state, SHA256_RAW_BYTES_LENGTH);
    }

    /* Clean up state data: */
    std::memset(context, 0, sizeof(SHA256_CTX));
}

void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_RAW_BYTES_LENGTH])
{
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, data, len);
    sha256_Final(&context, digest);
}
