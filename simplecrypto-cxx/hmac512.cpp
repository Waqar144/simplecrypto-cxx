#include "hmac512.h"

//#include "memzero.h"
//#include "options.h"

#include <cstring>
#include <string>

#if BYTE_ORDER == LITTLE_ENDIAN
static constexpr uint64_t inline reverse64(uint64_t w)
{
    w = (w >> 32) | (w << 32);
    w = ((w & 0xff00ff00ff00ff00ULL) >> 8) | ((w & 0x00ff00ff00ff00ffULL) << 8);
    w = ((w & 0xffff0000ffff0000ULL) >> 16) | ((w & 0x0000ffff0000ffffULL) << 16);
    return w;
}
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

const uint32_t sha256_initial_hash_value[8] = {0x6a09e667UL,
                                               0xbb67ae85UL,
                                               0x3c6ef372UL,
                                               0xa54ff53aUL,
                                               0x510e527fUL,
                                               0x9b05688cUL,
                                               0x1f83d9abUL,
                                               0x5be0cd19UL};

void hmac_sha256_Init(HMAC_SHA256_CTX* hctx, const uint8_t* key, const uint32_t keylen)
{
    static uint8_t i_key_pad[SHA256_BLOCK_LENGTH];
    memset(i_key_pad, 0, SHA256_BLOCK_LENGTH);
    if (keylen > SHA256_BLOCK_LENGTH) {
        sha256(key, keylen, i_key_pad);
    } else {
        memcpy(i_key_pad, key, keylen);
    }
    for (size_t i = 0; i < SHA256_BLOCK_LENGTH; i++) {
        hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
        i_key_pad[i] ^= 0x36;
    }
    sha256_Init(&(hctx->ctx));
    sha256_Update(&(hctx->ctx), i_key_pad, SHA256_BLOCK_LENGTH);
    std::memset(i_key_pad, 0, sizeof(i_key_pad));
    //    memzero(i_key_pad, sizeof(i_key_pad));
}

void hmac_sha256_Update(HMAC_SHA256_CTX* hctx, const uint8_t* msg, const uint32_t msglen)
{
    sha256_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha256_Final(HMAC_SHA256_CTX* hctx, uint8_t* hmac)
{
    sha256_Final(&(hctx->ctx), hmac);
    sha256_Init(&(hctx->ctx));
    sha256_Update(&(hctx->ctx), hctx->o_key_pad, SHA256_BLOCK_LENGTH);
    sha256_Update(&(hctx->ctx), hmac, SHA256_RAW_BYTES_LENGTH);
    sha256_Final(&(hctx->ctx), hmac);
    std::memset(hctx, 0, sizeof(HMAC_SHA256_CTX));
    //    memzero(hctx, sizeof(HMAC_SHA256_CTX));
}

void hmac_sha256(
    const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac)
{
    static HMAC_SHA256_CTX hctx;
    hmac_sha256_Init(&hctx, key, keylen);
    hmac_sha256_Update(&hctx, msg, msglen);
    hmac_sha256_Final(&hctx, hmac);
}

void hmac_sha256_prepare(
    const uint8_t* key, const uint32_t keylen, uint32_t* opad_digest, uint32_t* ipad_digest)
{
    static uint32_t key_pad[SHA256_BLOCK_LENGTH / sizeof(uint32_t)];

    std::memset(key_pad, 0, sizeof(key_pad));
    //    memzero(key_pad, sizeof(key_pad));
    if (keylen > SHA256_BLOCK_LENGTH) {
        static SHA256_CTX context;
        sha256_Init(&context);
        sha256_Update(&context, key, keylen);
        sha256_Final(&context, (uint8_t*)key_pad);
    } else {
        memcpy(key_pad, key, keylen);
    }

    /* compute o_key_pad and its digest */
    for (size_t i = 0; i < SHA256_BLOCK_LENGTH / (int)sizeof(uint32_t); i++) {
        uint32_t data;
#if BYTE_ORDER == LITTLE_ENDIAN
        data = reverse64(key_pad[i]);
//        REVERSE32(key_pad[i], data);
#else
        data = key_pad[i];
#endif
        key_pad[i] = data ^ 0x5c5c5c5c;
    }
    sha256_Transform(sha256_initial_hash_value, key_pad, opad_digest);

    /* convert o_key_pad to i_key_pad and compute its digest */
    for (size_t i = 0; i < SHA256_BLOCK_LENGTH / (int)sizeof(uint32_t); i++) {
        key_pad[i] = key_pad[i] ^ 0x5c5c5c5c ^ 0x36363636;
    }
    sha256_Transform(sha256_initial_hash_value, key_pad, ipad_digest);
    std::memset(key_pad, 0, sizeof(key_pad));
}

const std::array<uint64_t, 8> sha512_initial_hash_value = {0x6a09e667f3bcc908ULL,
                                                           0xbb67ae8584caa73bULL,
                                                           0x3c6ef372fe94f82bULL,
                                                           0xa54ff53a5f1d36f1ULL,
                                                           0x510e527fade682d1ULL,
                                                           0x9b05688c2b3e6c1fULL,
                                                           0x1f83d9abfb41bd6bULL,
                                                           0x5be0cd19137e2179ULL};

void hmac_sha512_Init(HMAC_SHA512_CTX* hctx, const uint8_t* key, const uint32_t keylen)
{
    static uint8_t i_key_pad[SHA512_BLOCK_LENGTH];
    memset(i_key_pad, 0, SHA512_BLOCK_LENGTH);
    if (keylen > SHA512_BLOCK_LENGTH) {
        sha512(key, keylen, i_key_pad);
    } else {
        memcpy(i_key_pad, key, keylen);
    }
    for (size_t i = 0; i < SHA512_BLOCK_LENGTH; i++) {
        hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
        i_key_pad[i] ^= 0x36;
    }
    sha512_Init(&(hctx->ctx));
    sha512_Update(&(hctx->ctx), i_key_pad, SHA512_BLOCK_LENGTH);
    std::memset(i_key_pad, 0, sizeof(i_key_pad));
}

void hmac_sha512_Update(HMAC_SHA512_CTX* hctx, const uint8_t* msg, const uint32_t msglen)
{
    sha512_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha512_Final(HMAC_SHA512_CTX* hctx, uint8_t* hmac)
{
    sha512_Final(&(hctx->ctx), hmac);
    sha512_Init(&(hctx->ctx));
    sha512_Update(&(hctx->ctx), hctx->o_key_pad, SHA512_BLOCK_LENGTH);
    sha512_Update(&(hctx->ctx), hmac, SHA512_RAW_BYTES_LENGTH);
    sha512_Final(&(hctx->ctx), hmac);
    std::memset(hctx, 0, sizeof(HMAC_SHA512_CTX));
    //    memzero(hctx, sizeof(HMAC_SHA512_CTX));
}

void hmac_sha512(
    const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac)
{
    HMAC_SHA512_CTX hctx;
    hmac_sha512_Init(&hctx, key, keylen);
    hmac_sha512_Update(&hctx, msg, msglen);
    hmac_sha512_Final(&hctx, hmac);
}

void hmac_sha512_prepare(
    const uint8_t* key, const uint32_t keylen, uint64_t* opad_digest, uint64_t* ipad_digest)
{
    static std::array<uint64_t, SHA512_BLOCK_LENGTH / sizeof(uint64_t)> key_pad;
    static SHA512_CTX context;

    std::memset(key_pad.data(), 0, sizeof(key_pad));
    //    memzero(key_pad, sizeof(key_pad));
    if (keylen > SHA512_BLOCK_LENGTH) {
        sha512_Init(&context);
        sha512_Update(&context, key, keylen);
        sha512_Final(&context, (uint8_t*)key_pad.data());
    } else {
        memcpy(key_pad.data(), key, keylen);
    }

    /* compute o_key_pad and its digest */
    for (size_t i = 0; i < SHA512_BLOCK_LENGTH / (int)sizeof(uint64_t); i++) {
        uint64_t data;
#if BYTE_ORDER == LITTLE_ENDIAN
        data = reverse64(key_pad[i]);
//        REVERSE64(key_pad[i], data);
#else
        data = key_pad[i];
#endif
        key_pad[i] = data ^ 0x5c5c5c5c5c5c5c5c;
    }
    std::array<uint64_t, 8> tmp;
    std::memcpy(tmp.data(), opad_digest, 8);
    sha512_Transform(sha512_initial_hash_value, key_pad, tmp);
    std::memcpy(opad_digest, tmp.data(), 8);

    /* convert o_key_pad to i_key_pad and compute its digest */
    for (size_t i = 0; i < SHA512_BLOCK_LENGTH / (int)sizeof(uint64_t); i++) {
        key_pad[i] = key_pad[i] ^ 0x5c5c5c5c5c5c5c5c ^ 0x3636363636363636;
    }

    std::memcpy(tmp.data(), ipad_digest, 8);
    sha512_Transform(sha512_initial_hash_value, key_pad, tmp);
    std::memcpy(ipad_digest, tmp.data(), 8);
    std::memset(key_pad.data(), 0, sizeof(key_pad));
    //    memzero(key_pad, sizeof(key_pad));
}
