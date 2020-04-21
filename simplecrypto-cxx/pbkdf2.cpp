#include "pbkdf2.h"

#include "hmac512.h"
//#include "memzero.h"
//#include "sha2.hpp"

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

static constexpr inline uint32_t Reverse32(uint32_t w)
{
    w = (w >> 16) | (w << 16);
    return (w & 0xff00ff00UL) >> 8 | (w & 0x00ff00ffUL) << 8;
}
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

void pbkdf2_hmac_sha256_Init(
    PBKDF2_HMAC_SHA256_CTX* pctx, const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen)
{
    SHA256_CTX ctx;
    uint32_t blocknr = 1;
#if BYTE_ORDER == LITTLE_ENDIAN
    blocknr = Reverse32(blocknr);
#endif

    hmac_sha256_prepare(pass, passlen, pctx->odig, pctx->idig);
    memset(pctx->g, 0, sizeof(pctx->g));
    pctx->g[8] = 0x80000000;
    pctx->g[15] = (SHA256_BLOCK_LENGTH + SHA256_RAW_BYTES_LENGTH) * 8;

    memcpy(ctx.state.data(), pctx->idig, sizeof(pctx->idig));
    ctx.bitcount = SHA256_BLOCK_LENGTH * 8;
    sha256_Update(&ctx, salt, saltlen);
    sha256_Update(&ctx, (uint8_t*)&blocknr, sizeof(blocknr));
    sha256_Final(&ctx, (uint8_t*)pctx->g);
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t); k++) {
        pctx->g[k] = Reverse32(pctx->g[k]);
    }
#endif
    sha256_Transform(pctx->odig, pctx->g, pctx->g);
    memcpy(pctx->f, pctx->g, SHA256_RAW_BYTES_LENGTH);
    pctx->first = 1;
}

void pbkdf2_hmac_sha256_Update(PBKDF2_HMAC_SHA256_CTX* pctx, uint32_t iterations)
{
    for (uint32_t i = pctx->first; i < iterations; i++) {
        sha256_Transform(pctx->idig, pctx->g, pctx->g);
        sha256_Transform(pctx->odig, pctx->g, pctx->g);
        for (uint32_t j = 0; j < SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t); j++) {
            pctx->f[j] ^= pctx->g[j];
        }
    }
    pctx->first = 0;
}

void pbkdf2_hmac_sha256_Final(PBKDF2_HMAC_SHA256_CTX* pctx, uint8_t* key)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t); k++) {
        pctx->f[k] = Reverse32(pctx->f[k]);
        //        REVERSE32(pctx->f[k], pctx->f[k]);
    }
#endif
    memcpy(key, pctx->f, SHA256_RAW_BYTES_LENGTH);
    std::memset(pctx, 0, sizeof(PBKDF2_HMAC_SHA256_CTX));
    //    memzero(pctx, sizeof(PBKDF2_HMAC_SHA256_CTX));
}

void pbkdf2_hmac_sha256(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key)
{
    PBKDF2_HMAC_SHA256_CTX pctx;
    pbkdf2_hmac_sha256_Init(&pctx, pass, passlen, salt, saltlen);
    pbkdf2_hmac_sha256_Update(&pctx, iterations);
    pbkdf2_hmac_sha256_Final(&pctx, key);
}

void pbkdf2_hmac_sha512_Init(
    PBKDF2_HMAC_SHA512_CTX* pctx, const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen)
{
    SHA512_CTX ctx;
    uint32_t blocknr = 1;
#if BYTE_ORDER == LITTLE_ENDIAN
    blocknr = Reverse32(blocknr);
#endif

    hmac_sha512_prepare(pass, passlen, pctx->odig, pctx->idig);
    memset(pctx->g.data(), 0, sizeof(pctx->g));
    pctx->g[8] = 0x8000000000000000;
    pctx->g[15] = (SHA512_BLOCK_LENGTH + SHA512_RAW_BYTES_LENGTH) * 8;

    memcpy(ctx.state.data(), pctx->idig.data(), sizeof(pctx->idig));
    ctx.bitcount[0] = SHA512_BLOCK_LENGTH * 8;
    ctx.bitcount[1] = 0;
    sha512_Update(&ctx, salt, saltlen);
    sha512_Update(&ctx, (uint8_t*)&blocknr, sizeof(blocknr));
    sha512_Final(&ctx, (uint8_t*)pctx->g.data());
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t); k++) {
        pctx->g[k] = reverse64(pctx->g[k]);
        //        REVERSE64(pctx->g[k], pctx->g[k]);
    }
#endif
    //    std::array<uint64_t, 8> tmp;
    //    std::copy(pctx->g.begin(), pctx->g.begin() + 8, tmp.begin());
    sha512_Transform(pctx->odig, pctx->g, pctx->g.data());
    //    std::copy(tmp.begin(), tmp.end(), pctx->g.begin());
    memcpy(pctx->f.data(), pctx->g.data(), SHA512_RAW_BYTES_LENGTH);
    pctx->first = 1;
}

void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX* pctx, uint32_t iterations)
{
    for (uint32_t i = pctx->first; i < iterations; i++) {
        //        std::array<uint64_t, 8> tmp;
        //        std::copy(pctx->g.begin(), pctx->g.begin() + 8, tmp.begin());
        sha512_Transform(pctx->idig, pctx->g, pctx->g.data());
        //        std::copy(tmp.begin(), tmp.end(), pctx->g.begin());

        //        tmp.fill(0);
        //        std::copy(pctx->g.begin(), pctx->g.begin() + 8, tmp.begin());
        sha512_Transform(pctx->odig, pctx->g, pctx->g.data());
        //        std::copy(tmp.begin(), tmp.end(), pctx->g.begin());
        for (uint32_t j = 0; j < SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t); j++) {
            pctx->f[j] ^= pctx->g[j];
        }
    }
    pctx->first = 0;
}

void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX* pctx, uint8_t* key)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t); k++) {
        pctx->f[k] = reverse64(pctx->f[k]);
        //        REVERSE64(pctx->f[k], pctx->f[k]);
    }
#endif
    memcpy(key, pctx->f.data(), SHA512_RAW_BYTES_LENGTH);
    std::memset(pctx, 0, sizeof(PBKDF2_HMAC_SHA512_CTX));
    //    memzero(pctx, sizeof(PBKDF2_HMAC_SHA512_CTX));
}

void pbkdf2_hmac_sha512(
    const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen, uint32_t iterations, uint8_t* key)
{
    PBKDF2_HMAC_SHA512_CTX pctx;
    pbkdf2_hmac_sha512_Init(&pctx, pass, passlen, salt, saltlen);
    pbkdf2_hmac_sha512_Update(&pctx, iterations);
    pbkdf2_hmac_sha512_Final(&pctx, key);
}
