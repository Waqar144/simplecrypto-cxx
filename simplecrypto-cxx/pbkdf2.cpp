/**
 * Copyright (c) 2000-2001 Aaron D. Gifford
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2020 Waqar Ahmed
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "pbkdf2.h"

#include "hmac.h"

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

template <>
void pbkdf2_hmac_sha256_Init(
    PBKDF2_CTX<uint32_t, SHA256_BLOCK_LENGTH, SHA256_RAW_BYTES_LENGTH>* pctx,
    const uint8_t* pass,
    int passlen,
    const uint8_t* salt,
    int saltlen)
{
    SHA256_CTX ctx;
    uint32_t blocknr = 1;
#if BYTE_ORDER == LITTLE_ENDIAN
    blocknr = Reverse32(blocknr);
#endif

    hmac_sha256_prepare(pass, passlen, pctx->odig.data(), pctx->idig.data());
    memset(pctx->g.data(), 0, sizeof(pctx->g));
    pctx->g[8] = 0x80000000;
    pctx->g[15] = (SHA256_BLOCK_LENGTH + SHA256_RAW_BYTES_LENGTH) * 8;

    memcpy(ctx.state.data(), pctx->idig.data(), sizeof(pctx->idig));
    ctx.bitcount = SHA256_BLOCK_LENGTH * 8;
    sha256_Update(&ctx, salt, saltlen);
    sha256_Update(&ctx, (uint8_t*)&blocknr, sizeof(blocknr));
    sha256_Final(&ctx, (uint8_t*)pctx->g.data());
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t); k++) {
        pctx->g[k] = Reverse32(pctx->g[k]);
    }
#endif
    sha256_Transform(pctx->odig, pctx->g, pctx->g.data());
    memcpy(pctx->f.data(), pctx->g.data(), SHA256_RAW_BYTES_LENGTH);
    pctx->first = 1;
}

template <>
void pbkdf2_hmac_sha256_Update(
    PBKDF2_CTX<uint32_t, SHA256_BLOCK_LENGTH, SHA256_RAW_BYTES_LENGTH>* pctx, uint32_t iterations)
{
    for (uint32_t i = pctx->first; i < iterations; i++) {
        sha256_Transform(pctx->idig, pctx->g, pctx->g.data());
        sha256_Transform(pctx->odig, pctx->g, pctx->g.data());
        for (uint32_t j = 0; j < SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t); j++) {
            pctx->f[j] ^= pctx->g[j];
        }
    }
    pctx->first = 0;
}

template <>
void pbkdf2_hmac_sha256_Final(
    PBKDF2_CTX<uint32_t, SHA256_BLOCK_LENGTH, SHA256_RAW_BYTES_LENGTH>* pctx, uint8_t* key)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t); k++) {
        pctx->f[k] = Reverse32(pctx->f[k]);
    }
#endif
    memcpy(key, pctx->f.data(), SHA256_RAW_BYTES_LENGTH);
    std::memset(pctx, 0, sizeof(PBKDF2_CTX<uint32_t, SHA256_BLOCK_LENGTH, SHA256_RAW_BYTES_LENGTH>));
}

void pbkdf2_hmac_sha256(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key)
{
    PBKDF2_CTX<uint32_t, SHA256_BLOCK_LENGTH, SHA256_RAW_BYTES_LENGTH> pctx;
    pbkdf2_hmac_sha256_Init(&pctx, pass, passlen, salt, saltlen);
    pbkdf2_hmac_sha256_Update(&pctx, iterations);
    pbkdf2_hmac_sha256_Final(&pctx, key);
}

template <>
void pbkdf2_hmac_sha512_Init(
    PBKDF2_CTX<uint64_t, SHA512_BLOCK_LENGTH, SHA512_RAW_BYTES_LENGTH>* pctx,
    const uint8_t* pass,
    int passlen,
    const uint8_t* salt,
    int saltlen)
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
    }
#endif
    sha512_Transform(pctx->odig, pctx->g, pctx->g.data());
    memcpy(pctx->f.data(), pctx->g.data(), SHA512_RAW_BYTES_LENGTH);
    pctx->first = 1;
}

template <>
void pbkdf2_hmac_sha512_Update(
    PBKDF2_CTX<uint64_t, SHA512_BLOCK_LENGTH, SHA512_RAW_BYTES_LENGTH>* pctx, uint32_t iterations)
{
    for (uint32_t i = pctx->first; i < iterations; i++) {
        sha512_Transform(pctx->idig, pctx->g, pctx->g.data());
        sha512_Transform(pctx->odig, pctx->g, pctx->g.data());
        for (uint32_t j = 0; j < SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t); j++) {
            pctx->f[j] ^= pctx->g[j];
        }
    }
    pctx->first = 0;
}

template <>
void pbkdf2_hmac_sha512_Final(
    PBKDF2_CTX<uint64_t, SHA512_BLOCK_LENGTH, SHA512_RAW_BYTES_LENGTH>* pctx, uint8_t* key)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    for (uint32_t k = 0; k < SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t); k++) {
        pctx->f[k] = reverse64(pctx->f[k]);
    }
#endif
    memcpy(key, pctx->f.data(), SHA512_RAW_BYTES_LENGTH);
    std::memset(pctx, 0, sizeof(PBKDF2_CTX<uint64_t, SHA512_BLOCK_LENGTH, SHA512_RAW_BYTES_LENGTH>));
}

void pbkdf2_hmac_sha512(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key)
{
    PBKDF2_CTX<uint64_t, SHA512_BLOCK_LENGTH, SHA512_RAW_BYTES_LENGTH> pctx;
    pbkdf2_hmac_sha512_Init(&pctx, pass, passlen, salt, saltlen);
    pbkdf2_hmac_sha512_Update(&pctx, iterations);
    pbkdf2_hmac_sha512_Final(&pctx, key);
}

template <>
std::vector<uint8_t> hashPbkdf2<std::string>(
    Algo algo, const std::string& pass, const std::string& salt, uint32_t iterations, size_t outKeySize)
{
    if (outKeySize <= 0) {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> outKey(outKeySize);
    switch (algo) {
    case Algo::SHA256:
        pbkdf2_hmac_sha256(
            reinterpret_cast<const uint8_t*>(pass.c_str()),
            pass.size(),
            reinterpret_cast<const uint8_t*>(salt.c_str()),
            salt.size(),
            iterations,
            &outKey[0]);
        break;
    case Algo::SHA512:
        pbkdf2_hmac_sha512(
            reinterpret_cast<const uint8_t*>(pass.c_str()),
            pass.size(),
            reinterpret_cast<const uint8_t*>(salt.c_str()),
            salt.size(),
            iterations,
            &outKey[0]);
        break;
    }
    return outKey;
}
