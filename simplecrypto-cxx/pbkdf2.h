#ifndef PBKDF2_H
#define PBKDF2_H

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
#include "sha256.h"
#include "sha512.h"

typedef struct _PBKDF2_HMAC_SHA256_CTX {
    uint32_t odig[SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t)];
    uint32_t idig[SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t)];
    uint32_t f[SHA256_RAW_BYTES_LENGTH / sizeof(uint32_t)];
    uint32_t g[SHA256_BLOCK_LENGTH / sizeof(uint32_t)];
    char first;
} PBKDF2_HMAC_SHA256_CTX;

typedef struct _PBKDF2_HMAC_SHA512_CTX {
    std::array<uint64_t, SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t)> odig;
    std::array<uint64_t, SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t)> idig;
    std::array<uint64_t, SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t)> f;
    std::array<uint64_t, SHA512_BLOCK_LENGTH / sizeof(uint64_t)> g;
    char first;
} PBKDF2_HMAC_SHA512_CTX;

void pbkdf2_hmac_sha256_Init(
    PBKDF2_HMAC_SHA256_CTX* pctx, const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen);
void pbkdf2_hmac_sha256_Update(PBKDF2_HMAC_SHA256_CTX* pctx, uint32_t iterations);
void pbkdf2_hmac_sha256_Final(PBKDF2_HMAC_SHA256_CTX* pctx, uint8_t* key);
void pbkdf2_hmac_sha256(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key);

void pbkdf2_hmac_sha512_Init(
    PBKDF2_HMAC_SHA512_CTX* pctx, const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen);
void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX* pctx, uint32_t iterations);
void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX* pctx, uint8_t* key);
void pbkdf2_hmac_sha512(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key);

#endif // PBKDF2_H
