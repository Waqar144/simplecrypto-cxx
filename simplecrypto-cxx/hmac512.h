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
#ifndef HMAC512_H
#define HMAC512_H

#include "sha256.h"
#include "sha512.h"
#include <array>

#include <cstdint>

typedef struct _HMAC_SHA256_CTX {
    std::array<uint8_t, SHA256_BLOCK_LENGTH> o_key_pad;
    //    uint8_t o_key_pad[SHA256_BLOCK_LENGTH];
    SHA256_CTX ctx;
} HMAC_SHA256_CTX;

typedef struct _HMAC_SHA512_CTX {
    std::array<uint8_t, SHA512_BLOCK_LENGTH> o_key_pad;
    //    uint8_t o_key_pad[SHA512_BLOCK_LENGTH];
    SHA512_CTX ctx;
} HMAC_SHA512_CTX;

void hmac_sha256_Init(HMAC_SHA256_CTX* hctx, const uint8_t* key, const uint32_t keylen);
void hmac_sha256_Update(HMAC_SHA256_CTX* hctx, const uint8_t* msg, const uint32_t msglen);
void hmac_sha256_Final(HMAC_SHA256_CTX* hctx, uint8_t* hmac);
void hmac_sha256(
    const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac);
void hmac_sha256_prepare(
    const uint8_t* key, const uint32_t keylen, uint32_t* opad_digest, uint32_t* ipad_digest);

void hmac_sha512_Init(HMAC_SHA512_CTX* hctx, const uint8_t* key, const uint32_t keylen);
void hmac_sha512_Update(HMAC_SHA512_CTX* hctx, const uint8_t* msg, const uint32_t msglen);
void hmac_sha512_Final(HMAC_SHA512_CTX* hctx, uint8_t* hmac);
void hmac_sha512(
    const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac);
void hmac_sha512_prepare(
    const uint8_t* key,
    const uint32_t keylen,
    std::array<uint64_t, 8>& opad_digest,
    std::array<uint64_t, 8>& ipad_digest);

#endif // HMAC512_H
