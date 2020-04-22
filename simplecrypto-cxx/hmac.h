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

enum class HMAC_ALGO : unsigned char { Sha256, Sha512 };

template <typename CTX, size_t BLOCK_LEN>
struct HMAC_CTX {
    std::array<uint8_t, BLOCK_LEN> o_key_pad;
    CTX ctx;
};

template <typename CTX, size_t BLOCK_LEN>
void hmac_sha256_Init(HMAC_CTX<CTX, BLOCK_LEN>* hctx, const uint8_t* key, const uint32_t keylen);
template <typename CTX, size_t BLOCK_LEN>
void hmac_sha256_Update(HMAC_CTX<CTX, BLOCK_LEN>* hctx, const uint8_t* msg, const uint32_t msglen);
template <typename CTX, size_t BLOCK_LEN>
void hmac_sha256_Final(HMAC_CTX<CTX, BLOCK_LEN>* hctx, uint8_t* hmac);

void hmac_sha256(
    const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac);
void hmac_sha256_prepare(
    const uint8_t* key, const uint32_t keylen, uint32_t* opad_digest, uint32_t* ipad_digest);

template <typename CTX, size_t BLOCK_LEN>
void hmac_sha512_Init(HMAC_CTX<CTX, BLOCK_LEN>* hctx, const uint8_t* key, const uint32_t keylen);
template <typename CTX, size_t BLOCK_LEN>
void hmac_sha512_Update(HMAC_CTX<CTX, BLOCK_LEN>* hctx, const uint8_t* msg, const uint32_t msglen);
template <typename CTX, size_t BLOCK_LEN>
void hmac_sha512_Final(HMAC_CTX<CTX, BLOCK_LEN>* hctx, uint8_t* hmac);

void hmac_sha512(
    const uint8_t* key, const uint32_t keylen, const uint8_t* msg, const uint32_t msglen, uint8_t* hmac);
void hmac_sha512_prepare(
    const uint8_t* key,
    const uint32_t keylen,
    std::array<uint64_t, 8>& opad_digest,
    std::array<uint64_t, 8>& ipad_digest);

template <typename T>
std::vector<uint8_t> hashHmac(HMAC_ALGO algo, const T& key, const T& msg)
{
    using PassType = typename std::decay<decltype(*key.begin())>::type;
    using SaltType = typename std::decay<decltype(*msg.begin())>::type;
    static_assert(std::is_same<PassType, uint8_t>::value, "uint8_t allowed only");
    static_assert(std::is_same<SaltType, uint8_t>::value, "uint8_t allowed only");

    std::vector<uint8_t> outHmac;
    switch (algo) {
    case HMAC_ALGO::Sha256:
        outHmac.resize(SHA256_RAW_BYTES_LENGTH);
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size(), &outHmac[0]);
        break;
    case HMAC_ALGO::Sha512:
        outHmac.resize(SHA512_RAW_BYTES_LENGTH);
        hmac_sha512(key.data(), key.size(), msg.data(), msg.size(), &outHmac[0]);
        break;
    }
    return outHmac;
}

template <>
std::vector<uint8_t> hashHmac(HMAC_ALGO algo, const std::string& key, const std::string& msg);

#endif // HMAC512_H
