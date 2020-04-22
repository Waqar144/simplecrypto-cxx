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

template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
struct PBKDF2_CTX {
    std::array<T, RAW_BYTES_LEN / sizeof(T)> odig;
    std::array<T, RAW_BYTES_LEN / sizeof(T)> idig;
    std::array<T, RAW_BYTES_LEN / sizeof(T)> f;
    std::array<T, BLOCK_LEN / sizeof(T)> g;
    char first;
};

template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
void pbkdf2_hmac_sha256_Init(
    PBKDF2_CTX<T, BLOCK_LEN, RAW_BYTES_LEN>* pctx,
    const uint8_t* pass,
    int passlen,
    const uint8_t* salt,
    int saltlen);
template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
void pbkdf2_hmac_sha256_Update(PBKDF2_CTX<T, BLOCK_LEN, RAW_BYTES_LEN>* pctx, uint32_t iterations);
template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
void pbkdf2_hmac_sha256_Final(PBKDF2_CTX<T, BLOCK_LEN, RAW_BYTES_LEN>* pctx, uint8_t* key);

void pbkdf2_hmac_sha256(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key);

template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
void pbkdf2_hmac_sha512_Init(
    PBKDF2_CTX<T, BLOCK_LEN, RAW_BYTES_LEN>* pctx,
    const uint8_t* pass,
    int passlen,
    const uint8_t* salt,
    int saltlen);
template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
void pbkdf2_hmac_sha512_Update(PBKDF2_CTX<T, BLOCK_LEN, RAW_BYTES_LEN>* pctx, uint32_t iterations);
template <typename T, size_t BLOCK_LEN, size_t RAW_BYTES_LEN>
void pbkdf2_hmac_sha512_Final(PBKDF2_CTX<T, BLOCK_LEN, RAW_BYTES_LEN>* pctx, uint8_t* key);

void pbkdf2_hmac_sha512(
    const uint8_t* pass,
    size_t passlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    uint8_t* key);

enum class Algo : unsigned char { SHA256, SHA512 };

template <typename T>
std::vector<uint8_t> hashPbkdf2(
    Algo algo, const T& pass, const T& salt, uint32_t iterations, size_t outKeySize)
{
    using PassType = typename std::decay<decltype(*pass.begin())>::type;
    using SaltType = typename std::decay<decltype(*salt.begin())>::type;
    static_assert(std::is_same<PassType, uint8_t>::value, "uint8_t allowed only");
    static_assert(std::is_same<SaltType, uint8_t>::value, "uint8_t allowed only");

    if (outKeySize <= 0) {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> outKey(outKeySize);
    switch (algo) {
    case Algo::SHA256:
        pbkdf2_hmac_sha256(
            pass.data(), pass.size(), salt.data(), salt.size(), iterations, &outKey[0]);
        break;
    case Algo::SHA512:
        pbkdf2_hmac_sha512(
            pass.data(), pass.size(), salt.data(), salt.size(), iterations, &outKey[0]);
        break;
    }
    return outKey;
}

template <>
std::vector<uint8_t> hashPbkdf2<std::string>(
    Algo algo, const std::string& pass, const std::string& salt, uint32_t iterations, size_t outKeySize);

#endif // PBKDF2_H
