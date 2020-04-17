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
#ifndef SHA256_H
#define SHA256_H

#include <array>
#include <cstdint>

static constexpr size_t SHA256_BLOCK_LENGTH = 64;
static constexpr size_t SHA256_RAW_BYTES_LENGTH = 32;
static constexpr size_t SHA256_HEX_STRING_LENGTH = (SHA256_RAW_BYTES_LENGTH * 2 + 1);

struct SHA256_CTX {
    std::array<uint32_t, SHA256_BLOCK_LENGTH / sizeof(uint32_t)> buffer = {0};
    std::array<uint32_t, 8> state;
    uint64_t bitcount = 0;
};

void sha256_Init(SHA256_CTX* context);
void sha256_Update(SHA256_CTX* context, const uint8_t* data, size_t len);
void sha256_Final(SHA256_CTX* context, uint8_t digest[]);

/**
 * @brief takes `data` as input and outputs `digest` as hash
 * @param data
 * @param len
 * @param digest
 */
void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_RAW_BYTES_LENGTH]);


/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <typename Out>
void sha256(const std::string& data, Out& output)
{
    if (output.size() != SHA256_RAW_BYTES_LENGTH) {
        output.resize(SHA256_RAW_BYTES_LENGTH);
    }


#if __cplusplus == 201103L
    using Type = typename std::decay<decltype(*output.begin())>::type;
#else
    using Type = typename Out::value_type;
#endif
    static_assert(
        std::is_same<Type, uint8_t>::value == true, "Output container should be of uint8_t");

    return sha256(reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), &output[0]);
}

#endif // SHA256_H
