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
