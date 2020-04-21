#ifndef PBKDF2_H
#define PBKDF2_H


//#include "sha2.hpp"
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
    //    std::array<uint64_t, 16> g;
    //    uint64_t odig[SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t)];
    //    uint64_t idig[SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t)];
    //    uint64_t f[SHA512_RAW_BYTES_LENGTH / sizeof(uint64_t)];
    //    uint64_t g[SHA512_BLOCK_LENGTH / sizeof(uint64_t)];
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
    const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen, uint32_t iterations, uint8_t* key);

#endif // PBKDF2_H
