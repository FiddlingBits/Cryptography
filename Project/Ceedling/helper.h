/****************************************************************************************************
 * Pragmas
 ****************************************************************************************************/

#pragma once

/****************************************************************************************************
 * Includes
 ****************************************************************************************************/

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>

/****************************************************************************************************
 * Type Definitions
 ****************************************************************************************************/

typedef enum
{
    /* Secure Hash Algorithm 2 (SHA-2) */
    HELPER_HASH_ALGORITHM_SHA_224,
    HELPER_HASH_ALGORITHM_SHA_256,
    HELPER_HASH_ALGORITHM_SHA_384,
    HELPER_HASH_ALGORITHM_SHA_512,

    /* Secure Hash Algorithm 3 (SHA-3) */
    HELPER_HASH_ALGORITHM_SHA3_224,
    HELPER_HASH_ALGORITHM_SHA3_256,
    HELPER_HASH_ALGORITHM_SHA3_384,
    HELPER_HASH_ALGORITHM_SHA3_512,

    /* End Of List */
    HELPER_HASH_ALGORITHM_COUNT
} helper_hashAlgorithm_t;

/****************************************************************************************************
 * Functions
 ****************************************************************************************************/

extern void helper_convertBufferToHexString(const uint8_t * const Buffer, const size_t BufferLength, char * const hexString);
extern const char *helper_getHashAlgorithmName(const helper_hashAlgorithm_t HashAlgorithm);
extern size_t helper_getHashLength(const helper_hashAlgorithm_t HashAlgorithm);
extern void helper_getMacParameters(const EVP_MD *MessageDigest, OSSL_PARAM parameters[2]);
extern const EVP_MD *helper_getMessageDigest(const helper_hashAlgorithm_t HashAlgorithm);
extern void helper_getRandomBuffer(uint8_t * const buffer, const size_t BufferLength);
extern void helper_verifyHash(const uint8_t * const Input, const size_t InputLength, const helper_hashAlgorithm_t HashAlgorithm, const uint8_t * const ExpectedHash, const size_t ExpectedHashLength);
extern void helper_verifyHmac(const uint8_t * const Input, const size_t InputLength, const uint8_t * const Key, const size_t KeyLength, const helper_hashAlgorithm_t HashAlgorithm, const uint8_t * const ExpectedHmac, const size_t ExpectedHmacLength);
