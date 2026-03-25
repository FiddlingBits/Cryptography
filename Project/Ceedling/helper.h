/****************************************************************************************************
 * Pragmas
 ****************************************************************************************************/

#pragma once

/****************************************************************************************************
 * Includes
 ****************************************************************************************************/

#include <stdint.h>
#include <stdio.h>

/****************************************************************************************************
 * Type Definitions
 ****************************************************************************************************/

typedef enum
{
    /* Secure Hash Algorithm 2 (SHA-2) */
    HELPER_HASH_ALGORITHM_SHA2_224,
    HELPER_HASH_ALGORITHM_SHA2_256,
    HELPER_HASH_ALGORITHM_SHA2_384,
    HELPER_HASH_ALGORITHM_SHA2_512,

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
extern void helper_getRandomBuffer(uint8_t * const buffer, const size_t BufferLength);
extern void helper_verifyHash(const uint8_t * const Input, const size_t InputLength, const helper_hashAlgorithm_t HashAlgorithm, const uint8_t * const ExpectedHash, const size_t ExpectedHashLength);
