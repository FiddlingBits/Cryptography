/****************************************************************************************************
 * Includes
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/evp.h>
#include "unity.h"

/****************************************************************************************************
 * Set Up/Tear Down
 ****************************************************************************************************/

void setUp(void)
{
}

void tearDown(void)
{
}

/****************************************************************************************************
 * Tests (Public)
 ****************************************************************************************************/

/*** Hash ***/
void test_hash_1(void)
{
    /*** Hash ***/
    /* Variables */
    EVP_MD_CTX *messageDigestContext;
    uint8_t hash[EVP_MAX_MD_SIZE], input[100];
    helper_hashAlgorithm_t hashAlgorithm;
    size_t hashLength;
    const EVP_MD *MessageDigest;

    /* Calculate Hash */
    for(hashAlgorithm = 0; hashAlgorithm < HELPER_HASH_ALGORITHM_COUNT; hashAlgorithm++)
    {
        /* Set Up */
        messageDigestContext = EVP_MD_CTX_new();
        helper_getRandomBuffer(input, sizeof(input));
        switch(hashAlgorithm)
        {
            case HELPER_HASH_ALGORITHM_SHA2_224:
                hashLength = 28;
                MessageDigest = EVP_sha224();
                break;
            case HELPER_HASH_ALGORITHM_SHA2_256:
                hashLength = 32;
                MessageDigest = EVP_sha256();
                break;
            case HELPER_HASH_ALGORITHM_SHA2_384:
                hashLength = 48;
                MessageDigest = EVP_sha384();
                break;
            case HELPER_HASH_ALGORITHM_SHA2_512:
                hashLength = 64;
                MessageDigest = EVP_sha512();
                break;
            case HELPER_HASH_ALGORITHM_SHA3_224:
                hashLength = 28;
                MessageDigest = EVP_sha3_224();
                break;
            case HELPER_HASH_ALGORITHM_SHA3_256:
                hashLength = 32;
                MessageDigest = EVP_sha3_256();
                break;
            case HELPER_HASH_ALGORITHM_SHA3_384:
                hashLength = 48;
                MessageDigest = EVP_sha3_384();
                break;
            case HELPER_HASH_ALGORITHM_SHA3_512:
                hashLength = 64;
                MessageDigest = EVP_sha3_512();
                break;
            case HELPER_HASH_ALGORITHM_COUNT:
            default:
                TEST_FAIL();
                break;
        }

        /* Calculate Hash */
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestInit_ex(messageDigestContext, MessageDigest, NULL));
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestUpdate(messageDigestContext, input, sizeof(input)));
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestFinal_ex(messageDigestContext, hash, NULL));

        /* Verify */
        helper_verifyHash(input, sizeof(input), hashAlgorithm, hash, hashLength);

        /* Clean Up */
        EVP_MD_CTX_free(messageDigestContext);
    }
}
