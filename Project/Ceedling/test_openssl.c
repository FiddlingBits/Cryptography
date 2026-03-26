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
    uint8_t hash[EVP_MAX_MD_SIZE], input[50];
    helper_hashAlgorithm_t hashAlgorithm;
    size_t hashLength;
    const EVP_MD *MessageDigest;
    EVP_MD_CTX *messageDigestContext;

    /* Calculate Hash */
    for(hashAlgorithm = 0; hashAlgorithm < HELPER_HASH_ALGORITHM_COUNT; hashAlgorithm++)
    {
        /* Set Up */
        hashLength = helper_getHashLength(hashAlgorithm);
        helper_getRandomBuffer(input, sizeof(input));
        MessageDigest = helper_getMessageDigest(hashAlgorithm);
        messageDigestContext = EVP_MD_CTX_new();

        /* Calculate Hash */
        (void)EVP_DigestInit_ex(messageDigestContext, MessageDigest, NULL);
        (void)EVP_DigestUpdate(messageDigestContext, input, sizeof(input));
        (void)EVP_DigestFinal_ex(messageDigestContext, hash, NULL);

        /* Verify */
        helper_verifyHash(input, sizeof(input), hashAlgorithm, hash, hashLength);

        /* Clean Up */
        EVP_MD_CTX_free(messageDigestContext);
    }
}

/*** Hash-Based Message Authentication Code (HMAC) ***/
void test_hmac_1(void)
{
    /*** Hash-Based Message Authentication Code (HMAC) ***/
    /* Variables */
    helper_hashAlgorithm_t hashAlgorithm;
    uint8_t hmac[EVP_MAX_MD_SIZE], input[100], key[32];
    size_t hmacLength;
    EVP_MAC *mac;
    EVP_MAC_CTX *macContext;
    const EVP_MD *MessageDigest;
    OSSL_PARAM parameters[2];

    /* Calculate HMAC */
    for(hashAlgorithm = 0; hashAlgorithm < HELPER_HASH_ALGORITHM_COUNT; hashAlgorithm++)
    {
        /* Set Up */
        helper_getRandomBuffer(input, sizeof(input));
        helper_getRandomBuffer(key, sizeof(key));
        mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        macContext = EVP_MAC_CTX_new(mac);
        MessageDigest = helper_getMessageDigest(hashAlgorithm);
        helper_getMacParameters(MessageDigest, parameters);

        /* Calculate HMAC */
        (void)EVP_MAC_init(macContext, key, sizeof(key), parameters);
        (void)EVP_MAC_update(macContext, input, sizeof(input));
        (void)EVP_MAC_final(macContext, hmac, &hmacLength, sizeof(hmac));

        /* Verify */
        helper_verifyHmac(input, sizeof(input), key, sizeof(key), hashAlgorithm, hmac, hmacLength);

        /* Clean Up */
        EVP_MAC_free(mac);
        EVP_MAC_CTX_free(macContext);
    }
}
