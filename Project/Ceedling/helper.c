/****************************************************************************************************
 * Includes
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include "unity.h"

/****************************************************************************************************
 * Function Prototypes
 ****************************************************************************************************/

static const char *helper_getCommandLineMessageDigestName(const helper_hashAlgorithm_t HashAlgorithm);

/****************************************************************************************************
 * Function Definitions (Public)
 ****************************************************************************************************/

/*** Convert Buffer to Hex String ***/
void helper_convertBufferToHexString(const uint8_t * const Buffer, const size_t BufferLength, char * const hexString)
{
    /*** Convert Buffer to Hex String ***/
    /* Variables */
    size_t i;

    /* Convert Buffer to Hex String */
    for(i = 0; i < BufferLength; i++)
        (void)sprintf(&hexString[2 * i], "%02X", Buffer[i]);
}

/*** Get Hash Algorithm Name ***/
const char *helper_getHashAlgorithmName(const helper_hashAlgorithm_t HashAlgorithm)
{
    /*** Get Hash Algorithm Name ***/
    /* Variables */
    const char *hashAlgorithmName;

    /* Get Hash Algorithm Name */
    switch(HashAlgorithm)
    {
        case HELPER_HASH_ALGORITHM_SHA_224:
            hashAlgorithmName = "SHA-224";
            break;
        case HELPER_HASH_ALGORITHM_SHA_256:
            hashAlgorithmName = "SHA-256";
            break;
        case HELPER_HASH_ALGORITHM_SHA_384:
            hashAlgorithmName = "SHA-384";
            break;
        case HELPER_HASH_ALGORITHM_SHA_512:
            hashAlgorithmName = "SHA-512";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_224:
            hashAlgorithmName = "SHA3-224";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_256:
            hashAlgorithmName = "SHA3-256";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_384:
            hashAlgorithmName = "SHA3-384";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_512:
            hashAlgorithmName = "SHA3-512";
            break;
        case HELPER_HASH_ALGORITHM_COUNT:
        default:
            TEST_FAIL();
            break;
    }

    /* Exit */
    return hashAlgorithmName;
}

/*** Get Hash Length ***/
size_t helper_getHashLength(const helper_hashAlgorithm_t HashAlgorithm)
{
    /*** Get Hash Length ***/
    /* Variables */
    size_t hashLength;

    /* Get Hash Length */
    switch(HashAlgorithm)
    {
        case HELPER_HASH_ALGORITHM_SHA_224:
        case HELPER_HASH_ALGORITHM_SHA3_224:
            hashLength = 28;
            break;
        case HELPER_HASH_ALGORITHM_SHA_256:
        case HELPER_HASH_ALGORITHM_SHA3_256:
            hashLength = 32;
            break;
        case HELPER_HASH_ALGORITHM_SHA_384:
        case HELPER_HASH_ALGORITHM_SHA3_384:
            hashLength = 48;
            break;
        case HELPER_HASH_ALGORITHM_SHA_512:
        case HELPER_HASH_ALGORITHM_SHA3_512:
            hashLength = 64;
            break;
        case HELPER_HASH_ALGORITHM_COUNT:
        default:
            TEST_FAIL();
            break;
    }

    /* Exit */
    return hashLength;
}

/*** Get Message Authentication Code Parameters ***/
void helper_getMacParameters(const EVP_MD *MessageDigest, OSSL_PARAM parameters[2])
{
    /*** Get Message Digest Name Parameters ***/
    parameters[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)EVP_MD_get0_name(MessageDigest), 0);
    parameters[1] = OSSL_PARAM_construct_end();
}

/*** Get Message Digest ***/
const EVP_MD *helper_getMessageDigest(const helper_hashAlgorithm_t HashAlgorithm)
{
    /*** Get Message Digest ***/
    /* Variables */
    const EVP_MD *messageDigest;

    switch(HashAlgorithm)
    {
        case HELPER_HASH_ALGORITHM_SHA_224:
            messageDigest = EVP_sha224();
            break;
        case HELPER_HASH_ALGORITHM_SHA_256:
            messageDigest = EVP_sha256();
            break;
        case HELPER_HASH_ALGORITHM_SHA_384:
            messageDigest = EVP_sha384();
            break;
        case HELPER_HASH_ALGORITHM_SHA_512:
            messageDigest = EVP_sha512();
            break;
        case HELPER_HASH_ALGORITHM_SHA3_224:
            messageDigest = EVP_sha3_224();
            break;
        case HELPER_HASH_ALGORITHM_SHA3_256:
            messageDigest = EVP_sha3_256();
            break;
        case HELPER_HASH_ALGORITHM_SHA3_384:
            messageDigest = EVP_sha3_384();
            break;
        case HELPER_HASH_ALGORITHM_SHA3_512:
            messageDigest = EVP_sha3_512();
            break;
        case HELPER_HASH_ALGORITHM_COUNT:
        default:
            TEST_FAIL();
            break;
    }

    /* Exit */
    return messageDigest;
}

/*** Get Random Buffer ***/
void helper_getRandomBuffer(uint8_t * const buffer, const size_t BufferLength)
{
    /*** Get Random Buffer ***/
    (void)getrandom(buffer, BufferLength, GRND_NONBLOCK);
}

/*** Verify Hash ***/
void helper_verifyHash(const uint8_t * const Input, const size_t InputLength, const helper_hashAlgorithm_t HashAlgorithm, const uint8_t * const ExpectedHash, const size_t ExpectedHashLength)
{
    /*** Verify Hash ***/
    /* Variables */
    char actualHashString[500], *algorithmString, command[500], expectedHashString[500], inputString[500];
    FILE *fp;

    /* Set Up */
    helper_convertBufferToHexString(ExpectedHash, ExpectedHashLength, expectedHashString);
    helper_convertBufferToHexString(Input, InputLength, inputString);
    (void)sprintf(command, "echo -n \"%s\" | xxd -r -p | openssl dgst -%s -binary | xxd -p -c 256 | tr '[:lower:]' '[:upper:]'", inputString, helper_getCommandLineMessageDigestName(HashAlgorithm));

    /* Send Command */
    fp = popen(command, "r");
    (void)fgets(actualHashString, sizeof(actualHashString), fp);
    actualHashString[strcspn(actualHashString, "\n")] = '\0';
    (void)pclose(fp);

    /* Verify */
    TEST_ASSERT_EQUAL_STRING(expectedHashString, actualHashString);
}

/*** Verify HMAC ***/
void helper_verifyHmac(const uint8_t * const Input, const size_t InputLength, const uint8_t * const Key, const size_t KeyLength, const helper_hashAlgorithm_t HashAlgorithm, const uint8_t * const ExpectedHmac, const size_t ExpectedHmacLength)
{
    /*** Verify HMAC ***/
    /* Variables */
    char actualHmacString[500], command[500], expectedHmacString[500], inputString[500], keyString[500];
    FILE *fp;

    /* Set Up */
    helper_convertBufferToHexString(ExpectedHmac, ExpectedHmacLength, expectedHmacString);
    helper_convertBufferToHexString(Input, InputLength, inputString);
    helper_convertBufferToHexString(Key, KeyLength, keyString);
    (void)sprintf(command, "echo -n \"%s\" | xxd -r -p | openssl dgst -%s -mac hmac -macopt hexkey:%s -binary | xxd -p -c 256 | tr '[:lower:]' '[:upper:]'", inputString, helper_getCommandLineMessageDigestName(HashAlgorithm), keyString);

    /* Send Command */
    fp = popen(command, "r");
    (void)fgets(actualHmacString, sizeof(actualHmacString), fp);
    actualHmacString[strcspn(actualHmacString, "\n")] = '\0';
    (void)pclose(fp);

    /* Verify */
    TEST_ASSERT_EQUAL_STRING(expectedHmacString, actualHmacString);
}

/****************************************************************************************************
 * Function Definitions (Private)
 ****************************************************************************************************/

/*** Get Command Line Message Digest Name ***/
static const char *helper_getCommandLineMessageDigestName(const helper_hashAlgorithm_t HashAlgorithm)
{
    /*** Get Command Line Message Digest Name ***/
    /* Variables */
    const char *messageDigestName;

    /* Get Command Line Message Digest Name */
    switch(HashAlgorithm)
    {
        case HELPER_HASH_ALGORITHM_SHA_224:
            messageDigestName = "sha224";
            break;
        case HELPER_HASH_ALGORITHM_SHA_256:
            messageDigestName = "sha256";
            break;
        case HELPER_HASH_ALGORITHM_SHA_384:
            messageDigestName = "sha384";
            break;
        case HELPER_HASH_ALGORITHM_SHA_512:
            messageDigestName = "sha512";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_224:
            messageDigestName = "sha3-224";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_256:
            messageDigestName = "sha3-256";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_384:
            messageDigestName = "sha3-384";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_512:
            messageDigestName = "sha3-512";
            break;
        case HELPER_HASH_ALGORITHM_COUNT:
        default:
            TEST_FAIL();
            break;
    }

    /* Exit */
    return messageDigestName;
}