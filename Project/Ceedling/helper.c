/****************************************************************************************************
 * Includes
 ****************************************************************************************************/

#include "helper.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include "unity.h"

/****************************************************************************************************
 * Functions
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
    switch(HashAlgorithm)
    {
        case HELPER_HASH_ALGORITHM_SHA2_224:
            algorithmString = "sha224";
            break;
        case HELPER_HASH_ALGORITHM_SHA2_256:
            algorithmString = "sha256";
            break;
        case HELPER_HASH_ALGORITHM_SHA2_384:
            algorithmString = "sha384";
            break;
        case HELPER_HASH_ALGORITHM_SHA2_512:
            algorithmString = "sha512";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_224:
            algorithmString = "sha3-224";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_256:
            algorithmString = "sha3-256";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_384:
            algorithmString = "sha3-384";
            break;
        case HELPER_HASH_ALGORITHM_SHA3_512:
            algorithmString = "sha3-512";
            break;
        case HELPER_HASH_ALGORITHM_COUNT:
        default:
            TEST_FAIL();
            break;
    }
    helper_convertBufferToHexString(ExpectedHash, ExpectedHashLength, expectedHashString);
    helper_convertBufferToHexString(Input, InputLength, inputString);
    (void)sprintf(command, "echo -n \"%s\" | xxd -r -p | openssl dgst -%s -binary | xxd -p -c 256 | tr '[:lower:]' '[:upper:]'", inputString, algorithmString);

    /* Send Command */
    fp = popen(command, "r");
    (void)fgets(actualHashString, sizeof(actualHashString), fp);
    actualHashString[strcspn(actualHashString, "\n")] = '\0';
    (void)pclose(fp);

    /* Verify */
    TEST_ASSERT_EQUAL_STRING(expectedHashString, actualHashString);
}
