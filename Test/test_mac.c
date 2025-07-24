/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
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
 * Test (Public)
 ****************************************************************************************************/

/*** Message Authentication Code (MAC) ***/
void test_hmac_1(void)
{
    /*** Message Authentication Code (MAC): Hash-Based (HMAC) ***/
    /* Variable */
    uint8_t actualHash[EVP_MAX_MD_SIZE], *expectedHash;
    unsigned int actualHashLength;
    const char *Message, *Key;
    size_t expectedHashLength;
    char *output;
    
    /* Set Up */
    Key = "key";
    Message = "message";
    output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(echo -n \"%s\" | xxd -p) | awk '{print $2}' | tr -d \"\\n\"", Message, Key);
    expectedHashLength = helper_convertHexStringToByteArray(output, &expectedHash);
    
    /* Calculate */
    TEST_ASSERT_NOT_NULL(HMAC(EVP_sha256(), Key, strlen(Key), Message, strlen(Message), actualHash, &actualHashLength));
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT(expectedHashLength, actualHashLength);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expectedHash, actualHash, expectedHashLength);
    
    /* Clean Up */
    free(expectedHash);
    free(output);
}
