/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
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

/*** Hash ***/
void test_hash_1(void)
{
    /*** Hash ***/
    /* Enumeration */
    typedef enum
    {
        TYPE_START,
        TYPE_SHA2_224,
        TYPE_SHA2_256,
        TYPE_SHA2_384,
        TYPE_SHA2_512,
        TYPE_SHA2_512_224,
        TYPE_SHA2_512_256,
        TYPE_SHA3_224,
        TYPE_SHA3_256,
        TYPE_SHA3_384,
        TYPE_SHA3_512,
        TYPE_SHAKE_128,
        TYPE_SHAKE_256,
        TYPE_END
    } type_t;
    
    /* Variable */
    uint8_t actualHash[EVP_MAX_MD_SIZE], *expectedHash;
    unsigned int actualHashLength;
    const char *Message;
    EVP_MD_CTX *ctx;
    size_t expectedHashLength;
    char *output;
    int outputLength;
    const EVP_MD *MessageDigest;
    OSSL_PARAM params[2];
    
    /* Set Up */
    Message = "message";
    params[1] = OSSL_PARAM_construct_end();
    
    /* Test */
    for(type_t type = TYPE_START + 1; type < TYPE_END; type++)
    {
        /* Set Up */
        switch(type)
        {
            case TYPE_SHA2_224:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha224 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha224();
                break;
            case TYPE_SHA2_256:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha256 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha256();
                break;
            case TYPE_SHA2_384:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha384 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha384();
                break;
            case TYPE_SHA2_512:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha512 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha512();
                break;
            case TYPE_SHA2_512_224:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha512-224 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha512_224();
                break;
            case TYPE_SHA2_512_256:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha512-256 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha512_256();
                break;
            case TYPE_SHA3_224:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha3-224 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha3_224();
                break;
            case TYPE_SHA3_256:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha3-256 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha3_256();
                break;
            case TYPE_SHA3_384:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha3-384 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha3_384();
                break;
            case TYPE_SHA3_512:
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -sha3-512 | awk '{print $2}' | tr -d \"\\n\"", Message);
                MessageDigest = EVP_sha3_512();
                break;
            case TYPE_SHAKE_128:
                outputLength = 17;
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -shake128 -xoflen %d | awk '{print $2}' | tr -d \"\\n\"", Message, outputLength);
                MessageDigest = EVP_shake128();
                params[0] = OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_XOFLEN, &outputLength);
                break;
            case TYPE_SHAKE_256:
                outputLength = 33;
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl dgst -shake256 -xoflen %d | awk '{print $2}' | tr -d \"\\n\"", Message, outputLength);
                MessageDigest = EVP_shake256();
                params[0] = OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_XOFLEN, &outputLength);
                break;
            default:
                /* Do Nothing */
                continue;
        }
        expectedHashLength = helper_convertHexStringToByteArray(output, &expectedHash);
        
        /* Initialize */
        ctx = EVP_MD_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestInit_ex(ctx, MessageDigest, NULL));
        if((type == TYPE_SHAKE_128) || (type == TYPE_SHAKE_256))
            TEST_ASSERT_EQUAL_INT(1, EVP_MD_CTX_set_params(ctx, params));
        
        /* Calculate */
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestUpdate(ctx, Message, strlen(Message)));
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestFinal_ex(ctx, actualHash, &actualHashLength));
        
        /* Verify */
        TEST_ASSERT_EQUAL_UINT(expectedHashLength, actualHashLength);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expectedHash, actualHash, expectedHashLength);
        
        /* Clean Up */
        EVP_MD_CTX_free(ctx);
        free(expectedHash);
        free(output);
    }
}
