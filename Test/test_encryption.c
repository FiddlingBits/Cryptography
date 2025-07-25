/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
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

/*** Encryption ***/
void test_encryption_1(void)
{
    /*** Encryption: Advanced Encryption Standard (AES) ***/
    /* Enumeration */
    typedef enum
    {
        TYPE_AES_START,
        TYPE_AES_128,
        TYPE_AES_192,
        TYPE_AES_256,
        TYPE_AES_END
    } type_t;
    
    /* Variable */
    int actualCipherTextLength, finalLength, keyLength, updateLength;
    uint8_t actualCipherText[128], actualPlainText[128], *expectedCipherText, expectedPlainText[128], iv[AES_BLOCK_SIZE], *key;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    size_t expectedCipherTextLength;
    char *ivString, *keyString, *output;
    
    /* Set Up */
    (void)sprintf(expectedPlainText, "This Is A Secret Message");
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, sizeof(iv))); // Initialization Vector
    ivString = helper_convertByteArrayToHexString(iv, sizeof(iv));
    
    /* Test */
    for(type_t type = TYPE_AES_START + 1; type < TYPE_AES_END; type++)
    {
        /* Set Up */
        switch(type)
        {
            case TYPE_AES_128:
                cipher = EVP_aes_128_cbc();
                keyLength = EVP_CIPHER_key_length(cipher);
                key = malloc(keyLength * sizeof(*key));
                TEST_ASSERT_EQUAL_INT(1, RAND_bytes(key, keyLength));
                keyString = helper_convertByteArrayToHexString(key, keyLength);
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl enc -aes-128-cbc -iv \"%s\" -K \"%s\" | xxd -p | tr -d \"\\n\"", expectedPlainText, ivString, keyString);
                break;
            case TYPE_AES_192:
                cipher = EVP_aes_192_cbc();
                keyLength = EVP_CIPHER_key_length(cipher);
                key = malloc(keyLength * sizeof(*key));
                TEST_ASSERT_EQUAL_INT(1, RAND_bytes(key, keyLength));
                keyString = helper_convertByteArrayToHexString(key, keyLength);
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl enc -aes-192-cbc -iv \"%s\" -K \"%s\" | xxd -p | tr -d \"\\n\"", expectedPlainText, ivString, keyString);
                break;
            case TYPE_AES_256:
                cipher = EVP_aes_256_cbc();
                keyLength = EVP_CIPHER_key_length(cipher);
                key = malloc(keyLength * sizeof(*key));
                TEST_ASSERT_EQUAL_INT(1, RAND_bytes(key, keyLength));
                keyString = helper_convertByteArrayToHexString(key, keyLength);
                output = helper_executeSystemCommand("echo -n \"%s\" | openssl enc -aes-256-cbc -iv \"%s\" -K \"%s\" | xxd -p | tr -d \"\\n\"", expectedPlainText, ivString, keyString);
                break;
            default:
                /* Do Nothing */
                continue;
        }
        expectedCipherTextLength = helper_convertHexStringToByteArray(output, &expectedCipherText);
        
        /* Initialize */
        ctx = EVP_CIPHER_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        TEST_ASSERT_EQUAL_INT(1, EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv));
        
        /* Encrypt */
        TEST_ASSERT_EQUAL_INT(1, EVP_EncryptUpdate(ctx, actualCipherText, &updateLength, expectedPlainText, strlen(expectedPlainText)));
        TEST_ASSERT_EQUAL_INT(1, EVP_EncryptFinal_ex(ctx, &actualCipherText[updateLength], &finalLength));
        actualCipherTextLength = updateLength + finalLength;
        
        /* Verify */
        TEST_ASSERT_EQUAL_INT(expectedCipherTextLength, actualCipherTextLength);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expectedCipherText, actualCipherText, expectedCipherTextLength);
        
        /* Initialize */
        TEST_ASSERT_EQUAL_INT(1, EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv));
        
        /* Decrypt */
        TEST_ASSERT_EQUAL_INT(1, EVP_DecryptUpdate(ctx, actualPlainText, &updateLength, actualCipherText, actualCipherTextLength));
        TEST_ASSERT_EQUAL_INT(1, EVP_DecryptFinal_ex(ctx, &actualPlainText[updateLength], &finalLength));
        actualPlainText[updateLength + finalLength] = '\0';
        
        /* Verify */
        TEST_ASSERT_EQUAL_STRING(expectedPlainText, actualPlainText);
            
        /* Clean Up */
        EVP_CIPHER_CTX_free(ctx);
        free(expectedCipherText);
        free(key);
        free(keyString);
        free(output);
    }
    
    /* Clean Up */
    free(ivString);
}

void test_encryption_2(void)
{
    /*** Encryption: Advanced Encryption Standard In Galois/Counter Mode (AES-GCM): AES-256-GCM (Note: Can't Use helper_executeSystemCommand Because AES-256-GCM Not Supported) ***/
    /* Variable */
    uint8_t aad[128], actualCipherText[128], actualPlainText[128], expectedPlainText[128], iv[AES_BLOCK_SIZE], *key, tag[16];
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    char *ivString, *keyString;
    int actualCipherTextLength, finalLength, keyLength, updateLength;
    
    /* Set Up */
    (void)sprintf(aad, "Optional Additional Authenticated Data");
    cipher = EVP_aes_256_gcm();
    (void)sprintf(expectedPlainText, "This Is A Secret Message");
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, sizeof(iv))); // Initialization Vector
    ivString = helper_convertByteArrayToHexString(iv, sizeof(iv));
    keyLength = EVP_CIPHER_key_length(cipher);
    key = malloc(keyLength * sizeof(*key));
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(key, keyLength));
    keyString = helper_convertByteArrayToHexString(key, keyLength);
    
    /* Initialize */
    ctx = EVP_CIPHER_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL));
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv));
    
    /* Encrypt */
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptUpdate(ctx, NULL, &updateLength, aad, strlen(aad))); // Authenticated, But Not Encrypted; Update Length Not Needed
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptUpdate(ctx, actualCipherText, &updateLength, expectedPlainText, strlen(expectedPlainText)));
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptFinal_ex(ctx, &actualCipherText[updateLength], &finalLength));
    actualCipherTextLength = updateLength + finalLength;
    
    /* Get Tag */
    TEST_ASSERT_EQUAL_INT(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag));
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL));
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv));
    
    /* Decrypt (Update) */
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptUpdate(ctx, NULL, &updateLength, aad, strlen(aad))); // Update Length Not Needed
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptUpdate(ctx, actualPlainText, &updateLength, actualCipherText, actualCipherTextLength));
    
    /* Set Tag */
    TEST_ASSERT_EQUAL_INT(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag));
    
    /* Decrypt (Final) */
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptFinal_ex(ctx, &actualPlainText[updateLength], &finalLength));
    actualPlainText[updateLength + finalLength] = '\0';
    
    /* Verify */
    TEST_ASSERT_EQUAL_STRING(expectedPlainText, actualPlainText);
    
    /* Clean Up */
    EVP_CIPHER_CTX_free(ctx);
    free(ivString);
    free(key);
    free(keyString);
}

void test_encryption_3(void)
{
    /*** Encryption: ChaCha20-Poly1305 (Note: Can't Use helper_executeSystemCommand Because ChaCha20-Poly1305 Not Supported) ***/
    /* Variable */
    uint8_t aad[128], actualCipherText[128], actualPlainText[128], expectedPlainText[128], *iv, *key, tag[16];
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    char *ivString, *keyString;
    int actualCipherTextLength, finalLength, ivLength, keyLength, updateLength;
    
    /* Set Up */
    (void)sprintf(aad, "Optional Additional Authenticated Data");
    cipher = EVP_chacha20_poly1305();
    (void)sprintf(expectedPlainText, "This Is A Secret Message");
    ivLength = EVP_CIPHER_iv_length(cipher);
    iv = malloc(ivLength * sizeof(*iv));
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, ivLength)); // Initialization Vector
    ivString = helper_convertByteArrayToHexString(iv, sizeof(iv));
    keyLength = EVP_CIPHER_key_length(cipher);
    key = malloc(keyLength * sizeof(*key));
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(key, keyLength));
    keyString = helper_convertByteArrayToHexString(key, keyLength);
    
    /* Initialize */
    ctx = EVP_CIPHER_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv));
    
    /* Encrypt */
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptUpdate(ctx, NULL, &updateLength, aad, strlen(aad))); // Authenticated, But Not Encrypted; Update Length Not Needed
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptUpdate(ctx, actualCipherText, &updateLength, expectedPlainText, strlen(expectedPlainText)));
    TEST_ASSERT_EQUAL_INT(1, EVP_EncryptFinal_ex(ctx, &actualCipherText[updateLength], &finalLength));
    actualCipherTextLength = updateLength + finalLength;
    
    /* Get Tag */
    TEST_ASSERT_EQUAL_INT(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag));
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv));
    
    /* Decrypt (Update) */
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptUpdate(ctx, NULL, &updateLength, aad, strlen(aad))); // Update Length Not Needed
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptUpdate(ctx, actualPlainText, &updateLength, actualCipherText, actualCipherTextLength));
    
    /* Set Tag */
    TEST_ASSERT_EQUAL_INT(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag));
    
    /* Decrypt (Final) */
    TEST_ASSERT_EQUAL_INT(1, EVP_DecryptFinal_ex(ctx, &actualPlainText[updateLength], &finalLength));
    actualPlainText[updateLength + finalLength] = '\0';
    
    /* Verify */
    TEST_ASSERT_EQUAL_STRING(expectedPlainText, actualPlainText);
    
    /* Clean Up */
    EVP_CIPHER_CTX_free(ctx);
    free(iv);
    free(ivString);
    free(key);
    free(keyString);
}
