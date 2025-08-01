/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
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

/*** Symmetric Encryption ***/
void test_symmetric_encryption_1(void)
{
    /*** Symmetric Encryption: Advanced Encryption Standard (AES) ***/
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
    uint8_t actualCipherText[128], actualPlainText[128], *expectedCipherText, expectedPlainText[128], iv[AES_BLOCK_SIZE], *key;
    int actualCipherTextLength, finalLength, keyLength, updateLength;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    size_t expectedCipherTextLength;
    char *ivString, *keyString, *output;
    
    /* Set Up */
    (void)sprintf(expectedPlainText, "This Is A Secret Message");
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, sizeof(iv)));
    ivString = helper_convertByteArrayToHexString(iv, sizeof(iv));
    
    /* Test */
    for(type_t type = TYPE_AES_START + 1; type < TYPE_AES_END; type++)
    {
        /* Set Up */
        switch(type)
        {case TYPE_AES_128:
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

void test_symmetric_encryption_2(void)
{
    /*** Symmetric Encryption: Advanced Encryption Standard In Galois/Counter Mode (AES-GCM) ***/
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
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, sizeof(iv)));
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

void test_symmetric_encryption_3(void)
{
    /*** Symmetric Encryption: ChaCha20-Poly1305 ***/
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
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, ivLength));
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

/*** Asymmetric Encryption ***/
void test_asymmetric_encryption_1(void)
{
    /*** Asymmetric Encryption: Rivest-Shamir-Adleman (RSA) ***/
    /* Variable */
    uint8_t *actualCipherText = NULL, *actualPlainText = NULL, expectedPlainText[128];
    size_t actualCipherTextLength, actualPlainTextLength;
    BIO *bio = NULL;
    EVP_PKEY *keyPair = NULL, *publicKey = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    
    /* Set Up */
    (void)sprintf(expectedPlainText, "This Is A Secret Message");
    
    /*** 1. Generate Keys ***/
    /* Set Up */
    bio = BIO_new(BIO_s_mem());
    TEST_ASSERT_NOT_NULL(bio);
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx, 2048));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &keyPair));
    TEST_ASSERT_NOT_NULL(keyPair);
    
    /* Separate Public Key */
    TEST_ASSERT_EQUAL_INT(1, PEM_write_bio_PUBKEY(bio, keyPair));
    publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(publicKey);
    
    /* Clean Up */
    BIO_free(bio);
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2. Encrypt With Public Key ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(publicKey, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_encrypt_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_OAEP_PADDING));
    
    /* Encrypt */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_encrypt(keyCtx, NULL, &actualCipherTextLength, expectedPlainText, strlen(expectedPlainText)));
    TEST_ASSERT(actualCipherTextLength != 0);
    actualCipherText = OPENSSL_malloc(actualCipherTextLength * sizeof(*actualCipherText));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_encrypt(keyCtx, actualCipherText, &actualCipherTextLength, expectedPlainText, strlen(expectedPlainText)));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 3. Decrypt With Private Key ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_decrypt_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_OAEP_PADDING)); 
    
    /* Decrypt */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_decrypt(keyCtx, NULL, &actualPlainTextLength, actualCipherText, actualCipherTextLength));
    TEST_ASSERT(actualPlainTextLength != 0);
    actualPlainText = OPENSSL_malloc(actualPlainTextLength * sizeof(*actualPlainText));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_decrypt(keyCtx, actualPlainText, &actualPlainTextLength, actualCipherText, actualCipherTextLength));
    actualPlainText[actualPlainTextLength] = '\0';
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT(strlen(expectedPlainText), actualPlainTextLength);
    TEST_ASSERT_EQUAL_STRING(expectedPlainText, actualPlainText);
    
    /*** Clean Up ***/
    OPENSSL_free(actualCipherText);
    OPENSSL_free(actualPlainText);
    EVP_PKEY_free(keyPair);
    EVP_PKEY_free(publicKey);
}

/*** Hybrid Encryption ***/
void test_hybrid_encryption_1(void)
{
    /*** Hybrid Encryption: Rivest-Shamir-Adleman (RSA) And Advanced Encryption Standard (AES) ***/
    /* Variable */
    uint8_t *actualCipherText = NULL, *actualPlainText = NULL, expectedPlainText[128], iv[AES_BLOCK_SIZE], *key;
    size_t actualCipherTextLength, actualPlainTextLength;
    BIO *bio = NULL;
    const EVP_CIPHER *cipher;
    size_t expectedPlainTextLength;
    int keyLength;
    EVP_PKEY *keyPair = NULL, *publicKey = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    
    /* Set Up */
    cipher = EVP_aes_256_cbc();
    
    /*** 1. Generate RSA Keys ***/
    /* Set Up */
    bio = BIO_new(BIO_s_mem());
    TEST_ASSERT_NOT_NULL(bio);
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx, 2048));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &keyPair));
    TEST_ASSERT_NOT_NULL(keyPair);
    
    /* Separate Public Key */
    TEST_ASSERT_EQUAL_INT(1, PEM_write_bio_PUBKEY(bio, keyPair));
    publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(publicKey);
    
    /* Clean Up */
    BIO_free(bio);
    bio = NULL;
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2. Generate AES Key And Initialization Vector ***/
    /* Set Up */
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(iv, sizeof(iv)));
    keyLength = EVP_CIPHER_key_length(cipher);
    key = malloc(keyLength * sizeof(*key));
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(key, keyLength));
    
    /*** 3. Encrypt AES Key And Initialization Vector With RSA Public Key ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(publicKey, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    (void)memcpy(&expectedPlainText[0], key, keyLength);
    (void)memcpy(&expectedPlainText[keyLength], iv, sizeof(iv));
    expectedPlainTextLength = keyLength + sizeof(iv);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_encrypt_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_OAEP_PADDING));
    
    /* Encrypt */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_encrypt(keyCtx, NULL, &actualCipherTextLength, expectedPlainText, expectedPlainTextLength));
    TEST_ASSERT(actualCipherTextLength != 0);
    actualCipherText = OPENSSL_malloc(actualCipherTextLength * sizeof(*actualCipherText));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_encrypt(keyCtx, actualCipherText, &actualCipherTextLength, expectedPlainText, expectedPlainTextLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 4. Decrypt AES Key And Initialization Vector With RSA Private Key ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_decrypt_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_OAEP_PADDING)); 
    
    /* Decrypt */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_decrypt(keyCtx, NULL, &actualPlainTextLength, actualCipherText, actualCipherTextLength));
    TEST_ASSERT(actualPlainTextLength != 0);
    actualPlainText = OPENSSL_malloc(actualPlainTextLength * sizeof(*actualPlainText));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_decrypt(keyCtx, actualPlainText, &actualPlainTextLength, actualCipherText, actualCipherTextLength));
    actualPlainText[actualPlainTextLength] = '\0';
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT(expectedPlainTextLength, actualPlainTextLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedPlainText, actualPlainText, expectedPlainTextLength);
    
    /*** 5. Symmetric Encryption May Now Take Place ***/
    
    /*** Clean Up ***/
    OPENSSL_free(actualCipherText);
    OPENSSL_free(actualPlainText);
    EVP_PKEY_free(keyPair);
    EVP_PKEY_free(publicKey);
}

void test_hybrid_encryption_2(void)
{
    /*** Hybrid Encryption: Ephemeral Elliptic Curve Diffie-Hellman (ECDH) And Advanced Encryption Standard In Galois/Counter Mode (AES-GCM) ***/
    /* Structure */
    typedef struct
    {
        EVP_PKEY *keyPair;
        unsigned char *sharedSecret;
        size_t sharedSecretLength;
    } entity_t;
    
    /* Variables */
    entity_t alice, bob;
    EVP_PKEY_CTX *keyCtx = NULL;
    
    /* Set Up */
    (void)memset(&alice, 0, sizeof(alice));
    (void)memset(&bob, 0, sizeof(bob));
    
    /*** 1a. Generate Alice's Keys ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyCtx, NID_X9_62_prime256v1));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &alice.keyPair));
    TEST_ASSERT_NOT_NULL(alice.keyPair);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 1b. Generate Bob's Ephemeral Keys ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyCtx, NID_X9_62_prime256v1));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &bob.keyPair));
    TEST_ASSERT_NOT_NULL(bob.keyPair);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2a. Bob Derives Shared Secret From Private Key And Alice's Public Key ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(bob.keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_set_peer(keyCtx, alice.keyPair)); // Bob Only Needs Alice's Public Key
    
    /* Derive Shared Secret */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, NULL, &bob.sharedSecretLength));
    bob.sharedSecret = OPENSSL_malloc(bob.sharedSecretLength * sizeof(*bob.sharedSecret));
    TEST_ASSERT_NOT_NULL(bob.sharedSecret);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, bob.sharedSecret, &bob.sharedSecretLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2b. Alice Derives Shared Secret From Private Key And Bob's Ephemeral Public Key ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(alice.keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_set_peer(keyCtx, bob.keyPair)); // Alice Only Needs Bob's Ephemeral Public Key
    
    /* Derive Shared Secret */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, NULL, &alice.sharedSecretLength));
    alice.sharedSecret = OPENSSL_malloc(alice.sharedSecretLength * sizeof(*alice.sharedSecret));
    TEST_ASSERT_NOT_NULL(alice.sharedSecret);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, alice.sharedSecret, &alice.sharedSecretLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT(alice.sharedSecretLength, bob.sharedSecretLength);
    TEST_ASSERT_EQUAL_MEMORY(alice.sharedSecret, bob.sharedSecret, alice.sharedSecretLength);
    
    /*** 3. Create AES Key From Shared Secret; Send/Receive Encrypted Data ***/
    
    /*** Clean Up ***/
    /* Alice */
    EVP_PKEY_free(alice.keyPair);
    OPENSSL_free(alice.sharedSecret);
    
    /* Bob */
    EVP_PKEY_free(bob.keyPair);
    OPENSSL_free(bob.sharedSecret);
}
