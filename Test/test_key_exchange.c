/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
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

/*** Key Exchange ***/
void test_key_exchange_1(void)
{
    /*** Key Exchange: Diffie-Hellman (DH) ***/
    
    /*
     * Simple Example:
     *   DH Parameters: 
     *     Generator (g): 5
     *     Prime Number (p): 23
     *   Alice:
     *     Peer Public Key (B): 10
     *     Private Key (a): 4
     *     Public Key (A): g^a % p = 5^4 % 23 = 625 % 23 = 4
     *     Shared Secret: B^a % p = 10^4 % 23 = 10000 % 23 = 18
     *   Bob:
     *     Peer Public Key (A): 4
     *     Private Key (b): 3
     *     Public Key (B): g^b % p = 5^3 % 23 = 125 % 23 = 10
     *     Shared Secret: A^b % p = 4^3 % 23 = 64 % 23 = 18
     */
    
    /* Structure */
    typedef struct
    {
        EVP_PKEY *keyPair, *peerPublicKey;
        unsigned char *serializedPublicKey, *sharedSecret;
        size_t serializedPublicKeyLength, sharedSecretLength;
    } entity_t;
    
    /* Variables */
    entity_t alice, bob;
    EVP_PKEY_CTX *keyCtx = NULL;
    EVP_PKEY *publicDhParameters = NULL;
    
    /* Set Up */
    (void)memset(&alice, 0, sizeof(alice));
    (void)memset(&bob, 0, sizeof(bob));
    
    /*** 1. Generate DH Parameters ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_paramgen_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_dh_nid(keyCtx, NID_ffdhe2048));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_paramgen(keyCtx, &publicDhParameters));
    TEST_ASSERT_NOT_NULL(publicDhParameters);
    TEST_ASSERT_EQUAL_INT(EVP_PKEY_DH, EVP_PKEY_base_id(publicDhParameters));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2a. Generate Alice's Keys ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(publicDhParameters, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &alice.keyPair));
    TEST_ASSERT_NOT_NULL(alice.keyPair);
    
    /* Serialize Public Key */
    alice.serializedPublicKeyLength = EVP_PKEY_get1_encoded_public_key(alice.keyPair, &alice.serializedPublicKey);
    TEST_ASSERT(alice.serializedPublicKeyLength != 0);
    TEST_ASSERT_NOT_NULL(alice.serializedPublicKey);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2b. Generate Bob's Keys ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(publicDhParameters, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &bob.keyPair));
    TEST_ASSERT_NOT_NULL(bob.keyPair);
    
    /* Serialize Public Key */
    bob.serializedPublicKeyLength = EVP_PKEY_get1_encoded_public_key(bob.keyPair, &bob.serializedPublicKey);
    TEST_ASSERT(bob.serializedPublicKeyLength != 0);
    TEST_ASSERT_NOT_NULL(bob.serializedPublicKey);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 3a. Exchange Public Key: Bob To Alice ***/
    /* Set Up */
    alice.peerPublicKey = EVP_PKEY_new();
    TEST_ASSERT_NOT_NULL(alice.peerPublicKey);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_copy_parameters(alice.peerPublicKey, publicDhParameters));
    
    /* Deserialize Bob's Public Key */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_set1_encoded_public_key(alice.peerPublicKey, bob.serializedPublicKey, bob.serializedPublicKeyLength));
    
    /*** 3b. Exchange Public Key: Alice To Bob ***/
    /* Set Up */
    bob.peerPublicKey = EVP_PKEY_new();
    TEST_ASSERT_NOT_NULL(bob.peerPublicKey);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_copy_parameters(bob.peerPublicKey, publicDhParameters));
    
    /* Deserialize Alice's Public Key */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_set1_encoded_public_key(bob.peerPublicKey, alice.serializedPublicKey, alice.serializedPublicKeyLength));
    
    /*** 4a. Derive Alice's Shared Secret ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(alice.keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_set_peer(keyCtx, alice.peerPublicKey));
    
    /* Derive */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, NULL, &alice.sharedSecretLength));
    TEST_ASSERT(alice.sharedSecretLength != 0);
    alice.sharedSecret = OPENSSL_malloc(alice.sharedSecretLength * sizeof(*alice.sharedSecret));
    TEST_ASSERT_NOT_NULL(alice.sharedSecret);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, alice.sharedSecret, &alice.sharedSecretLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 4b. Derive Bob's Shared Secret ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(bob.keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_set_peer(keyCtx, bob.peerPublicKey));
    
    /* Derive */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, NULL, &bob.sharedSecretLength));
    TEST_ASSERT(bob.sharedSecretLength != 0);
    bob.sharedSecret = OPENSSL_malloc(bob.sharedSecretLength * sizeof(*bob.sharedSecret));
    TEST_ASSERT_NOT_NULL(bob.sharedSecret);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, bob.sharedSecret, &bob.sharedSecretLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT(alice.sharedSecretLength, bob.sharedSecretLength);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(alice.sharedSecret, bob.sharedSecret, alice.sharedSecretLength);
    
    /*** 5. Send/Receive Encrypted Data ***/
    
    /*** Clean Up ***/
    /* Alice */
    EVP_PKEY_free(alice.keyPair);
    EVP_PKEY_free(alice.peerPublicKey);
    OPENSSL_free(alice.serializedPublicKey);
    OPENSSL_free(alice.sharedSecret);
    
    /* Bob */
    EVP_PKEY_free(bob.keyPair);
    EVP_PKEY_free(bob.peerPublicKey);
    OPENSSL_free(bob.serializedPublicKey);
    OPENSSL_free(bob.sharedSecret);
    
    /* Miscellaneous */
    EVP_PKEY_free(publicDhParameters);
}

void test_key_exchange_2(void)
{
    /*** Key Exchange: Elliptic Curve Diffie-Hellman (ECDH) ***/
    /* Structure */
    typedef struct
    {
        EVP_PKEY *keyPair, *peerPublicKey;
        unsigned char *serializedPublicKey, *sharedSecret;
        size_t serializedPublicKeyLength, sharedSecretLength;
    } entity_t;
    
    /* Variables */
    entity_t alice, bob;
    EVP_PKEY_CTX *keyCtx = NULL;
    EVP_PKEY *publicEcdhParameters = NULL;
    
    /* Set Up */
    (void)memset(&alice, 0, sizeof(alice));
    (void)memset(&bob, 0, sizeof(bob));
    
    /*** 1. Generate ECDH Parameters ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_paramgen_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyCtx, NID_X9_62_prime256v1));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_paramgen(keyCtx, &publicEcdhParameters));
    TEST_ASSERT_NOT_NULL(publicEcdhParameters);
    TEST_ASSERT_EQUAL_INT(EVP_PKEY_EC, EVP_PKEY_base_id(publicEcdhParameters));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2a. Generate Alice's Keys ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(publicEcdhParameters, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &alice.keyPair));
    TEST_ASSERT_NOT_NULL(alice.keyPair);
    
    /* Serialize Public Key */
    alice.serializedPublicKeyLength = EVP_PKEY_get1_encoded_public_key(alice.keyPair, &alice.serializedPublicKey);
    TEST_ASSERT(alice.serializedPublicKeyLength != 0);
    TEST_ASSERT_NOT_NULL(alice.serializedPublicKey);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 2b. Generate Bob's Keys ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(publicEcdhParameters, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    
    /* Generate */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &bob.keyPair));
    TEST_ASSERT_NOT_NULL(bob.keyPair);
    
    /* Serialize Public Key */
    bob.serializedPublicKeyLength = EVP_PKEY_get1_encoded_public_key(bob.keyPair, &bob.serializedPublicKey);
    TEST_ASSERT(bob.serializedPublicKeyLength != 0);
    TEST_ASSERT_NOT_NULL(bob.serializedPublicKey);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 3a. Exchange Public Key: Bob To Alice ***/
    /* Set Up */
    alice.peerPublicKey = EVP_PKEY_new();
    TEST_ASSERT_NOT_NULL(alice.peerPublicKey);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_copy_parameters(alice.peerPublicKey, publicEcdhParameters));
    
    /* Deserialize Bob's Public Key */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_set1_encoded_public_key(alice.peerPublicKey, bob.serializedPublicKey, bob.serializedPublicKeyLength));
    
    /*** 3b. Exchange Public Key: Alice To Bob ***/
    /* Set Up */
    bob.peerPublicKey = EVP_PKEY_new();
    TEST_ASSERT_NOT_NULL(bob.peerPublicKey);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_copy_parameters(bob.peerPublicKey, publicEcdhParameters));
    
    /* Deserialize Alice's Public Key */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_set1_encoded_public_key(bob.peerPublicKey, alice.serializedPublicKey, alice.serializedPublicKeyLength));
    
    /*** 4a. Derive Alice's Shared Secret ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(alice.keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_set_peer(keyCtx, alice.peerPublicKey));
    
    /* Derive */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, NULL, &alice.sharedSecretLength));
    TEST_ASSERT(alice.sharedSecretLength != 0);
    alice.sharedSecret = OPENSSL_malloc(alice.sharedSecretLength * sizeof(*alice.sharedSecret));
    TEST_ASSERT_NOT_NULL(alice.sharedSecret);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, alice.sharedSecret, &alice.sharedSecretLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /*** 4b. Derive Bob's Shared Secret ***/
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new(bob.keyPair, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_init(keyCtx));
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive_set_peer(keyCtx, bob.peerPublicKey));
    
    /* Derive */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, NULL, &bob.sharedSecretLength));
    TEST_ASSERT(bob.sharedSecretLength != 0);
    bob.sharedSecret = OPENSSL_malloc(bob.sharedSecretLength * sizeof(*bob.sharedSecret));
    TEST_ASSERT_NOT_NULL(bob.sharedSecret);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_derive(keyCtx, bob.sharedSecret, &bob.sharedSecretLength));
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT(alice.sharedSecretLength, bob.sharedSecretLength);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(alice.sharedSecret, bob.sharedSecret, alice.sharedSecretLength);
    
    /*** 5. Create AES Key From Shared Secret; Send/Receive Encrypted Data ***/
    
    /*** Clean Up ***/
    /* Alice */
    EVP_PKEY_free(alice.keyPair);
    EVP_PKEY_free(alice.peerPublicKey);
    OPENSSL_free(alice.serializedPublicKey);
    OPENSSL_free(alice.sharedSecret);
    
    /* Bob */
    EVP_PKEY_free(bob.keyPair);
    EVP_PKEY_free(bob.peerPublicKey);
    OPENSSL_free(bob.serializedPublicKey);
    OPENSSL_free(bob.sharedSecret);
    
    /* Miscellaneous */
    EVP_PKEY_free(publicEcdhParameters);
}
