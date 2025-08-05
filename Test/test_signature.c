/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include "helper.h"
#include <openssl/bn.h>
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

/*** Signature ***/
void test_signature_1(void)
{
    /*** Signature: Ed25519 ***/
    /* Variable */
    EVP_PKEY_CTX *keyCtx = NULL;
    EVP_PKEY *keyPair = NULL, *publicKey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    const char *Message;
    unsigned char *rawPublicKey, *signature = NULL;
    size_t rawPublicKeyLength, signatureLength;
    
    /* Set Up */
    Message = "message";
    
    /* Set Up */
    keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    TEST_ASSERT_NOT_NULL(keyCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen_init(keyCtx));
    
    /* Generate Key Pair */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_keygen(keyCtx, &keyPair));
    
    /* Separate Public Key */
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(keyPair, NULL, &rawPublicKeyLength));
    rawPublicKey = OPENSSL_malloc(rawPublicKeyLength * sizeof(*rawPublicKey));
    TEST_ASSERT_NOT_NULL(rawPublicKey);
    TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(keyPair, rawPublicKey, &rawPublicKeyLength));
    publicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, rawPublicKey, rawPublicKeyLength);
    TEST_ASSERT_NOT_NULL(publicKey);
    
    /* Clean Up */
    EVP_PKEY_CTX_free(keyCtx);
    OPENSSL_free(rawPublicKey);
    
    /* Set Up */
    mdCtx = EVP_MD_CTX_new();
    TEST_ASSERT_NOT_NULL(mdCtx);
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignInit(mdCtx, NULL, NULL, NULL, keyPair));
    
    /* Get Message Signature */
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestSign(mdCtx, NULL, &signatureLength, Message, strlen(Message)));
    signature = OPENSSL_malloc(signatureLength * sizeof(*signature));
    TEST_ASSERT_NOT_NULL(signature);
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestSign(mdCtx, signature, &signatureLength, Message, strlen(Message)));
    
    /* Initialize */
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestVerifyInit(mdCtx, NULL, NULL, NULL, publicKey));
    
    /* Verify Message Signature */
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestVerify(mdCtx, signature, signatureLength, Message, strlen(Message)));
    
    /* Clean Up */
    EVP_PKEY_free(keyPair);
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    OPENSSL_free(signature);
}

void test_signature_2(void)
{
    /*** Signature: Zero-Knowledge Proof (ZKP) Schnorr Identification Protocol ***/     
    /* Structure */
    typedef struct
    {
        const EC_POINT *generator;
        EC_GROUP *group;
        BIGNUM *order;
    } parameters_t;
    
    typedef struct
    {
        EC_POINT *commitment;
        BIGNUM *privateKey;
        EC_POINT *publicKey;
        BIGNUM *randomNonce; // Nonce = Number Used Once
        BIGNUM *response;
    } prover_t;
    
    typedef struct
    {
        BIGNUM *challenge;
        EC_POINT *side[2];
    } verifier_t;
    
    /* Variable */
    BIGNUM *bnTemp = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *ecTemp = NULL;
    parameters_t parameters;
    prover_t prover;
    verifier_t verifier;
    
    /* Set Up */
    (void)memset(&parameters, 0, sizeof(parameters));
    (void)memset(&prover, 0, sizeof(prover));
    (void)memset(&verifier, 0, sizeof(verifier));
    
    /*** Set Up ***/
    /* Miscellaneous */
    ctx = BN_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* Parameters */
    parameters.group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    TEST_ASSERT_NOT_NULL(parameters.group);
    parameters.generator = EC_GROUP_get0_generator(parameters.group);
    parameters.order = BN_new();
    TEST_ASSERT_NOT_NULL(parameters.order);
    TEST_ASSERT_EQUAL_INT(1, EC_GROUP_get_order(parameters.group, parameters.order, ctx));
    
    /* Prover */
    prover.privateKey = BN_new();
    TEST_ASSERT_NOT_NULL(prover.privateKey);
    prover.publicKey = EC_POINT_new(parameters.group);
    TEST_ASSERT_NOT_NULL(prover.publicKey);
    TEST_ASSERT_EQUAL_INT(1, BN_rand_range(prover.privateKey, parameters.order));
    TEST_ASSERT_EQUAL_INT(1, EC_POINT_mul(parameters.group, prover.publicKey, prover.privateKey, NULL, NULL, ctx));
    
    /*** Commitment */
    /* Set Up */
    prover.commitment = EC_POINT_new(parameters.group);
    TEST_ASSERT_NOT_NULL(prover.commitment);
    prover.randomNonce = BN_new();
    TEST_ASSERT_NOT_NULL(prover.randomNonce);
    
    /* Commit */
    TEST_ASSERT_EQUAL_INT(1, BN_rand_range(prover.randomNonce, parameters.order));
    TEST_ASSERT_EQUAL_INT(1, EC_POINT_mul(parameters.group, prover.commitment, prover.randomNonce, NULL, NULL, ctx));
    
    /*** Challenge ***/
    /* Set Up */
    verifier.challenge = BN_new();
    TEST_ASSERT_NOT_NULL(verifier.challenge);
    
    /* Challenge */
    TEST_ASSERT_EQUAL_INT(1, BN_rand_range(verifier.challenge, parameters.order));
    
    /*** Response ***/
    /* Set Up */
    prover.response = BN_new();
    TEST_ASSERT_NOT_NULL(prover.response);
    bnTemp = BN_new();
    TEST_ASSERT_NOT_NULL(bnTemp);
    
    /* Response */
    TEST_ASSERT_EQUAL_INT(1, BN_mod_mul(bnTemp, verifier.challenge, prover.privateKey, parameters.order, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_add(prover.response, prover.randomNonce, bnTemp, parameters.order, ctx));
    
    /* Clean Up */
    BN_free(bnTemp);
    
    /*** Verification ***/
    /* Set Up */
    ecTemp = EC_POINT_new(parameters.group);
    TEST_ASSERT_NOT_NULL(ecTemp);
    verifier.side[0] = EC_POINT_new(parameters.group);
    TEST_ASSERT_NOT_NULL(verifier.side[0]);
    verifier.side[1] = EC_POINT_new(parameters.group);
    TEST_ASSERT_NOT_NULL(verifier.side[1]);
    
    /* Calculate */
    TEST_ASSERT_EQUAL_INT(1, EC_POINT_mul(parameters.group, verifier.side[0], prover.response, NULL, NULL, ctx));
    TEST_ASSERT_EQUAL_INT(1, EC_POINT_mul(parameters.group, ecTemp, NULL, prover.publicKey, verifier.challenge, ctx));
    TEST_ASSERT_EQUAL_INT(1, EC_POINT_add(parameters.group, verifier.side[1], prover.commitment, ecTemp, ctx));
    
    /* Verify */
    TEST_ASSERT_EQUAL_INT(0, EC_POINT_cmp(parameters.group, verifier.side[0], verifier.side[1], ctx));
    
    /* Clean Up */
    EC_POINT_free(ecTemp);
    
    /*** Clean Up ***/
    /* Miscellaneous */
    BN_CTX_free(ctx);
    
    /* Parameters */
    EC_GROUP_free(parameters.group);
    BN_free(parameters.order);
    
    /* Prover */
    EC_POINT_free(prover.commitment);
    BN_free(prover.privateKey);
    EC_POINT_free(prover.publicKey);
    BN_free(prover.randomNonce);
    BN_free(prover.response);
    
    /* Verifier */
    BN_free(verifier.challenge);
    EC_POINT_free(verifier.side[0]);
    EC_POINT_free(verifier.side[1]);
}
