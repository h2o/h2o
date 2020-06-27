// bcrypt-test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <wincompat.h>
#include <bcrypt.h>
#include <stdio.h>
#include "picotls/ptlsbcrypt.h"
#include "picotls/minicrypto.h"

int KeyInit(BCRYPT_KEY_HANDLE *hKey, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz, const BYTE *proposedKey,
            DWORD proposedKeyLength, BYTE **ko, ULONG *ko_length)
{
    DWORD cbData = 0;
    HANDLE hAlgo = NULL;

    // Open an algorithm handle.
    NTSTATUS ret = BCryptOpenAlgorithmProvider(&hAlgo, name, NULL, 0);

    if (BCRYPT_SUCCESS(ret)) {
        // Set the properties to define the chaining mode
        ret = BCryptSetProperty(hAlgo, BCRYPT_CHAINING_MODE, (PBYTE)chain_mode, (ULONG)chain_mode_sz, 0);
    }

    *ko = NULL;
    *ko_length = 0;

    if (BCRYPT_SUCCESS(ret)) {
        DWORD ko_size = 0;
        ULONG cbResult = 0;

        ret = BCryptGetProperty(hAlgo, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ko_size, (ULONG)sizeof(ko_size), &cbResult, 0);

        if (BCRYPT_SUCCESS(ret)) {
            *ko = (uint8_t *)malloc(ko_size);
            if (*ko == NULL) {
                ret = STATUS_NO_MEMORY;
            } else {
                *ko_length = ko_size;
                memset(*ko, 0, *ko_length);
            }
        }
    }

    if (BCRYPT_SUCCESS(ret)) {
        // Generate the key from supplied input key bytes.
        ret = BCryptGenerateSymmetricKey(hAlgo, hKey, *ko, *ko_length, (PBYTE)proposedKey, proposedKeyLength, 0);
    } else {
        if (*ko != NULL) {
            free(*ko);
            *ko = NULL;
            *ko_length = 0;
        }
    }

    if (hAlgo != NULL) {
        BCryptCloseAlgorithmProvider(hAlgo, 0);
    }

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

void KeyRelease(BCRYPT_KEY_HANDLE *hKey, BYTE **ko, ULONG *ko_length)
{
    BCryptDestroyKey(*hKey);
    *hKey = NULL;
    if (*ko) {
        free(*ko);
    }
    *ko = NULL;
    *ko_length = 0;
}

int EncodeOneShot(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz, BYTE *key,
                  ULONG key_length,
    BYTE* iv, ULONG iv_length,
    BYTE *data, ULONG dataLength, uint64_t seq, BYTE *authData, ULONG authDataLength, ULONG authTagLength,
    BYTE *encrypted, ULONG encryptedLengthMax, ULONG *encryptedLength)
{

    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *authTag = encrypted + dataLength;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bacmi;
    BYTE iv_nonce[PTLS_MAX_IV_SIZE];
    BYTE *ko = NULL;
    ULONG ko_length = 0;
    int ret = 0;

    *encryptedLength = 0;

    if (KeyInit(&hKey, name, chain_mode, chain_mode_sz, key, key_length, &ko, &ko_length) != 0) {
        return -1;
    }

    memset(authTag, 0, authTagLength);
    // Set the auth mode info for AEAD
    BCRYPT_INIT_AUTH_MODE_INFO(bacmi);
    ptls_aead__build_iv(aead, iv_nonce, iv, seq);
    bacmi.pbNonce = iv_nonce;
    bacmi.cbNonce = iv_length;
    bacmi.pbAuthData = authData;
    bacmi.cbAuthData = authDataLength;
    bacmi.pbTag = authTag;
    bacmi.cbTag = authTagLength;
    /* All other fields are set to NULL by the INIT macro. */

    /* If called with a NULL pointer for the data block, we will merely compute the block size. */
    DWORD cbCipherText = 0;
    NTSTATUS status = BCryptEncrypt(hKey, data, dataLength, &bacmi, NULL, 0, encrypted, encryptedLengthMax, &cbCipherText, 0);

    KeyRelease(&hKey, &ko, &ko_length);

    if (BCRYPT_SUCCESS(status)) {
        *encryptedLength = cbCipherText + authTagLength;
    } else {
        ret = -1;
    }

    return ret;
}

int DecodeOneShot(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz, 
    BYTE *key, ULONG key_length, BYTE * iv, ULONG iv_length, BYTE *encrypted,
                  ULONG encryptedLength, uint64_t seq, BYTE *authData, ULONG authDataLength,
                  ULONG authTagLength, BYTE *decrypted, ULONG decryptedLengthMax, ULONG *decryptedLength)
{

    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *authTag = encrypted + (encryptedLength - authTagLength);
    BYTE iv_nonce[PTLS_MAX_IV_SIZE];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bacmi;
    BYTE *ko = NULL;
    ULONG ko_length = 0;
    int ret = 0;

    *decryptedLength = 0;

    if (KeyInit(&hKey, name, chain_mode, chain_mode_sz, key, key_length, &ko, &ko_length) != 0) {
        return -1;
    }

    // Set the auth mode info for AEAD
    BCRYPT_INIT_AUTH_MODE_INFO(bacmi);
    ptls_aead__build_iv(aead, iv_nonce, iv, seq);
    bacmi.pbNonce = iv_nonce;
    bacmi.cbNonce = iv_length;
    bacmi.pbAuthData = authData;
    bacmi.cbAuthData = authDataLength;
    bacmi.pbTag = authTag;
    bacmi.cbTag = authTagLength;
    /* All other fields are set to NULL by the INIT macro. */

    /* If called with a NULL pointer for the data block, we will merely compute the block size. */
    DWORD cbCipherText = 0;
    NTSTATUS status = BCryptDecrypt(hKey, encrypted, encryptedLength - authTagLength, &bacmi, NULL, 0, decrypted,
                                    decryptedLengthMax, &cbCipherText, 0);

    KeyRelease(&hKey, &ko, &ko_length);

    if (BCRYPT_SUCCESS(status)) {
        *decryptedLength = cbCipherText;
    } else {
        ret = -1;
    }

    return ret;
}

int test_oneshot(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz)
{
    BYTE key[32];
    BYTE data[123];
    BYTE iv[PTLS_MAX_IV_SIZE];
    uint64_t nonce;
    BYTE authData[9];
    BYTE encrypted[256];
    ULONG encryptedLength;
    BYTE decrypted[256];
    ULONG decryptedLength;
    ULONG authTagLength = (ULONG)aead->tag_size;
    int ret = 0;

    assert(sizeof(key) >= aead->key_size);
    assert(sizeof(iv) >= aead->iv_size);
    assert(sizeof(data) + authTagLength <= sizeof(encrypted));
    assert(sizeof(decrypted) >= sizeof(encrypted));

    memset(key, 'k', sizeof(key));
    memset(data, 'd', sizeof(data));
    memset(iv, 'n', sizeof(iv));
    nonce = 0;
    memset(authData, 'a', sizeof(authData));

    ret = EncodeOneShot(aead, name, chain_mode, chain_mode_sz, key, (ULONG)aead->key_size, iv, (ULONG)aead->iv_size, data,
        123, nonce, authData, 9, authTagLength, encrypted, 256, &encryptedLength);

    printf("Encrypt one shot returns %d, l=%d\n", ret, encryptedLength);

    if (ret == 0) {
        ret = DecodeOneShot(aead, name, chain_mode, chain_mode_sz, key, (ULONG)aead->key_size, 
            iv, (ULONG)aead->iv_size, encrypted, encryptedLength, nonce, authData, 9, 
            authTagLength, decrypted, 256, &decryptedLength);

        printf("Decrypt one shot returns %d, l=%d\n", ret, decryptedLength);

        if (ret == 0) {
            if (decryptedLength != 123) {
                printf("Wrong length, not %d\n", 123);
                ret = -1;
            } else if (memcmp(data, decrypted, 123) != 0) {
                printf("Data and decrypted don't match\n");
                ret = -1;
            } else {
                printf("One shot matches.\n");
            }
        }
    }

    return ret;
}

void delete_test_aead_context(ptls_aead_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->dispose_crypto(ctx);
        free(ctx);
    }
}

ptls_aead_context_t *new_test_aead_context(ptls_aead_algorithm_t *aead, int is_enc, BYTE *key, BYTE *iv)
{
    int ret = 0;
    ptls_aead_context_t *ctx = (ptls_aead_context_t *)malloc(aead->context_size);

    if (ctx != NULL) {
        memset(ctx, 0, aead->context_size);
        *ctx = (ptls_aead_context_t){aead};
        if (aead->setup_crypto(ctx, is_enc, key, iv) != 0) {
            printf("For %s, setup returns %d\n", aead->name, ret);
            delete_test_aead_context(ctx);
            ctx = NULL;
        }
    } else {
        printf("For %s, memory error during setup\n", aead->name);
    }

    return (ctx);
}

int test_decrypt(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz)
{
    BYTE key[32];
    BYTE iv[PTLS_MAX_IV_SIZE];
    BYTE data[123];
    uint64_t nonce;
    BYTE authData[9];
    BYTE encrypted[256];
    ULONG encryptedLength;
    BYTE decrypted[256];
    size_t decryptedLength;
    ULONG authTagLength = (ULONG)aead->tag_size;
    ptls_aead_context_t *ctx = NULL;
    int ret = 0;

    assert(sizeof(key) >= aead->key_size);
    assert(sizeof(iv) >= aead->iv_size);
    assert(sizeof(data) + authTagLength <= sizeof(encrypted));
    assert(sizeof(decrypted) >= sizeof(encrypted));

    memset(key, 'k', sizeof(key));
    memset(iv, 'n', sizeof(iv));
    memset(data, 'd', sizeof(data));
    nonce = 0;
    memset(authData, 'a', sizeof(authData));

    /* Create a decryption context */
    ctx = new_test_aead_context(aead, 0, key, iv);
    if (ctx == NULL) {
        ret = -1;
    }

    /* Do a simple encrypt using one shot bcrypt */
    if (ret == 0) {
        ret = EncodeOneShot(aead, name, chain_mode, chain_mode_sz, key, (ULONG)aead->key_size, 
            iv, (ULONG)aead->iv_size, data, 123, nonce,
            authData, 9, authTagLength, encrypted, 256, &encryptedLength);
    }

    /* Try decrypt with library procedure */
    if (ret == 0) {
        decryptedLength = ctx->do_decrypt(ctx, decrypted, encrypted, encryptedLength, nonce, authData, 9);
        if (decryptedLength >= encryptedLength) {
            printf("For %s, decrypt returns %d\n", aead->name, (int)decryptedLength);
            ret = -1;
        } else if (decryptedLength != 123) {
            printf("For %s, decrypt returns %d instead of %d\n", aead->name, (int)decryptedLength, 123);
            ret = -1;
        } else if (memcmp(data, decrypted, decryptedLength) != 0) {
            printf("For %s, decrypted does not match clear text\n", aead->name);
            ret = -1;
        } else {
            printf("For %s, decrypting test passes.\n", aead->name);
        }
    }

    delete_test_aead_context(ctx);

    return ret;
}

int test_encrypt(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz)
{
    BYTE key[32];
    BYTE iv[PTLS_MAX_IV_SIZE];
    BYTE data[123];
    uint64_t nonce;
    BYTE authData[9];
    BYTE encryptedRef[256];
    ULONG encryptedRefLength;
    BYTE encrypted[256];
    size_t encryptedLength;
    ULONG authTagLength = (ULONG)aead->tag_size;
    ptls_aead_context_t *ctx = NULL;
    int ret = 0;

    assert(sizeof(key) >= aead->key_size);
    assert(sizeof(iv) >= aead->iv_size);
    assert(sizeof(data) + authTagLength <= sizeof(encrypted));
    assert(sizeof(data) + authTagLength <= sizeof(encryptedRef));

    memset(key, 'k', sizeof(key));
    memset(iv, 'n', sizeof(iv));
    memset(data, 'd', sizeof(data));
    nonce = 0;
    memset(authData, 'a', sizeof(authData));

    /* Create an encryption context */
    ctx = new_test_aead_context(aead, 1, key, iv);
    if (ctx == NULL) {
        ret = -1;
    }

    /* Do a simple encrypt using one shot bcrypt */
    if (ret == 0) {
        ret = EncodeOneShot(aead, name, chain_mode, chain_mode_sz, key, (ULONG)aead->key_size, 
            iv, (ULONG)aead->iv_size, data, 123, nonce,
            authData, 9, authTagLength, encryptedRef, 256, &encryptedRefLength);
    }

    /* Try encrypt with library procedure */
    if (ret == 0) {
        ctx->do_encrypt_init(ctx, nonce, authData, 9);
        encryptedLength = ctx->do_encrypt_update(ctx, encrypted, data, 123);
        encryptedLength += ctx->do_encrypt_final(ctx, &encrypted[encryptedLength]);

        if (encryptedLength != encryptedRefLength) {
            printf("For %s, encrypt returns %d instead of %d\n", aead->name, (int)encryptedLength, encryptedRefLength);
            ret = -1;
        } else if (memcmp(encryptedRef, encrypted, encryptedRefLength) != 0) {
            printf("For %s, encrypted does not match ref\n", aead->name);
            for (ULONG i = 0; i < encryptedRefLength; i++) {
                if (encryptedRef[i] != encrypted[i]) {
                    printf("For %s, encrypted[%d] = 0x%02x vs encryptedRef[%d] = 0x%02x\n", aead->name, i, encrypted[i], i,
                           encryptedRef[i]);
                    break;
                }
            }
            ret = -1;
        } else {
            printf("For %s, encrypting test passes.\n", aead->name);
        }
    }

    delete_test_aead_context(ctx);

    return ret;
}

int test_for_size(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz)
{
    BYTE key[32];
    BYTE iv[PTLS_MAX_IV_SIZE];
    uint64_t nonce;
    BYTE authData[9];
    BYTE *data = NULL;
    BYTE *encrypted = NULL;
    BYTE *decrypted = NULL;
    size_t encryptedLength;
    size_t decryptedLength;
    ULONG authTagLength = (ULONG)aead->tag_size;
    ptls_aead_context_t *ctx_e = NULL;
    ptls_aead_context_t *ctx_d = NULL;
    ULONG packet_size[] = {1500, 128, 3, 0};
    ULONG nb_packet_size = (ULONG)(sizeof(packet_size) / sizeof(ULONG));
    int ret = 0;

    assert(sizeof(key) >= aead->key_size);
    assert(sizeof(iv) >= aead->iv_size);

    memset(key, 'k', sizeof(key));
    memset(key, 'n', sizeof(iv));
    nonce = 0;
    memset(authData, 'a', sizeof(authData));

    /* Create the encryption contexts */
    ctx_e = new_test_aead_context(aead, 1, key, iv);
    ctx_d = new_test_aead_context(aead, 0, key, iv);

    if (ctx_e == NULL || ctx_d == NULL) {
        ret = -1;
    }

    /* Test a variety of packet sizes */
    for (ULONG i = 0; ret == 0 && i < nb_packet_size; i++) {
        ULONG data_size = (packet_size[i] > 0) ? packet_size[i] : 128;
        ULONG encrypted_size = packet_size[i] + authTagLength;

        data = (BYTE *)malloc(data_size);
        encrypted = (BYTE *)malloc(encrypted_size);
        decrypted = (BYTE *)malloc(data_size);

        if (data == NULL || encrypted == NULL || decrypted == NULL) {
            printf("For %s: cannot allocate memory for packet size[%d] = %d\n", aead->name, i, packet_size[i]);
        } else {
            memset(data, 'd', data_size);

            ctx_e->do_encrypt_init(ctx_e, nonce, authData, 9);
            encryptedLength = ctx_e->do_encrypt_update(ctx_e, encrypted, data, packet_size[i]);
            encryptedLength += ctx_e->do_encrypt_final(ctx_e, &encrypted[encryptedLength]);
            decryptedLength = ctx_d->do_decrypt(ctx_d, decrypted, encrypted, encryptedLength, nonce, authData, 9);

            if (decryptedLength >= encryptedLength) {
                printf("For %s, decrypt returns %d\n", aead->name, (int)decryptedLength);
                ret = -1;
            } else if (decryptedLength != packet_size[i]) {
                printf("For %s, decrypt returns %d instead of %d\n", aead->name, (int)decryptedLength, packet_size[i]);
                ret = -1;
            } else if (memcmp(data, decrypted, decryptedLength) != 0) {
                printf("For %s, decrypted does not match clear text\n", aead->name);
                ret = -1;
            } else {
                printf("For %s, test packet size[%d] = %d passes.\n", aead->name, i, packet_size[i]);
            }
        }

        if (data != NULL) {
            free(data);
            data = NULL;
        }

        if (encrypted != NULL) {
            free(encrypted);
            encrypted = NULL;
        }

        if (decrypted != NULL) {
            free(decrypted);
            decrypted = NULL;
        }
    }

    delete_test_aead_context(ctx_e);
    delete_test_aead_context(ctx_d);

    return ret;
}

int test_one_aead(ptls_aead_algorithm_t *aead, wchar_t *name, wchar_t *chain_mode, size_t chain_mode_sz)
{
    int ret = test_oneshot(aead, name, chain_mode, chain_mode_sz);

    printf("For %s, test one shot returns %d\n", aead->name, ret);

    if (ret == 0) {
        ret = test_decrypt(aead, name, chain_mode, chain_mode_sz);

        printf("For %s, test decrypt returns %d\n", aead->name, ret);
    }

    if (ret == 0) {
        ret = test_encrypt(aead, name, chain_mode, chain_mode_sz);

        printf("For %s, test encrypt returns %d\n", aead->name, ret);
    }

    if (ret == 0) {
        ret = test_for_size(aead, name, chain_mode, chain_mode_sz);

        printf("For %s, test packet sizes returns %d\n", aead->name, ret);
    }

    return ret;
}

/* Test of cipher functions.
 * The test verifies that a message encode with a bcrypt function can be
 * decoded with a minicrypto function, and vice versa.
 */

int test_cipher_one_way(char const *name1, char const *name2, ptls_cipher_algorithm_t *b1, ptls_cipher_algorithm_t *b2,
                        unsigned int nb_blocks)
{
    BYTE key[32];
    BYTE nonce[16];
    BYTE data[128];
    BYTE encrypted[128];
    BYTE decrypted[128];
    size_t data_size = b1->block_size * nb_blocks;
    ptls_cipher_context_t *ctx1 = NULL;
    ptls_cipher_context_t *ctx2 = NULL;
    int ret = 0;

    assert(sizeof(key) >= b1->key_size);
    assert(sizeof(data) >= data_size);
    assert(sizeof(nonce) >= b1->iv_size);

    memset(key, 'k', sizeof(key));
    memset(data, 'd', data_size);

    ctx1 = ptls_cipher_new(b1, 1, key);
    ctx2 = ptls_cipher_new(b2, 0, key);

    if (ctx1 == NULL || ctx2 == NULL) {
        ret = -1;
    } else {
        memset(nonce, 0, sizeof(nonce));
        if (ctx1->do_init != NULL) {
            ctx1->do_init(ctx1, nonce);
        }

        if (ctx2->do_init != NULL) {
            ctx2->do_init(ctx2, nonce);
        }

        ctx1->do_transform(ctx1, encrypted, data, data_size);
        ctx2->do_transform(ctx2, decrypted, encrypted, data_size);

        if (memcmp(data, decrypted, data_size) != 0) {
            printf("For %s -> %s, decrypted does not match clear text\n", name1, name2);
            ret = -1;
        } else {
            printf("For %s -> %s, test passes.\n", name1, name2);
        }
    }

    if (ctx1 != NULL) {
        ptls_cipher_free(ctx1);
    }

    if (ctx2 != NULL) {
        ptls_cipher_free(ctx2);
    }

    return ret;
}

int test_cipher_pair(char const *name1, char const *name2, ptls_cipher_algorithm_t *b1, ptls_cipher_algorithm_t *b2,
                     unsigned int nb_blocks)
{
    int ret = test_cipher_one_way(name1, name2, b1, b2, nb_blocks);

    if (ret == 0) {
        ret = test_cipher_one_way(name2, name1, b2, b1, nb_blocks);
    }

    return ret;
}

/* Test of the hash functions
 */

int test_hash_calc(char const *name1, char const *name2, ptls_hash_algorithm_t *h1, ptls_hash_algorithm_t *h2)
{
    BYTE data[123];
    BYTE tag1[128];
    BYTE tag2[128];
    ptls_hash_context_t *ctx1 = NULL;
    ptls_hash_context_t *ctx2 = NULL;
    int ret = 0;

    assert(sizeof(tag1) >= h1->digest_size);
    assert(sizeof(tag2) >= h2->digest_size);
    assert(h1->digest_size == h2->digest_size);

    memset(data, 'd', sizeof(data));
    memset(tag1, '1', sizeof(tag1));
    memset(tag2, '2', sizeof(tag2));

    if (h1->digest_size != h2->digest_size) {
        ret = -1;
    }
    if (ret == 0) {
        ret = ptls_calc_hash(h1, tag1, data, sizeof(data));
    }

    if (ret == 0) {
        ret = ptls_calc_hash(h2, tag2, data, sizeof(data));
    }

    if (ret == 0){
        if (memcmp(tag1, tag2, h1->digest_size) != 0) {
            printf("For %s -> %s, hash1 does not match hash2\n", name1, name2);
            ret = -1;
        } else {
            printf("For %s -> %s, hash test passes.\n", name1, name2);
        }
    }

    return ret;
}

/* Minimal test program for the bcrypt functions.
 * Need to add tests for the SHA256 and SHA384 implementations.
 */

int main()
{
    int ret = 0;

    ret |= test_cipher_pair("bcrypt aes128ecb", "minicrypto aes128ecb", &ptls_bcrypt_aes128ecb, &ptls_minicrypto_aes128ecb, 1);
    ret |= test_cipher_pair("bcrypt aes256ecb", "minicrypto aes256ecb", &ptls_bcrypt_aes256ecb, &ptls_minicrypto_aes256ecb, 1);

    ret |= test_cipher_pair("bcrypt aes128ctr", "minicrypto aes128ctr", &ptls_bcrypt_aes128ctr, &ptls_minicrypto_aes128ctr, 4);
    ret |= test_cipher_pair("bcrypt aes256ctr", "minicrypto aes256ctr", &ptls_bcrypt_aes256ctr, &ptls_minicrypto_aes256ctr, 4);
        
    ret |= test_one_aead(&ptls_bcrypt_aes128gcm, BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM));

    ret |= test_one_aead(&ptls_bcrypt_aes256gcm, BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM));

    ret |= test_hash_calc("bcrypt sha256", "minicrypto sha256", &ptls_bcrypt_sha256, &ptls_minicrypto_sha256);
    ret |= test_hash_calc("bcrypt sha384", "minicrypto sha384", &ptls_bcrypt_sha384, &ptls_minicrypto_sha384);

    exit(ret);
}
