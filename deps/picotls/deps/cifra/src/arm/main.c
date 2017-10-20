#ifndef TEST
# error You must select a function to test.
#endif

#include "semihost.h"
#include "aes.h"
#include "hmac.h"
#include "sha2.h"
#include "sha3.h"
#include "modes.h"
#include "salsa20.h"
#include "curve25519.h"
#include "poly1305.h"
#include "norx.h"
#include "chacha20poly1305.h"

#include <stdio.h>

typedef void (*measure_fn)(void);
static uint32_t bracket; /* bracket mode parameter */

static void do_nothing(void)
{
}

static void stack_64w(void)
{
  volatile uint32_t words[64];
  words[0] = 0;
  words[63] = 0;
  (void) words[63];
}

static void stack_8w(void)
{
  volatile uint32_t words[8];
  words[0] = 0;
  words[7] = 0;
  (void) words[7];
}

static void hashtest_sha256(void)
{
  uint8_t hash[CF_SHA256_HASHSZ];
  cf_sha256_context ctx;
  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "", 0);
  cf_sha256_digest_final(&ctx, hash);
}

static void hashtest_sha512(void)
{
  uint8_t hash[CF_SHA512_HASHSZ];
  cf_sha512_context ctx;
  cf_sha512_init(&ctx);
  cf_sha512_update(&ctx, "", 0);
  cf_sha512_digest_final(&ctx, hash);
}

static void hashtest_sha3_256(void)
{
  uint8_t hash[CF_SHA3_256_HASHSZ];
  cf_sha3_context ctx;
  cf_sha3_256_init(&ctx);
  cf_sha3_256_update(&ctx, "", 0);
  cf_sha3_256_digest_final(&ctx, hash);
}

static void hashtest_sha3_512(void)
{
  uint8_t hash[CF_SHA3_512_HASHSZ];
  cf_sha3_context ctx;
  cf_sha3_512_init(&ctx);
  cf_sha3_512_update(&ctx, "", 0);
  cf_sha3_512_digest_final(&ctx, hash);
}

static void aes128block_test(void)
{
  uint8_t key[16] = { 0 }, block[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
  cf_aes_encrypt(&ctx, block, block);
}

static void aes128sched_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
}

static void aes256block_test(void)
{
  uint8_t key[32] = { 0 }, block[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
  cf_aes_encrypt(&ctx, block, block);
}

static void aes256sched_test(void)
{
  uint8_t key[32] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
}

static void aes128gcm_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[12] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_gcm_encrypt(&cf_aes, &ctx,
                 msg, sizeof msg,
                 aad, sizeof aad,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);
}

static void aes128eax_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[12] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_eax_encrypt(&cf_aes, &ctx,
                 msg, sizeof msg,
                 aad, sizeof aad,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);
}

static void aes128ccm_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[11] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_ccm_encrypt(&cf_aes, &ctx,
                 msg, sizeof msg, 4,
                 aad, sizeof aad,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);
}

static void salsa20_test(void)
{
  uint8_t key[32] = { 0 };
  uint8_t nonce[8] = { 0 };
  uint8_t msg[64] = { 0 };
  uint8_t cipher[64] = { 0 };

  cf_salsa20_ctx ctx;
  cf_salsa20_init(&ctx, key, sizeof key, nonce);
  cf_salsa20_cipher(&ctx, msg, cipher, sizeof msg);
}

static void chacha20_test(void)
{
  uint8_t key[32] = { 0 };
  uint8_t nonce[8] = { 0 };
  uint8_t msg[64] = { 0 };
  uint8_t cipher[64] = { 0 };

  cf_chacha20_ctx ctx;
  cf_chacha20_init(&ctx, key, sizeof key, nonce);
  cf_chacha20_cipher(&ctx, msg, cipher, sizeof msg);
}

static void curve25519_test(void)
{
  uint8_t secret[32] = { 1 };
  uint8_t pubkey[32];
  cf_curve25519_mul_base(pubkey, secret);
}

static const uint8_t *mac_message = (const uint8_t *) "hello world";
static const size_t mac_message_len = 11;

static void poly1305_test(void)
{
  uint8_t key[32] = { 0 },
          nonce[16] = { 0 },
          encnonce[16],
          mac[16];

  cf_aes_context aes;
  cf_aes_init(&aes, key, 16);
  cf_aes_encrypt(&aes, nonce, encnonce);

  cf_poly1305 poly;
  cf_poly1305_init(&poly, key + 16, encnonce);
  cf_poly1305_update(&poly, mac_message, mac_message_len);
  cf_poly1305_finish(&poly, mac);
}

static void hmacsha256_test(void)
{
  uint8_t key[32] = { 0 },
          mac[32] = { 0 };

  cf_hmac_ctx ctx;
  cf_hmac_init(&ctx, &cf_sha256, key, sizeof key);
  cf_hmac_update(&ctx, mac_message, mac_message_len);
  cf_hmac_finish(&ctx, mac);
}

static void norx_test(void)
{
  uint8_t key[16] = { 0 };
  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[8] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_norx32_encrypt(key,
                    nonce,
                    aad, sizeof aad,
                    msg, sizeof msg,
                    NULL, 0,
                    cipher,
                    tag);
}

#ifndef BRACKET_MODE
# define AEADPERF_LEN 1
#else
# define AEADPERF_LEN BRACKET_END
#endif

static uint8_t aead_msg[AEADPERF_LEN] = { 0 };
static uint8_t aead_cipher[AEADPERF_LEN] = { 0 };
static uint8_t aead_aad[16] = { 0 };
static uint8_t aead_key[32] = { 0 };
static uint8_t aead_nonce[16] = { 0 };
static uint8_t aead_tag[16] = { 0 };

static void aeadperf_norx(void)
{
  cf_norx32_encrypt(aead_key, aead_nonce,
                    aead_aad, sizeof aead_aad,
                    aead_msg, bracket,
                    NULL, 0,
                    aead_cipher, aead_tag);
}

static void aeadperf_chacha20poly1305(void)
{
  cf_chacha20poly1305_encrypt(aead_key, aead_nonce,
                              aead_aad, sizeof aead_aad,
                              aead_msg, bracket,
                              aead_cipher, aead_tag);
}
static void aeadperf_aes128gcm(void)
{
  cf_aes_context ctx;
  cf_aes_init(&ctx, aead_key, 16);

  cf_gcm_encrypt(&cf_aes, &ctx,
                 aead_msg, bracket,
                 aead_aad, sizeof aead_aad,
                 aead_nonce, 12,
                 aead_cipher,
                 aead_tag, 16);
}

static void aeadperf_aes128ccm(void)
{
  cf_aes_context ctx;
  cf_aes_init(&ctx, aead_key, 16);

  cf_ccm_encrypt(&cf_aes, &ctx,
                 aead_msg, bracket,
                 4,
                 aead_aad, sizeof aead_aad,
                 aead_nonce, 11,
                 aead_cipher,
                 aead_tag, 16);
}

static void aeadperf_aes128eax(void)
{
  cf_aes_context ctx;
  cf_aes_init(&ctx, aead_key, 16);

  cf_eax_encrypt(&cf_aes, &ctx,
                 aead_msg, bracket,
                 aead_aad, sizeof aead_aad,
                 aead_nonce, 12,
                 aead_cipher,
                 aead_tag, 16);
}

static void aeadperf_aes256gcm(void)
{
  cf_aes_context ctx;
  cf_aes_init(&ctx, aead_key, 32);

  cf_gcm_encrypt(&cf_aes, &ctx,
                 aead_msg, bracket,
                 aead_aad, sizeof aead_aad,
                 aead_nonce, 12,
                 aead_cipher,
                 aead_tag, 16);
}

static void aeadperf_aes256ccm(void)
{
  cf_aes_context ctx;
  cf_aes_init(&ctx, aead_key, 32);

  cf_ccm_encrypt(&cf_aes, &ctx,
                 aead_msg, bracket,
                 4,
                 aead_aad, sizeof aead_aad,
                 aead_nonce, 11,
                 aead_cipher,
                 aead_tag, 16);
}

static void aeadperf_aes256eax(void)
{
  cf_aes_context ctx;
  cf_aes_init(&ctx, aead_key, 32);

  cf_eax_encrypt(&cf_aes, &ctx,
                 aead_msg, bracket,
                 aead_aad, sizeof aead_aad,
                 aead_nonce, 12,
                 aead_cipher,
                 aead_tag, 16);
}

/* Provided by linkscript */
extern uint32_t __HeapLimit;

#define STACK_MAGIC 0x57ac34df

static __attribute__((noinline)) void clear_stack(void)
{
  uint32_t *stack_start = &__HeapLimit;
  uint32_t ss = 0, *stack_stop = &ss;
  size_t words = stack_stop - stack_start;
  for (size_t i = 0; i < words; i++)
    stack_start[i] = STACK_MAGIC;
}

static __attribute__((noinline)) uint32_t measure_stack(void)
{
  uint32_t *stack_start = &__HeapLimit;
  uint32_t ss, *stack_stop = &ss;
  size_t words = stack_stop - stack_start;
  for (size_t i = 0; i < words; i++)
    if (stack_start[i] != STACK_MAGIC)
      return words - i + 4; /* we used 4 words for ourselves, roughly */

  return 0;
}

static void measure(measure_fn fn)
{
  clear_stack();
  uint32_t start_cycles = reset_cycles();
  fn();
  uint32_t end_cycles = get_cycles();
  uint32_t stack_words = measure_stack();

  emit("cycles = ");
  emit_uint32(end_cycles - start_cycles);
  emit("\n");
  emit("stack = ");
  emit_uint32(stack_words << 2);
  emit("\n");
}

#define STRING_(x) #x
#define STRING(x) STRING_(x)

int main(void)
{
  emit(STRING(TEST) "\n");
#ifdef BRACKET_MODE
  for (bracket = BRACKET_START; bracket <= BRACKET_END; bracket += BRACKET_STEP)
  {
    emit("bracket = ");
    emit_uint32(bracket);
    emit("\n");
    measure(TEST);
  }
#else
  measure(TEST);
#endif
  quit_success();

  (void) bracket;
  (void) do_nothing;
  (void) stack_8w;
  (void) stack_64w;
  (void) hashtest_sha256;
  (void) hashtest_sha512;
  (void) hashtest_sha3_256;
  (void) hashtest_sha3_512;
  (void) aes128block_test;
  (void) aes128sched_test;
  (void) aes256block_test;
  (void) aes256sched_test;
  (void) aes128gcm_test;
  (void) aes128eax_test;
  (void) aes128ccm_test;
  (void) salsa20_test;
  (void) chacha20_test;
  (void) curve25519_test;
  (void) poly1305_test;
  (void) hmacsha256_test;
  (void) norx_test;
  (void) aeadperf_norx;
  (void) aeadperf_chacha20poly1305;
  (void) aeadperf_aes128gcm;
  (void) aeadperf_aes128ccm;
  (void) aeadperf_aes128eax;
  (void) aeadperf_aes256gcm;
  (void) aeadperf_aes256ccm;
  (void) aeadperf_aes256eax;
}
