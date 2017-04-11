#include <stdint.h>
#include <stdio.h>

#include <openssl/evp.h>

#define MAX_LENGTH 1024

static void printhex(const uint8_t *buf, size_t len)
{
  for (size_t i = 0; i < len; i++)
    printf("%02x", buf[i]);
}

/* This test produces a single hash value which depends on
 * hashes with all preimage lengths up to max.
 *
 * It emits
 *  H(H(t(0)) || H(t(1)) || ... || H(t(max-1))))
 * where
 *  t(n) = (n % 256) ^ n
 * (informally, t(n) is a n-length octet string of octets with value n mod 256)
 */
static void emit_length_test(const char *name, const EVP_MD *h, size_t max)
{
  EVP_MD_CTX outer, inner;
  EVP_DigestInit(&outer, h);
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digestlen;

  for (size_t n = 0; n < max; n++)
  {
    EVP_DigestInit(&inner, h);
    for (size_t i = 0; i < n; i++)
    {
      uint8_t byte = n & 0xff;
      EVP_DigestUpdate(&inner, &byte, 1);
    }
    digestlen = sizeof digest;
    EVP_DigestFinal(&inner, digest, &digestlen);

    EVP_DigestUpdate(&outer, digest, digestlen);
  }

  digestlen = sizeof digest;
  EVP_DigestFinal(&outer, digest, &digestlen);

  printf("%s(%zu) = ", name, max);
  printhex(digest, (size_t) digestlen);
  printf("\n");
}

int main(void)
{
  emit_length_test("SHA1", EVP_sha1(), MAX_LENGTH);
  emit_length_test("SHA224", EVP_sha224(), MAX_LENGTH);
  emit_length_test("SHA256", EVP_sha256(), MAX_LENGTH);
  emit_length_test("SHA384", EVP_sha384(), MAX_LENGTH);
  emit_length_test("SHA512", EVP_sha512(), MAX_LENGTH);
  return 0;
}
