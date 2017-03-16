/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "curve25519.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_base_mul(void)
{
  uint8_t secret[32];
  uint8_t public[32];
  uint8_t expect[32];

  unhex(secret, 32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  unhex(expect, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  cf_curve25519_mul_base(public, secret);
  TEST_CHECK(memcmp(expect, public, 32) == 0);
  
  unhex(secret, 32, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  unhex(expect, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  cf_curve25519_mul_base(public, secret);
  TEST_CHECK(memcmp(expect, public, 32) == 0);
}

static void test_mul(void)
{
  uint8_t scalar[32];
  uint8_t public[32];
  uint8_t shared[32];
  uint8_t expect[32];

  unhex(scalar, 32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  unhex(public, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  unhex(expect, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  cf_curve25519_mul(shared, scalar, public);
  TEST_CHECK(memcmp(expect, shared, 32) == 0);
}

TEST_LIST = {
  { "base-mul", test_base_mul },
  { "mul", test_mul },
  { 0 }
};

