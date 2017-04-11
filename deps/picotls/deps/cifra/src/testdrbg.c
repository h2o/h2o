/*
 * cifra - embedded cryptography library
 * Written in 2016 by Joseph Birr-Pixton <jpixton@gmail.com>
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

#include "drbg.h"
#include "sha1.h"
#include "sha2.h"

#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_hashdrbg_sha256_vector(void)
{
  uint8_t entropy[32], nonce[16], persn[32], reseed[32], got[128], expect[128];

  /* This is the first KAT from NIST's CAVP example
   * file for SHA-256 with all inputs used; line 4360. */
  unhex(entropy, sizeof entropy, "b87bb4de5c148d964fc0cb612d69295671780b4270fe32bf389b6f49488efe13");
  unhex(nonce, sizeof nonce, "27eb37a0c695c4ee3c9b70b7f6b33492");
  unhex(persn, sizeof persn, "52321406ac8a9c266b1f8d811bb871269e5824b59a0234f01d358193523bbb7c");
  unhex(reseed, sizeof reseed, "7638267f534c4e6ee22cc6ca6ed824fd5d3d387c00b89dd791eb5ac9766385b8");

  unhex(expect, sizeof expect, "de01c061651bab3cef2fc4ea89a56b6e86e74b2e9fd11ed671c97c813778a06a2c1f41b41e754a5257750c6bde9601da9d67d8d9564f4a8538b92516a2dacc496dee257b85393f2a01ad59aa3257f1b6da9566e3706d2d6d4a26e511b0c64d7dc223acb24827178afa43ca8d5a66f983d6929dc61564c4c14fc32d85765a23f7");

  cf_hash_drbg_sha256 ctx;
  cf_hash_drbg_sha256_init(&ctx, entropy, sizeof entropy, nonce, sizeof nonce, persn, sizeof persn);
  cf_hash_drbg_sha256_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);

  /* This is line 5064 from Hash_DRBG.rsp */
  unhex(entropy, sizeof entropy, "63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569");
  unhex(nonce, sizeof nonce, "808aa38f2a72a62359915a9f8a04ca68");
  /* no persn */
  unhex(reseed, sizeof reseed, "e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3");
  unhex(expect, sizeof expect, "04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17");

  cf_hash_drbg_sha256_init(&ctx, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  cf_hash_drbg_sha256_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hashdrbg_sha256_vector_addnl(void)
{
  uint8_t entropy[32], nonce[16], reseed[32], got[128], expect[128], addnl[32];

  /* Hash_DRBG.rsp, line 5230. No personlisation string, but with additional data. */
  unhex(entropy, sizeof entropy, "9cfb7ad03be487a3b42be06e9ae44f283c2b1458cec801da2ae6532fcb56cc4c");
  unhex(nonce, sizeof nonce, "a20765538e8db31295747ec922c13a69");
  unhex(reseed, sizeof reseed, "96bc8014f90ebdf690db0e171b59cc46c75e2e9b8e1dc699c65c03ceb2f4d7dc");
  unhex(expect, sizeof expect, "71c1154a2a7a3552413970bf698aa02f14f8ea95e861f801f463be27868b1b14b1b4babd9eba5915a6414ab1104c8979b1918f3094925aeab0d07d2037e613b63cbd4f79d9f95c84b47ed9b77230a57515c211f48f4af6f5edb2c308b33905db308cf88f552c8912c49b34e66c026e67b302ca65b187928a1aba9a49edbfe190");

  cf_hash_drbg_sha256 ctx;
  cf_hash_drbg_sha256_init(&ctx, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  unhex(addnl, sizeof addnl, "6fea0894052dab3c44d503950c7c72bd7b87de87cb81d3bb51c32a62f742286d");
  cf_hash_drbg_sha256_reseed(&ctx, reseed, sizeof reseed, addnl, sizeof addnl);
  unhex(addnl, sizeof addnl, "d3467c78563b74c13db7af36c2a964820f2a9b1b167474906508fdac9b2049a6");
  cf_hash_drbg_sha256_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  unhex(addnl, sizeof addnl, "5840a11cc9ebf77b963854726a826370ffdb2fc2b3d8479e1df5dcfa3dddd10b");
  cf_hash_drbg_sha256_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hmacdrbg_sha1_vector(void)
{
  uint8_t entropy[16], nonce[8], reseed[16], got[80], expect[80];

  /* HMAC_DRBG.rsp, line 8. */
  unhex(entropy, sizeof entropy, "79349bbf7cdda5799557866621c91383");
  unhex(nonce, sizeof nonce, "1146733abf8c35c8");
  unhex(reseed, sizeof reseed, "c7215b5b96c48e9b338c74e3e99dfedf");
  unhex(expect, sizeof expect, "c6a16ab8d420706f0f34ab7fec5adca9d8ca3a133e159ca6ac43c6f8a2be22834a4c0a0affb10d7194f1c1a5cf7322ec1ae0964ed4bf122746e087fdb5b3e91b3493d5bb98faed49e85f130fc8a459b7");

  cf_hmac_drbg ctx;
  cf_hmac_drbg_init(&ctx, &cf_sha1, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  cf_hmac_drbg_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hmac_drbg_gen(&ctx, got, sizeof got);
  cf_hmac_drbg_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hmacdrbg_sha1_vector_addnl(void)
{
  uint8_t entropy[16], nonce[8], reseed[16], got[80], expect[80], addnl[16];

  /* HMAC_DRBG.rsp, line 174. */
  unhex(entropy, sizeof entropy, "7d7052a776fd2fb3d7191f733304ee8b");
  unhex(nonce, sizeof nonce, "be4a0ceedca80207");
  unhex(reseed, sizeof reseed, "49047e879d610955eed916e4060e00c9");
  unhex(expect, sizeof expect, "a736343844fc92511391db0addd9064dbee24c8976aa259a9e3b6368aa6de4c9bf3a0effcda9cb0e9dc33652ab58ecb7650ed80467f76a849fb1cfc1ed0a09f7155086064db324b1e124f3fc9e614fcb");

  cf_hmac_drbg ctx;
  cf_hmac_drbg_init(&ctx, &cf_sha1, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  unhex(addnl, sizeof addnl, "fd8bb33aab2f6cdfbc541811861d518d");
  cf_hmac_drbg_reseed(&ctx, reseed, sizeof reseed, addnl, sizeof addnl);
  unhex(addnl, sizeof addnl, "99afe347540461ddf6abeb491e0715b4");
  cf_hmac_drbg_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  unhex(addnl, sizeof addnl, "02f773482dd7ae66f76e381598a64ef0");
  cf_hmac_drbg_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hmacdrbg_sha256_vector(void)
{
  uint8_t entropy[32], nonce[16], reseed[32], got[128], expect[128];

  /* HMAC_DRBG.rsp, line 5064. */
  unhex(entropy, sizeof entropy, "06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d");
  unhex(nonce, sizeof nonce, "0e66f71edc43e42a45ad3c6fc6cdc4df");
  unhex(reseed, sizeof reseed, "01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552");
  unhex(expect, sizeof expect, "76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a80225422918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124");

  cf_hmac_drbg ctx;
  cf_hmac_drbg_init(&ctx, &cf_sha256, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  cf_hmac_drbg_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hmac_drbg_gen(&ctx, got, sizeof got);
  cf_hmac_drbg_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hmacdrbg_sha256_vector_addnl(void)
{
  uint8_t entropy[32], nonce[16], reseed[32], got[128], expect[128], addnl[32];

  /* HMAC_DRBG.rsp, line 5230. */
  unhex(entropy, sizeof entropy, "05ac9fc4c62a02e3f90840da5616218c6de5743d66b8e0fbf833759c5928b53d");
  unhex(nonce, sizeof nonce, "2b89a17904922ed8f017a63044848545");
  unhex(reseed, sizeof reseed, "2791126b8b52ee1fd9392a0a13e0083bed4186dc649b739607ac70ec8dcecf9b");
  unhex(expect, sizeof expect, "02ddff5173da2fcffa10215b030d660d61179e61ecc22609b1151a75f1cbcbb4363c3a89299b4b63aca5e581e73c860491010aa35de3337cc6c09ebec8c91a6287586f3a74d9694b462d2720ea2e11bbd02af33adefb4a16e6b370fa0effd57d607547bdcfbb7831f54de7073ad2a7da987a0016a82fa958779a168674b56524");

  cf_hmac_drbg ctx;
  cf_hmac_drbg_init(&ctx, &cf_sha256, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  unhex(addnl, sizeof addnl, "43bac13bae715092cf7eb280a2e10a962faf7233c41412f69bc74a35a584e54c");
  cf_hmac_drbg_reseed(&ctx, reseed, sizeof reseed, addnl, sizeof addnl);
  unhex(addnl, sizeof addnl, "3f2fed4b68d506ecefa21f3f5bb907beb0f17dbc30f6ffbba5e5861408c53a1e");
  cf_hmac_drbg_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  unhex(addnl, sizeof addnl, "529030df50f410985fde068df82b935ec23d839cb4b269414c0ede6cffea5b68");
  cf_hmac_drbg_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hmacdrbg_sha512_vector(void)
{
  uint8_t entropy[32], nonce[16], reseed[32], got[256], expect[256];

  /* HMAC_DRBG.rsp, line 10120. */
  unhex(entropy, sizeof entropy, "48c121b18733af15c27e1dd9ba66a9a81a5579cdba0f5b657ec53c2b9e90bbf6");
  unhex(nonce, sizeof nonce, "bbb7c777428068fad9970891f879b1af");
  unhex(reseed, sizeof reseed, "e0ffefdadb9ccf990504d568bdb4d862cbe17ccce6e22dfcab8b4804fd21421a");
  unhex(expect, sizeof expect, "05da6aac7d980da038f65f392841476d37fe70fbd3e369d1f80196e66e54b8fadb1d60e1a0f3d4dc173769d75fc3410549d7a843270a54a068b4fe767d7d9a59604510a875ad1e9731c8afd0fd50b825e2c50d062576175106a9981be37e02ec7c5cd0a69aa0ca65bddaee1b0de532e10cfa1f5bf6a026e47379736a099d6750ab121dbe3622b841baf8bdcbe875c85ba4b586b8b5b57b0fecbec08c12ff2a9453c47c6e32a52103d972c62ab9affb8e728a31fcefbbccc556c0f0a35f4b10ace2d96b906e36cbb72233201e536d3e13b045187b417d2449cad1edd192e061f12d22147b0a176ea8d9c4c35404395b6502ef333a813b6586037479e0fa3c6a23");

  cf_hmac_drbg ctx;
  cf_hmac_drbg_init(&ctx, &cf_sha512, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  cf_hmac_drbg_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hmac_drbg_gen(&ctx, got, sizeof got);
  cf_hmac_drbg_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hmacdrbg_sha512_vector_addnl(void)
{
  uint8_t entropy[32], nonce[16], reseed[32], got[256], expect[256], addnl[32];

  /* HMAC_DRBG.rsp, line 10286. */
  unhex(entropy, sizeof entropy, "4686a959e17dfb96c294b09c0f7a60efb386416cfb4c8972bcc55e44a151607a");
  unhex(nonce, sizeof nonce, "5226543b4c89321bbfb0f11f18ee3462");
  unhex(reseed, sizeof reseed, "5ef50daaf29929047870235c17762f5df5d9ab1af656e0e215fcc6fd9fc0d85d");
  unhex(expect, sizeof expect, "b60d8803531b2b8583d17bdf3ac7c01f3c65cf9b069862b2d39b9024b34c172b712db0704acb078a1ab1aec0390dbaee2dec9be7b234e63da481fd469a92c77bc7bb2cfca586855520e0f9e9d47dcb9bdf2a2fdfa9f2b4342ef0ea582616b55477717cfd516d46d6383257743656f7cf8b38402ba795a8c9d35a4aa88bec623313dad6ead689d152b54074f183b2fee556f554db343626cea853718f18d386bc8bebb0c07b3c5e96ceb391ffceece88864dbd3be83a613562c5c417a24807d5f9332974f045e79a9ade36994af6cf9bbeeb71d0025fcb4ad50f121cbc2df7cd12ff5a50cddfd9a4bbc6d942d743c8b8fbebe00eeccea3d14e07ff8454fa715da");

  cf_hmac_drbg ctx;
  cf_hmac_drbg_init(&ctx, &cf_sha512, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  unhex(addnl, sizeof addnl, "d2383c3e528492269e6c3b3aaa2b54fbf48731f5aa52150ce7fc644679a5e7c6");
  cf_hmac_drbg_reseed(&ctx, reseed, sizeof reseed, addnl, sizeof addnl);
  unhex(addnl, sizeof addnl, "c841e7a2d9d13bdb8644cd7f5d91d241a369e12dc6c9c2be50d1ed29484bff98");
  cf_hmac_drbg_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  unhex(addnl, sizeof addnl, "9054cf9216af66a788d3bf6757b8987e42d4e49b325e728dc645d5e107048245");
  cf_hmac_drbg_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

TEST_LIST = {
  { "hashdrbg-sha256", test_hashdrbg_sha256_vector },
  { "hashdrbg-sha256-addnl", test_hashdrbg_sha256_vector_addnl },
  { "hmacdrbg-sha1", test_hmacdrbg_sha1_vector },
  { "hmacdrbg-sha1-addnl", test_hmacdrbg_sha1_vector_addnl },
  { "hmacdrbg-sha256", test_hmacdrbg_sha256_vector },
  { "hmacdrbg-sha256-addnl", test_hmacdrbg_sha256_vector_addnl },
  { "hmacdrbg-sha512", test_hmacdrbg_sha512_vector },
  { "hmacdrbg-sha512-addnl", test_hmacdrbg_sha512_vector_addnl },
  { 0 }
};

