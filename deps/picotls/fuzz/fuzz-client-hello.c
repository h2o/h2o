#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"

void deterministic_random_bytes(void *buf, size_t len) {
  for (int i = 0; i < len; i++) {
    ((uint8_t *)buf)[i] = 0;
  }
}

uint8_t fake_ticket[] = {
    0x00, 0x4d, 0x70, 0x74, 0x6c, 0x73, 0x30, 0x30, 0x30, 0x31, 0x00, 0x00,
    0x01, 0x67, 0x7b, 0xce, 0xa7, 0x55, 0x00, 0x30, 0x45, 0xc2, 0x95, 0x37,
    0x16, 0x9e, 0x79, 0x8c, 0x0c, 0x53, 0x14, 0x3f, 0x15, 0x4c, 0x93, 0x8f,
    0x74, 0x65, 0x76, 0x7a, 0x76, 0x1e, 0x4f, 0x90, 0xbf, 0xa1, 0xb9, 0x54,
    0xfd, 0x4e, 0x06, 0x4a, 0xd4, 0xb2, 0x84, 0xad, 0x12, 0xc9, 0xf1, 0x1e,
    0x1a, 0x95, 0x85, 0xc5, 0x19, 0xc1, 0x69, 0x5f, 0x00, 0x17, 0x13, 0x02,
    0xed, 0xec, 0xfb, 0xd7, 0x00, 0x00, 0x00};

static int encrypt_ticket_cb_fake(ptls_encrypt_ticket_t *_self, ptls_t *tls,
                                  int is_encrypt, ptls_buffer_t *dst,
                                  ptls_iovec_t src) {
  (void)_self;
  int ret;

  if (is_encrypt) {
    if ((ret = ptls_buffer_reserve(dst, 32)) != 0) return ret;
    memcpy(dst->base + dst->off, fake_ticket, 32);
    dst->off += 32;
  } else {
    if ((ret = ptls_buffer_reserve(dst, sizeof(fake_ticket))) != 0) return ret;
    memcpy(dst->base + dst->off, fake_ticket, sizeof(fake_ticket));
    dst->off += sizeof(fake_ticket);
  }

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // key exchanges
  ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
  key_exchanges[0] = &ptls_openssl_secp256r1;
  // the second cipher suite is used for the PSK ticket
  ptls_cipher_suite_t *cipher_suites[] = {&ptls_openssl_aes128gcmsha256,
                                          &ptls_openssl_aes256gcmsha384, NULL};

  // create ptls_context_t
  ptls_context_t ctx_server = {deterministic_random_bytes, &ptls_get_time,
                               key_exchanges, cipher_suites};
  ctx_server.verify_certificate = NULL;

  // setup server fake cache
  struct st_util_session_cache_t sc;
  sc.super.cb = encrypt_ticket_cb_fake;
  ctx_server.ticket_lifetime = UINT_MAX;
  ctx_server.max_early_data_size = 8192;
  ctx_server.encrypt_ticket = &sc.super;

  // create pls_t
  ptls_t *tls_server = ptls_new(&ctx_server, 1);  // 1: server

  // empty hsprop
  ptls_handshake_properties_t hsprop = {{{{NULL}}}};

  // buffers
  ptls_buffer_t server_response;
  ptls_buffer_init(&server_response, "", 0);

  // accept client_hello
  size_t consumed = size;
  int ret =
      ptls_handshake(tls_server, &server_response, data, &consumed, &hsprop);

  // more messages to parse?
  if (ret == 0 && size - consumed > 0) {
    size = size - consumed;
    // reset buffer
    ptls_buffer_dispose(&server_response);
    ptls_buffer_init(&server_response, "", 0);
    // receive messages
    ptls_receive(tls_server, &server_response, data + consumed, &size);
  }

  // clean
  ptls_buffer_dispose(&server_response);
  ptls_free(tls_server);

  //
  return 0;
}
