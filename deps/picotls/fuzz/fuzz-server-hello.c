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

static int fake_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls,
                          ptls_iovec_t src) {
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // key exchanges
  ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
  key_exchanges[0] = &ptls_openssl_secp256r1;
  ptls_cipher_suite_t *cipher_suites[] = {&ptls_openssl_aes128gcmsha256, NULL};

  // create ptls_context_t
  ptls_context_t ctx_client = {deterministic_random_bytes, &ptls_get_time,
                               key_exchanges, cipher_suites};
  ctx_client.verify_certificate = NULL;

  // create pls_t
  ptls_t *tls_client = ptls_new(&ctx_client, 0);  // 0: client

  // fake ticket saving
  static struct st_util_save_ticket_t st;
  st.super.cb = fake_ticket_cb;
  ctx_client.save_ticket = &st.super;

  // empty hsprop
  ptls_handshake_properties_t hsprop = {{{{NULL}}}};

  // buffers
  ptls_buffer_t client_encbuf;
  ptls_buffer_init(&client_encbuf, "", 0);

  // generate client_hello
  ptls_handshake(tls_client, &client_encbuf, NULL, 0, &hsprop);

  // reset buffer
  ptls_buffer_dispose(&client_encbuf);
  ptls_buffer_init(&client_encbuf, "", 0);

  // accept server
  size_t consumed = size;
  int ret =
      ptls_handshake(tls_client, &client_encbuf, data, &consumed, &hsprop);

  // more messages to parse?
  if (ret == 0 && size - consumed > 0) {
    size = size - consumed;
    // reset buffer
    ptls_buffer_dispose(&client_encbuf);
    ptls_buffer_init(&client_encbuf, "", 0);
    // receive messages
    ptls_receive(tls_client, &client_encbuf, data + consumed, &size);
  }

  // cleaning
  ptls_buffer_dispose(&client_encbuf);
  ptls_free(tls_client);

  return 0;
}
