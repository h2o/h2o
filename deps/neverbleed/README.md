Neverbleed
===============

Neverbleed is an [OpenSSL engine](https://www.openssl.org/docs/man1.0.2/crypto/engine.html) that runs RSA private key operations in an isolated process, thereby minimizing the risk of private key leak in case of vulnerability such as [Heartbleed](http://heartbleed.com/).

The engine is known to work together with existing versions of OpenSSL or LibreSSL, with minimal changes to the server source code.

FAQ
---

### Q. How much is the overhead?

Virtually none.

Generally speaking, private key operations are much more heavier than the overhead of inter-process communication.
On my Linux VM running on Core i7 @ 2.4GHz (MacBook Pro 15" Late 2013), OpenSSL 1.0.2 without privilege separation processes 319.56 full TLS handshakes per second, whereas OpenSSL with privilege separation processes 316.72 handshakes per second (note: RSA key length: 2,048 bits, selected cipher-suite: ECDHE-RSA-AES128-GCM-SHA256).

### Q. Why does the library only protect the private keys?

Because private keys are the only _long-term_ secret being used for encrypting and/or digitally-signing the communication.

Depending on how OpenSSL is used, it might be beneficial to separate symmetric cipher operations or TLS operations as a whole.
But even in such case, it would still be a good idea to isolate private key operations from them considering the impact of private key leaks.
In other words, separating private key operations only to an isolated process in always a good thing to do.

### Q. Is there any HTTP server that uses Neverbleed?

Neverbleed is used by [H2O](https://h2o.examp1e.net/) HTTP2 server since version [1.5.0-beta4](https://github.com/h2o/h2o/releases/tag/v1.5.0-beta4).

How-to
------

The library exposes two functions: `neverbleed_init` and `neverbleed_load_private_key_file`.

The first function spawns an external process dedicated to private key operations, and the second function assigns a RSA private key stored in the specified file to an existing SSL context (`SSL_CTX`).

By

1. adding call to `neverbleed_init`
2. replacing call to `SSL_CTX_use_PrivateKey_file` with `neverbleed_load_private_key_file`

the privilege separation engine will be used for all the incoming TLS connections.

```
  neverbleed_t nb;
  char errbuf[NEVERBLEED_ERRBUF_SIZE];

  /* initialize the OpenSSL library and the neverbleed engine */
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  if (neverbleed_init(&nb, errbuf) != 0) {
    fprintf(stderr, "neverbleed_init failed: %s\n", errbuf);
    ...
  }

  ...

  /* load certificate chain and private key */
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certchain_fn) != 1) {
    fprintf(stderr, "failed to load certificate chain file:%s\n", certchain_fn);
    ...
  }
  if (neverbleed_load_private_key_file(&nb, ctx, privkey_fn, errbuf) != 1) {
    fprintf(stderr, "failed to load private key from file:%s:%s\n", privkey_fn, errbuf);
    ...
  }
```

Also, `neverbleed_setuidgid` function can be used to drop the privileges of the daemon process once it completes loading all the private keys.
