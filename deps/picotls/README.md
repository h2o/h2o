picotls
===

[![Build Status](https://travis-ci.org/h2o/picotls.svg?branch=master)](https://travis-ci.org/h2o/picotls)

Picotls is a [TLS 1.3](https://tlswg.github.io/tls13-spec/) implementation written in C.

At the moment, the library implements draft-22 of the specification, including support 0-RTT resumption using PSK or PSK-DHE.

Primary goal of the project is to create a fast, tiny TLS 1.3 implementation that can be used with the HTTP/2 protocol stack and possibly the upcoming QUIC stack of the [H2O HTTP/2 server](https://h2o.examp1e.net).

Picotls only implements the communination protocol; cryptographic operations are delegated to cryptographic engines.
At the moment, _minicrypto_ binding (uses [cifra](https://github.com/ctz/cifra/) and [micro-ecc](https://github.com/kmackay/micro-ecc)) and _openssl_ binding are provided.

License and algorithms supported by the bindings are as follows:

| Binding | License | Key Exchange | Certificate | AEAD cipher |
|:-----:|:-----:|:-----:|:-----:|:-----:|
| minicrypto | [CC0](https://github.com/ctz/cifra/) / [2-clause BSD](https://github.com/kmackay/micro-ecc) | secp256r1, x25519 | ECDSA (P256)<sup>1</sup> | AES-128-GCM |
| OpenSSL | OpenSSL | secp256r1 | RSA, ECDSA (P256) | AES-128-GCM |

Note 1: Minicrypto binding is capable of signing a handshake using the certificate's key, but cannot verify a signature sent by the peer.

Building picotls
---

If you have cloned picotls from git then ensure that you have initialised the submodules:
```
% git submodule init
% git submodule update
```

Build using cmake:
```
% cmake .
% make
% make check
```

A dedicated documentation for using picotls with Visual Studio can be found in [WindowsPort.md](WindowsPort.md).

Developer documentation
---

Developer documentation should be available on [the wiki](https://github.com/h2o/picotls/wiki).

Using the cli command
---

Run the test server (at 127.0.0.1:8443):
```
% ./cli -c /path/to/certificate.pem -k /path/to/private-key.pem  127.0.0.1 8443
```

Connect to the test server:
```
% ./cli 127.0.0.1 8443
```

Using resumption:
```
% ./cli -s session-file 127.0.0.1 8443
```
The session-file is read-write.
The cli server implements a single-entry session cache.
The cli server sends NewSessionTicket when it first sends application data after receiving ClientFinished.

Using early-data:
```
% ./cli -s session-file -e 127.0.0.1 8443
```
When `-e` option is used, client first waits for user input, and then sends CLIENT_HELLO along with the early-data.

License
---

The software is provided under the MIT license.
Note that additional licences apply if you use the minicrypto binding (see above).
