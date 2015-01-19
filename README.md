H2O - an optimized HTTP server with support for HTTP/1.x and HTTP/2
===

[![Build Status](https://travis-ci.org/h2o/h2o.svg?branch=master)](https://travis-ci.org/h2o/h2o)

Copyright (c) 2014,2015 [DeNA Co., Ltd.](http://dena.com/), [Tatsuhiko Kubo](https://github.com/cubicdaiya/), [Domingo Alvarez Duarte](https://github.com/mingodad/), [Nick Desaulniers](https://github.com/nickdesaulniers/)

H2O is a very fast HTTP server written in C.  It can also be used as a library.

This is the README for H2O version 0.9.1-alpha1 (HEAD).

### License

[The MIT License](http://opensource.org/licenses/MIT).

Includes third-party softwares (also licensed under the MIT license): [klib](https://github.com/attractivechaos/klib/), [picohttpparser](https://github.com/h2o/picohttpparser), [hpack-huffman-table.h](https://github.com/h2o/h2o/blob/master/lib/http2/hpack_huffman_table.h).

### Features

- HTTP/1.0, HTTP/1.1
 - uses [PicoHTTPParser](https://github.com/h2o/picohttpparser)
 - persistent connections
 - chunked encoding
- [HTTP/2](http://http2.github.io/)
 - draft 16 (and draft 14 to support older clients)
 - negotiation methods: NPN, ALPN, Upgrade, direct
 - dependency and weight-based prioritization
- [WebSocket](http://www.ietf.org/rfc/rfc6455.txt)
 - uses [wslay](https://github.com/tatsuhiro-t/wslay/)
 - only usable at library level
- TLS
 - uses [OpenSSL](https://www.openssl.org/)
 - forward secrecy
 - AEAD ciphers
 - OCSP stapling (automatically enabled)
 - session resumption (internal memory)
- static file serving
 - conditional GET using last-modified / etag
 - directory listing
 - mime-type configuration
- reverse proxy
 - HTTP/1 only (no HTTPS)
 - persistent upstream connection
- access-logging
 - apache-like format strings
- graceful restart and self-upgrade
 - via [Server::Starter](http://search.cpan.org/~kazuho/Server-Starter-0.17/start_server)

Using the Standalone Server
---

### Installation

Following softwares are required to build the standalone server.  It is likely that you would be possible to find and install them as part of your operation system (by running yum, apt-get, brew, etc. depending on the OS).

- [cmake](http://www.cmake.org/)
- [libyaml](http://pyyaml.org/wiki/LibYAML)
- [OpenSSL](https://www.openssl.org/) (1.0.2 or above is recommended)

Download and extract a source release from [here](https://github.com/h2o/h2o/releases), or clone the Git repository.

Run the commands below.  The last command installs `h2o` (the standalone server) to `usr/local`.

```
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local .
$ make
$ sudo make install
```

Type `make test` to run the unit tests (note that extra components are required for running the tests; a complete list of prerequisites can be found in the `before_script` section of [.travis.yml](https://github.com/h2o/h2o/blob/master/.travis.yml)).

### Running the Server

First, let's try running the server using a configuration file included in the `examples/` directory.  The command below invokes the standalone server using [examples/h2o/h2o.conf](https://github.com/kazuho/h2o/blob/master/examples/h2o/h2o.conf), which directs the server to listen on port 8080.  Try accessing [http://127.0.0.1:8080/](http://127.0.0.1:8080/).

```
$ h2o -c examples/h2o/h2o.conf
```

Use [`--help` to print a list of command line options and configuration directives that can be used](https://gist.github.com/kazuho/f15b79211ea76f1bf6e5).

```
$ ./h2o --help
```

Building the Library
---

H2O can also be used as a software library with [libuv version 1.0.0](https://github.com/joyent/libuv).
Note that prior versions of libuv cannot be used due to massive changes to the APIs in 1.0.0.

Examples can be found within the [examples/](https://github.com/kazuho/h2o/blob/master/examples/) directory.

For the time being, using libh2o as a submodule is the recommend way.

```
$ cmake .
$ make libh2o
```

Benchmarks
---

### Remote Benchmark

The scores were recorded on Amazon EC2 running two c3.8xlarge instances (server and client) on a single network placement.

![benchmark results](http://kazuhooku.com/~kazuho/h2o.github.io/h2o-bench-0.9.0.png)

note: for reverse-proxy tests, another H2O process running on the same host was used as the upstream server

### Local Benchmark

The scores (requests/second.core) were recorded on Ubuntu 14.04 (x86-64) / VMware Fusion 7.1.0 / OS X 10.9.5 / MacBook Pro 15" Early 2013

__HTTP/1.1__

|Server \ size of content|6 bytes|4,096 bytes|
|------------------------|------:|----------:|
|h2o/0.9.0               | 75,483|     59,673|
|nginx/1.7.9 ([conf](https://gist.github.com/kazuho/c9c12021567e3ab83809))            | 37,289|     43,988|

note: `wrk -c 500 -d 30 -t 1`

__HTTP/2__

|Server \ size of content|6 bytes|4,096 bytes|
|------------------------|------:|----------:|
|h2o/0.9.0 ([conf](https://gist.github.com/kazuho/5966cafb40e4473a62f8))              |272,300|    116,022|
|tiny-nghttpd ([nghttpd @ ab1dd11](https://github.com/tatsuhiro-t/nghttp2/)) |198,018|93,868|
|[trusterd @ cff8e15](https://github.com/matsumoto-r/trusterd) |167,306|67,600|

note: `h2load -c 500 -m 100 -n 2000000`

Further Reading
---

- [Presentation slides at HTTP2 Conference](http://www.slideshare.net/kazuho/h2o-20141103pptx) - discusses the design of H2O and the motives behind
- [Kazuho's Weblog](http://blog.kazuhooku.com/) - the developers weblog (with [H2O+in English](http://blog.kazuhooku.com/search/label/H2O+in%20English) tag, [H2O+日本語](http://blog.kazuhooku.com/search/label/H2O+日本語) tag)
