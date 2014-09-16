H2O - an optimized HTTP server / library implementation
===

H2O is an optimized server implementation with support for HTTP/1, HTTP/2, websocket running either on TCP or TLS (i.e. HTTPS and WSS).

It uses libuv as its backend, but a tiny event loop is also provided in case speed / code footprint is important.

Building and Running the Server
---

Run the commands below to build and run the H2O server.  The last command will read the configuration from [etc/h2o.conf](https://github.com/kazuho/h2o/blob/master/examples/h2o.conf) and start listening on port 8080.  Try accessing [http://127.0.0.1:8080/](http://127.0.0.1:8080/).

```
$ cmake .
$ make h2o
$ ./h2o -c examples/h2o.conf
```

Building the Library
---

```
$ cmake .
$ make libh2o
```

The library is designed to work together with the upcoming [libuv version 1.0.0](https://github.com/joyent/libuv).  Examples can be found within the [exmaples/](https://github.com/kazuho/h2o/blob/master/examples/) directory.
