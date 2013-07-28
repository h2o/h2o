libyrmcds
=========

libyrmcds is a [memcached][] client library written in C.  
This is a companion to [yrmcds][], a memcached compatible KVS.

Features
--------

* Minimalistic.

    libyrmcds does *not* provide any rich features like consistent hashing.
    Instead, it can be used as a base library to implement such rich
    features.

* Only the binary protocol is supported.

    By supporting only the latest [binary protocol][binprot], libyrmcds
    provides full access to the every aspect of the protocol.

* Support for [yrmcds][] extensions.

    Specifically, [the server-side locking][locking] is supported.

* Separated send / recv operations.

    Although the socket used in libyrmcds is blocking, receiving results
    from the server is separated from the sending operations.  You can
    even use a different thread to receive results asynchronously.

Build
-----

Just run `make`.

Install
-------

Place `yrmcds.h` and `libyrmcds.a` to appropriate directories.

Usage
-----

See [USAGE.md](USAGE.md).

[memcached]: http://memcached.org/
[yrmcds]: http://cybozu.github.io/yrmcds/
[binproto]: https://code.google.com/p/memcached/wiki/BinaryProtocolRevamped
[locking]: https://github.com/cybozu/yrmcds/blob/master/docs/locking.md
