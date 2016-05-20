[![Build Status](https://travis-ci.org/cybozu/libyrmcds.png)](https://travis-ci.org/cybozu/libyrmcds)
libyrmcds
=========

libyrmcds is a [memcached][] client library written in C.  
This is a companion to [yrmcds][], a memcached compatible KVS.

In addition to the library itself, a client program called `yc` is included.

Features
--------

* Minimalistic.

    libyrmcds does *not* provide any rich features like consistent hashing.
    Instead, it can be used as a base library to implement such rich
    features.

* Designed for binary protocol.

    In order to access the true power of the binary protocol, libyrmcds
    is designed primarily for binary protocol.  Limited support for the
    text protocol is provided, though.

* Support for [yrmcds][] extensions.

    Specifically, [the server-side locking][locking] and [the counter extension][counter] is supported.

* Separated send / recv operations.

    Although the socket used in libyrmcds is blocking, receiving results
    from the server is separated from the sending operations.  You can
    even use a different thread to receive results asynchronously.

* Optional compression with [LZ4][].

    Large objects can be transparently compressed/uncompressed with
    [LZ4][] compression algorithm.

Build
-----

Just run `make`.

To support [transparent LZ4 compression][compress], obtain LZ4 source
code and rebuild the library as follows:

```
$ make lz4
$ make clean; make
```

Install
-------

Place `yrmcds.h` and `libyrmcds.a` to appropriate directories.

Usage
-----

See [USAGE.md](USAGE.md).

Authors & Contributors
----------------------

* Yamamoto, Hirotaka [@ymmt2005](https://github.com/ymmt2005)
* Nojima, Yusuke [@nojima](https://github.com/nojima)
* Tanuma, Shuhei [@chobie](https://github.com/chobie)
* Oku, Kazuho [@kazuho](https://github.com/kazuho)
* Fazal Majid [@fazalmajid](https://github.com/fazalmajid)

[memcached]: http://memcached.org/
[yrmcds]: http://cybozu.github.io/yrmcds/
[binprot]: https://code.google.com/p/memcached/wiki/BinaryProtocolRevamped
[locking]: https://github.com/cybozu/yrmcds/blob/master/docs/locking.md
[counter]: https://github.com/cybozu/yrmcds/blob/master/docs/counter.md
[LZ4]: https://code.google.com/p/lz4/
[compress]: USAGE.md#transparent-compression
