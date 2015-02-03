Usage
=====

`yc`
----

`yc` is a memcached/yrmcds client program.  It provides access to all
libyrmcds library functions therefore access to all server functions.

`yc` prints out its usage when invoked without command-line arguments.

Minimal example
---------------

```c
#include <yrmcds.h>

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <stdio.h>

void check_error(yrmcds_error e) {
    if( e != 0 ) {
        if( e == YRMCDS_SYSTEM_ERROR ) {
            error(0, errno, "system error");
        } else {
            fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));
        }
        exit(2);
    }
}

void check_response(const yrmcds_response* r) {
    if( r->status != YRMCDS_STATUS_OK ) {
        fprintf(stderr, "Command failed: 0x%04x %.*s\n",
                r->status, (int)r->data_len, r->data);
        exit(3);
    }
}

int main(int argc, char** argv) {
    yrmcds c;
    yrmcds_response r;

    check_error( yrmcds_connect(&c, "localhost", 11211) );
    check_error( yrmcds_noop(&c, NULL) );
    check_error( yrmcds_recv(&c, &r) );
    check_response(&r);
    check_error( yrmcds_close(&c) );

    return 0;
}
```

Compilation and linking
-----------------------

Link with `-lyrmcds -lpthread` as follows:

```
gcc -g -O2 -o foo foo.c -lyrmcds -lpthread
```

Request serial number
---------------------

All command sending functions can issue a unique serial number of the
command.  This can be used when you receive responses asynchronously
as described in the next section.

```c
uint32_t async_cas(yrmcds* c) {
    uint32_t serial;
    // try compare-and-swap
    check_error( yrmcds_set(&c, "abc", 3, "12345", 5, 0, 0, 5, 0, &serial) );
    return serial;
}
```

Multi-threading
---------------

All functions in libyrmcds are thread-safe as long as different `yrmcds`
structs are used.  Additionally, any number of threads can use command
sending functions such as `yrmcds_get()` or `yrmcds_set()` even when
they share the same `yrmcds` struct.

Further, `yrmcds_recv()` can be used in parallel with command sending
functions.  You can create a dedicated thread to receive server responses
asynchronously.  Use request serial numbers to identify a response's
request.

```c
void async_recv(yrmcds* c, void (*notify)(uint32_t, yrmcds_response* r)) {
    yrmcds_respone r;
    while( 1 ) {
        check_error( yrmcds_recv(&c, &r) );
        (*notify)(r.serial, &r);
    }
}
```

Transparent compression
-----------------------

libyrmcds provides optional transparent data compression by [LZ4][].

To use this feature, the library must be built with LZ4 as follows:

```
$ make lz4
$ make
```

If the library supports LZ4 compression, you can enable transparent
LZ4 (de)compression for large objects.  The threshold for compression
can be set by `yrmcds_set_compression()`.  The compression is disabled
by default.

Note that all clients must support and enable the compression to
properly handle compressed data.

Counter extension
-----------------

yrmcds has a distributed counter extension for resource management.
If the extension is enabled in server, you can access counters by `yrmcds_cnt_*` functions.
The usage of each function is very similar to the corresponding `yrmcds_` function.

The minimum example is:

```c
#include <yrmcds.h>

#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>

void check_error(yrmcds_error e) {
    if( e != YRMCDS_OK ) {
        if( e == YRMCDS_SYSTEM_ERROR ) {
            error(0, errno, "system error");
        } else {
            fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));
        }
        exit(2);
    }
}

void check_response(const yrmcds_cnt_response* r) {
    if( r->status != YRMCDS_STATUS_OK ) {
        fprintf(stderr, "Command failed: 0x%02x %.*s\n",
                r->status, (int)r->body_length, r->body);
        exit(3);
    }
}

int main(void) {
    yrmcds_cnt c;
    yrmcds_cnt_response r;

    check_error( yrmcds_cnt_connect(&c, "localhost", 11215) );
    check_error( yrmcds_cnt_noop(&c, NULL) );
    check_error( yrmcds_cnt_recv(&c, &r) );
    check_response(&r);
    check_error( yrmcds_cnt_close(&c) );

    return 0;
}
```

API documents
-------------

HTML documents generated with Doxygen is available [here][api].


[api]: http://cybozu.github.io/libyrmcds/html/
[LZ4]: https://code.google.com/p/lz4/
