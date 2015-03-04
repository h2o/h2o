asyncaddrinfo
===

`asyncaddrinfo.h` is a header file-only wrapper for `getaddrinfo(3)`.

It is capable of performing asynchronous lookups on Linux.  On other platforms, it will perform synchronous lookups using the same interface.

See `exmaples/` for how to use the library.
