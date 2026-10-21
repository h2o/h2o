# Local modifications to the vendored copy of libgkc

`deps/libgkc` is a vendored copy of the garbage-collecting summary of
[kazuho/libgkc](https://github.com/kazuho/libgkc). It is tracked in this repository as ordinary files (it is
not a git submodule), so that the fork can carry local changes; the changes have to be re-applied when the
vendored copy is updated.

## 1. Use the compiler's `offsetof` where there is one

**Status:** applied in this repository. Upstream: not reported yet.

The file provided its own `offsetof` for the compilers that do not have one, spelling it as
`((size_t) &((TYPE *)0)->MEMBER)`. That spelling reads a member through a null pointer, which is undefined
behaviour, and the undefined behaviour sanitizer of the CI reports it at every use of the `container_of` macro
that is built on it — seven reports, all of them `member access within null pointer of type 'struct gkc_tuple'`.

The macro now uses `__builtin_offsetof` on the compilers that have it (GCC and Clang, and therefore every
compiler that the CI uses), and keeps the spelling of the original for the others.

**Files touched:** `gkc.c` (`offsetof`).
