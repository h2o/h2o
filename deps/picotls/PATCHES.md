# Local modifications to the vendored copy of picotls

`deps/picotls` is a vendored copy of [h2o/picotls](https://github.com/h2o/picotls). It is tracked in this
repository as ordinary files (it is not a git submodule), so that the fork can carry local changes; the
changes have to be re-applied when the vendored copy is updated.

## 1. Do not form a pointer from a null input in `ptls_handshake()`

**Status:** applied in this repository. Upstream: not reported yet.

`ptls_handshake()` receives the data that the peer has sent as `input` and `*inlen`. When there is
nothing to read, the caller passes a null `input` with a length of zero. The function then computed the
end of the input as `src + *inlen`, which is the addition of a zero offset to a null pointer, and, once
the input had been consumed, subtracted the two pointers from each other.

Both are undefined behaviour, and the undefined behaviour sanitizer of the CI reports them:
`runtime error: applying zero offset to null pointer` at `deps/picotls/lib/picotls.c:6124`.

The address of an empty buffer is used in place of the null pointer now, so that the arithmetic is
defined. The length of the input is zero in that case, so nothing is ever read from that buffer, and
the behaviour of the function is unchanged.

**Files touched:** `lib/picotls.c` (`empty_input`, `ptls_handshake()`).
