golombset
===

Golombset is a pure-C, header-file-only implementation of Golomb coded set, which is an compressed form of [Bloom filter](https://en.wikipedia.org/Bloom_filter).

It is compresses every zero-range of Bloom filter (e.g. `0000...1`) using [Golomb coding](https://en.wikipedia.org/wiki/Golomb_coding).
Please refer to [Golomb-coded sets: smaller than Bloom filters](http://giovanni.bajo.it/post/47119962313/golomb-coded-sets-smaller-than-bloom-filters) for more information about the algorithm.

API
---

__`int golombset_encode(unsigned fixed_bits, const unsigned *keys, size_t num_keys, void *buf, size_t *bufsize);`__

The function encodes an pre-sorted array of keys into given buffer.

The function returns zero if successful, or -1 if otherwise (e.g. the size of the buffer is not sufficient).
`bufsize` is an input-output parameter.
Upon calling the function the value of the pointer must specify the size of the buffer being supplied.
When the function returns successfully, the value is updated the length of the bytes actually used to store the encoded data.

__`int golombset_decode(unsigned fixed_bits, const void *buf, size_t bufsize, unsigned *keys, size_t *num_keys);`__

The function decodes the compressed data into an array of keys.

The function returns zero if successful, or -1 if the size of the `keys` buffer is too small (specified by `*num_keys` when the function is being called).
Upon successful return, the number of keys decoded will be stored in `*num_keys`.
