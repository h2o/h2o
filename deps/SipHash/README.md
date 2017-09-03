# SipHash

Reference implementation of SipHash, a family of pseudorandom functions
optimized for speed on short messages.

SipHash was designed as a mitigation to [hash-flooding DoS
attacks](https://131002.net/siphash/siphashdos_29c3_slides.pdf).
It is now used in the hash tables implementation of Python, Ruby, Perl
5, etc.

SipHash was designed by [Jean-Philippe Aumasson](https://131002.net) and
[Daniel J. Bernstein](http://cr.yp.to). 


## Usage

Running

```sh
  make
```

will build tests for 

* SipHash-2-4, the default version of SipHash returning 64-bit tags
* SipHash-2-4 with doubled tag size, i.e. 128-bit tags
* HalfSipHash-2-4, a version of SipHash working with 32-bit words and
  returning 32-bit tags by default
* HalfSipHash-2-4 with doubled tag size, i.e. 64-bit tags


```C
  ./test
```

verifies 64 test vectors, and

```C
  ./debug
```

does the same and prints intermediate values.

The code can be adapted to implement SipHash-*c*-*d*, the version of SipHash
with *c* compression rounds and *d* finalization rounds, by tweaking the
lines
```C
#define cROUNDS 2
#define dROUNDS 4
```

Obviously, if the number of rounds is modified then the test vectors
won't verify.



## Intellectual property

The SipHash reference code is released under [CC0
license](https://creativecommons.org/publicdomain/zero/1.0/), a public
domain-like licence.

We aren't aware of any patents or patent applications relevant to
SipHash, and we aren't planning to apply for any.


## References

The [SipHash page](https://131002.net/siphash) includes
* a list of third-party implementations and modules
* a list of projects using SipHash
* references to cryptanalysis results
