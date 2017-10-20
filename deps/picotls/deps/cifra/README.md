# Cifra
Cifra is a collection of cryptographic primitives targeted at embedded use.

[![Build Status](https://travis-ci.org/ctz/cifra.svg?branch=master)](https://travis-ci.org/ctz/cifra)

[![Documentation](https://readthedocs.org/projects/pip/badge/)](https://cifra.readthedocs.org/en/latest/)

[![Analysis Status](https://scan.coverity.com/projects/4324/badge.svg)](https://scan.coverity.com/projects/4324)

[![Coverage Status](https://coveralls.io/repos/ctz/cifra/badge.svg?branch=coveralls-scan)](https://coveralls.io/r/ctz/cifra?branch=coveralls-scan)

## Aims
In order of descending emphasis, cifra aims for:

* **Clarity** and **simplicity**.
* Countermeasures for side channel leaks inherent in some
  algorithms.
* Suitability for embedded use.  Particularly: cifra uses an
  absolute minimum of the standard C library and is reasonably
  efficient with respect to code and data space.

## Features
* **AES** in the **GCM**, **CCM**, **EAX** and **OCB** authenticated encryption modes.
* **NORX** authenticated encryption system.
* **SHA224**, **SHA256**, **SHA384** and **SHA512** hash functions (including **HMAC** and **PBKDF2**).
* **SHA3-224**, **SHA3-256**, **SHA3-384**, **SHA3-512** hash functions (FIPS 202 compatible).
* **ChaCha20** and **Salsa20** stream ciphers.
* **Poly1305** one time MAC.
* 100% code coverage by line, zero static analysis defects, valgrind-clean.

Additionally cifra imports curve25519 from elsewhere (&mu;NaCl, NaCl, tweetNaCl,
Adam Langley's curve25519-donna) for comparison between various implementations
on embedded targets.

## Documentation
Available at [Read the Docs](https://cifra.readthedocs.org/en/latest/).

## Testing
There is quite a lot of testing available:

* **Host builds**: run `make test` in the `src` directory.  This builds and
  runs assorted test programs.
* **Emulated embedded builds**: run `make test` in the `src/arm` directory.  This
  expects to find `qemu-system-gnuarmeclipse` on the path.  These tests assume
  a Cortex-M3 target.
* **Cortex-M0 on-target tests**: run `make test.stm32f0` in the `src/arm` directory.
  This expects to find `openocd` on the path, with an STM32F0xx attached via
  stlinkv2.  It uses ARM semihosting to report results.
* **Cortex-M3/4 on-target tests**: run `make test.stm32f1` or `make test.stm32f3` as above.

Additionally all embedded targets expect to find the `arm-none-eabi` toolchain
to be on the path.

## Measurements
All measurements performed at `-Os` (optimise for space), on the following MCUs: 

Core       | Part number   | Price (1s)   | Max clock  | Flash | SRAM
---------- | ------------- | ------------ | ---------- | ----- | -----
Cortex-M0  | STM32F030F4P6 | 1.17EUR      | 48MHz      | 16KB  | 4KB
Cortex-M3  | STM32F103C8T6 | 2.87EUR      | 72MHz      | 64KB  | 20KB
Cortex-M4F | STM32F303K6T6 | 4.53EUR      | 72MHz      | 32KB  | 12KB

More measurements are available for AEAD modes on my blog post:
[Benchmarking Modern Authenticated Encryption on €1 devices](http://jbp.io/2015/06/01/modern-authenticated-encryption-for-1-euro/).

## AES
This test does a key schedule, then encrypts one block.

### 128-bit key
Core       | Cycles (key schedule + block) | Cycles (key schedule) | Cycles (block) | Stack | Code size
---------- | ----------------------------- | --------------------- | -------------- | ----- | ---------
Cortex-M0  | 7156                          | 2147                  | 5009           | 312B  | 1020B    
Cortex-M3  | 4692                          | 1591                  | 3101           | 300B  | 960B     
Cortex-M4F | 4591                          | 1571                  | 3020           | 300B  | 960B     

### 256-bit key
Core       | Cycles (key schedule + block) | Cycles (key schedule) | Cycles (block) | Stack | Code size
---------- | ----------------------------- | --------------------- | -------------- | ----- | ---------
Cortex-M0  | 10611                         | 3650                  | 6961           | 396B  | 1100B    
Cortex-M3  | 6735                          | 2450                  | 4285           | 380B  | 1048B    
Cortex-M4F | 6588                          | 2416                  | 4172           | 380B  | 1048B    

## AES128-GCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 57022  | 796B  | 2600B
Cortex-M3  | 44306  | 812B  | 2644B
Cortex-M4F | 43657  | 812B  | 2644B

## AES128-EAX
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 50564  | 932B  | 2836B
Cortex-M3  | 32855  | 932B  | 2780B
Cortex-M4F | 32159  | 932B  | 2780B

## AES128-CCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 37677  | 772B  | 2280B
Cortex-M3  | 24462  | 780B  | 2256B
Cortex-M4F | 23949  | 780B  | 2256B

## NORX32
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 10692  | 320B  | 1636B
Cortex-M3  | 6909   | 320B  | 1820B
Cortex-M4F | 6855   | 320B  | 1820B

## ChaCha20
This test encrypts a 64 byte message.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 5981   | 564B  | 1416B
Cortex-M3  | 3487   | 544B  | 1328B
Cortex-M4F | 3468   | 544B  | 1328B

(For comparison with AES, add an AES256 key schedule plus 4 blocks.
That's about 33K cycles.)

## Salsa20
This test encrypts a 64 byte message.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 6173   | 560B  | 1412B
Cortex-M3  | 3320   | 552B  | 1272B
Cortex-M4F | 3311   | 552B  | 1272B

## SHA256
This test hashes the empty string (one compression function invocation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 11561  | 312B  | 1760B
Cortex-M3  | 6530   | 300B  | 1708B
Cortex-M4F | 6278   | 300B  | 1708B

## SHA512
This test hashes the empty string (one compression function invocation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 38447  | 796B  | 2888B
Cortex-M3  | 28771  | 836B  | 2988B
Cortex-M4F | 28777  | 836B  | 2980B

## SHA3-256
This test hashes the empty string (one sponge permutation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 93648  | 848B  | 2212B
Cortex-M3  | 74321  | 856B  | 2164B
Cortex-M4F | 72215  | 856B  | 2140B

## SHA3-512
This test hashes the empty string (one sponge permutation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 92565  | 880B  | 2212B
Cortex-M3  | 73509  | 888B  | 2164B
Cortex-M4F | 71419  | 888B  | 2140B

## HMAC-SHA256
This test computes a MAC with a 32 byte key over the
message "hello world".

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 48924  | 1328B | 2200B
Cortex-M3  | 28333  | 1324B | 2132B
Cortex-M4F | 27337  | 1324B | 2132B

## Poly1305-AES
This test computes a MAC with a 32 byte key over the
message "hello world".  It includes the AES nonce
processing.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 15719  | 704B  | 1920B
Cortex-M3  | 11328  | 696B  | 1964B
Cortex-M4F | 10706  | 696B  | 1932B

## Curve25519
This test is one point multiplication.

This uses the implementation from [&mu;NaCl](http://munacl.cryptojedi.org/curve25519-cortexm0.shtml)
by Düll, Haase, Hinterwälder, Hutter, Paar, Sánchez and Schwabe.

Core       | Cycles  | Stack | Code size
---------- | ------- | ----- | ---------
Cortex-M0  | 4070271 | 464B  | 5596B
Cortex-M3  | 3720363 | 448B  | 5536B
Cortex-M4F | 3720105 | 448B  | 5536B

See [curve25519-shootout](curve25519-shootout.md) for comparitive measurements
for other curve25519 implementations.

## C library requirements
Cifra requires `memcpy`, `memset`, and `abort`.

## Future
* ~~Keccak hash function (aka SHA3)~~.
* ~~Poly1305 one-time MAC~~.
* Constant time curve25519 for Cortex-M4F using the FPU.
* Constant time curve25519 for Cortex-M3 (avoiding the variable-time multiplier).

## Notable past bugs/advisories
* [Issue #2](https://github.com/ctz/cifra/issues/2): in all versions before commit
  [d62aa26e](https://github.com/ctz/cifra/commit/d62aa26e2c3c49e5b8a4298644cff290406d9357)
  (September 16th 2015) too much padding was added when hashing messages of certain
  lengths.  Specifically, messages whose length satisfied `len % 64 = 55` for
  SHA1/SHA224/SHA256 or `len % 128 = 119` for SHA384/SHA512.  SHA3 was not affected.
  Better testing is now in place.
* [Issue #3](https://github.com/ctz/cifra/issues/3): in all versions before commit
  [82d77cd8](https://github.com/ctz/cifra/commit/82d77cd8323f6d4473fcb68517752a778970138d)
  (April 16th 2016) EAX would produce wrong tags for empty AADs or messages.  The
  underlying CMAC is now more resistant to this case.

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

Please attribute the author.  This is a request only, and not a license term.

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
