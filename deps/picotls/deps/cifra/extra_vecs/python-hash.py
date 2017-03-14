#!/usr/bin/python2

#
# see openssl-hash for details of what this is computing
# you'll need python-sha3 from https://github.com/bjornedstrom/python-sha3
#

import hashlib
import sha3

# check sha3 at least works; pysha3 *DOES NOT* (it is keccak, not sha3)
assert '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532' == hashlib.sha3_256('abc').hexdigest()

def hh(x):
    return ''.join(['\\x' + x[y:y+2] for y in range(0, len(x), 2)])

def len_test(name, H, max):
    outer = H()

    for n in range(max):
        inner = H()
        inner.update(chr(n & 0xff) * n)
        outer.update(inner.digest())

    result = outer.hexdigest()
    print '%s(%d) = %s  or  %s' % (name, max, result, hh(result))

if __name__ == '__main__':
    MAX = 1024
    len_test('SHA1', hashlib.sha1, MAX)
    len_test('SHA224', hashlib.sha224, MAX)
    len_test('SHA256', hashlib.sha256, MAX)
    len_test('SHA384', hashlib.sha384, MAX)
    len_test('SHA512', hashlib.sha512, MAX)
    len_test('SHA3-224', hashlib.sha3_224, MAX)
    len_test('SHA3-256', hashlib.sha3_256, MAX)
    len_test('SHA3-384', hashlib.sha3_384, MAX)
    len_test('SHA3-512', hashlib.sha3_512, MAX)
