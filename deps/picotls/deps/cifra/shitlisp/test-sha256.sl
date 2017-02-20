(assert (=
	(sha256 (bytes "abc"))
	[ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad])
)

(assert (=
	(sha256 (bytes "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	[248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1])
)

(assert (=
	(sha256 (* (bytes "a") 1000000))
	[cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0])
)

(assert (=
	(sha256 (bytes "The quick brown fox jumps over the lazy dog"))
	[d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592])
)

(assert (=
	(sha256 (bytes "The quick brown fox jumps over the lazy cog"))
	[e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be])
)

(assert (=
	(sha256 [])
	[e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855])
)

(assert (=
	(hmac-sha256 (* [0b] 20) (bytes "Hi There"))
	[b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7])
)

(assert (=
	(hmac-sha256 (bytes "Jefe") (bytes "what do ya want for nothing?"))
	[5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843])
)

(assert (=
	(hmac-sha256 (* [aa] 20) (* [dd] 50))
	[773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe])
)

(assert (=
	(hmac-sha256 [0102030405060708090a0b0c0d0e0f10111213141516171819] (* [cd] 50))
	[82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b])
)

(assert (=
	(hmac-sha256 (* [aa] 131) (bytes "Test Using Larger Than Block-Size Key - Hash Key First"))
	[60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54])
)

(assert (=
	(hmac-sha256 (* [aa] 131) (bytes "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
	[9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2])
)


(puts success)
