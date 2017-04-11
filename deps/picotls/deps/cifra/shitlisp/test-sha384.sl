(assert (=
	(sha384 (bytes "abc"))
	[cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7])
)

(assert (=
	(sha384 (bytes "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	[3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b])
)

(assert (=
	(sha384 (bytes "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
	[09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039])
)

(assert (=
	(sha384 (* (bytes "a") 1000000))
	[9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985])
)

(assert (=
	(sha384 (bytes "The quick brown fox jumps over the lazy dog"))
	[ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1])
)

(assert (=
	(sha384 (bytes "The quick brown fox jumps over the lazy cog"))
	[098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b])
)

(assert (=
	(sha384 [])
	[38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b])
)

(assert (=
	(hmac-sha384 (* [0b] 20) (bytes "Hi There"))
	[afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6])
)

(assert (=
	(hmac-sha384 (bytes "Jefe") (bytes "what do ya want for nothing?"))
	[af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649])
)

(assert (=
	(hmac-sha384 (* [aa] 20) (* [dd] 50))
	[88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27])
)

(assert (=
	(hmac-sha384 [0102030405060708090a0b0c0d0e0f10111213141516171819] (* [cd] 50))
	[3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb])
)

(assert (=
	(hmac-sha384 (* [aa] 131) (bytes "Test Using Larger Than Block-Size Key - Hash Key First"))
	[4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952])
)

(assert (=
	(hmac-sha384 (* [aa] 131) (bytes "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
	[6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e])
)


(puts success)
