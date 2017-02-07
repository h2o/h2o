(assert (=
	(sha512 (bytes "abc"))
	[ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f])
)

(assert (=
	(sha512 (bytes "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	[204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445])
)

(assert (=
	(sha512 (bytes "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
	[8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909])
)

(assert (=
	(sha512 (* (bytes "a") 1000000))
	[e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b])
)

(assert (=
	(sha512 (bytes "The quick brown fox jumps over the lazy dog"))
	[07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6])
)

(assert (=
	(sha512 (bytes "The quick brown fox jumps over the lazy cog"))
	[3eeee1d0 e11733ef 152a6c29 503b3ae2 0c4f1f3c da4cb26f 1bc1a41f 91c7fe4a b3bd8649 4049e201 c4bd5155 f31ecb7a 3c860684 3c4cc8df cab7da11 c8ae5045])
)

(assert (=
	(sha512 [])
	[cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e])
)

(assert (=
	(hmac-sha512 (* [0b] 20) (bytes "Hi There"))
	[87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854])
)

(assert (=
	(hmac-sha512 (bytes "Jefe") (bytes "what do ya want for nothing?"))
	[164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737])
)

(assert (=
	(hmac-sha512 (* [aa] 20) (* [dd] 50))
	[fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb])
)

(assert (=
	(hmac-sha512 [0102030405060708090a0b0c0d0e0f10111213141516171819] (* [cd] 50))
	[b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd])
)

(assert (=
	(hmac-sha512 (* [aa] 131) (bytes "Test Using Larger Than Block-Size Key - Hash Key First"))
	[80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598])
)

(assert (=
	(hmac-sha512 (* [aa] 131) (bytes "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
	[e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58])
)


(puts success)
