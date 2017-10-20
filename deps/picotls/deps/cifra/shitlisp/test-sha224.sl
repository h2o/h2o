(assert (=
	(sha224 (bytes "abc"))
	[23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7])
)

(assert (=
	(sha224 [])
	[d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f])
)

(assert (=
	(hmac-sha224 (* [0b] 20) (bytes "Hi There"))
	[896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22])
)

(assert (=
	(hmac-sha224 (bytes "Jefe") (bytes "what do ya want for nothing?"))
	[a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44])
)

(assert (=
	(hmac-sha224 (* [aa] 20) (* [dd] 50))
	[7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea])
)

(assert (=
	(hmac-sha224 [0102030405060708090a0b0c0d0e0f10111213141516171819] (* [cd] 50))
	[6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a])
)

(assert (=
	(hmac-sha224 (* [aa] 131) (bytes "Test Using Larger Than Block-Size Key - Hash Key First"))
	[95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e])
)

(assert (=
	(hmac-sha224 (* [aa] 131) (bytes "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
	[3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1])
)

(puts success)
