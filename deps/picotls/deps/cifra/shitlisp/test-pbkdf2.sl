(assert (=
	(pbkdf2-sha256 (bytes "password") (bytes "salt") 1 32)
	[120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b])
)

(assert (=
	(pbkdf2-sha256 (bytes "password") (bytes "salt") 2 32)
	[ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43])
)

(assert (=
	(pbkdf2-sha256 (bytes "password") (bytes "salt") 4096 32)
	[c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a])
)

(assert (=
	(pbkdf2-sha256 (bytes "passwordPASSWORDpassword") (bytes "saltSALTsaltSALTsaltSALTsaltSALTsalt") 4096 40)
	[348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9])
)

(assert (=
	(pbkdf2-sha256 [] (bytes "salt") 1024 32)
	[9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d])
)

(assert (=
	(pbkdf2-sha256 (bytes "password") [] 1024 32)
	[ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46])
)

(assert (=
	(pbkdf2-sha256 [7061737300776f7264] [7361006c74] 4096 16)
	[89b69d0516f829893c696226650a8687])
)

(puts success)
