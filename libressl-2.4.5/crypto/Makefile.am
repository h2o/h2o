include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I$(top_srcdir)/crypto/asn1
AM_CPPFLAGS += -I$(top_srcdir)/crypto/evp
AM_CPPFLAGS += -I$(top_srcdir)/crypto/modes
AM_CPPFLAGS += -I$(top_srcdir)/crypto

lib_LTLIBRARIES = libcrypto.la

EXTRA_DIST = VERSION
EXTRA_DIST += CMakeLists.txt

# needed for a CMake target
EXTRA_DIST += compat/strcasecmp.c

libcrypto_la_LDFLAGS = -version-info @LIBCRYPTO_VERSION@ -no-undefined
libcrypto_la_LIBADD = libcompat.la
if !HAVE_EXPLICIT_BZERO
libcrypto_la_LIBADD += libcompatnoopt.la
endif
libcrypto_la_CPPFLAGS = $(AM_CPPFLAGS)
libcrypto_la_CPPFLAGS += -DLIBRESSL_INTERNAL
libcrypto_la_CPPFLAGS += -DOPENSSL_NO_HW_PADLOCK
if OPENSSL_NO_ASM
libcrypto_la_CPPFLAGS += -DOPENSSL_NO_ASM
else
if HOST_WIN
libcrypto_la_CPPFLAGS += -DOPENSSL_NO_ASM
endif
endif

if OPENSSLDIR_DEFINED
libcrypto_la_CPPFLAGS += -DOPENSSLDIR=\"@OPENSSLDIR@\"
else
libcrypto_la_CPPFLAGS += -DOPENSSLDIR=\"$(sysconfdir)/ssl\"
endif

noinst_LTLIBRARIES = libcompat.la

# compatibility functions that need to be built without optimizations
if !HAVE_EXPLICIT_BZERO
noinst_LTLIBRARIES += libcompatnoopt.la

libcompatnoopt_la_CFLAGS = -O0
libcompatnoopt_la_SOURCES =

if HOST_WIN
libcompatnoopt_la_SOURCES += compat/explicit_bzero_win.c
else
libcompatnoopt_la_SOURCES += compat/explicit_bzero.c
endif
endif

# other compatibility functions
libcompat_la_SOURCES =
libcompat_la_LIBADD = $(PLATFORM_LDADD)

if !HAVE_STRLCAT
libcompat_la_SOURCES += compat/strlcat.c
endif

if !HAVE_STRLCPY
libcompat_la_SOURCES += compat/strlcpy.c
endif

if !HAVE_STRNDUP
libcompat_la_SOURCES += compat/strndup.c
# the only user of strnlen is strndup, so only build it if needed
if !HAVE_STRNLEN
libcompat_la_SOURCES += compat/strnlen.c
endif
endif

if !HAVE_ASPRINTF
libcompat_la_SOURCES += compat/bsd-asprintf.c
endif

if !HAVE_INET_PTON
libcompat_la_SOURCES += compat/inet_pton.c
endif

if !HAVE_TIMEGM
libcompat_la_SOURCES += compat/timegm.c
endif

if !HAVE_REALLOCARRAY
libcompat_la_SOURCES += compat/reallocarray.c
endif

if !HAVE_TIMINGSAFE_MEMCMP
libcompat_la_SOURCES += compat/timingsafe_memcmp.c
endif

if !HAVE_TIMINGSAFE_BCMP
libcompat_la_SOURCES += compat/timingsafe_bcmp.c
endif

if HOST_WIN
libcompat_la_SOURCES += compat/posix_win.c
endif

include Makefile.am.arc4random

libcrypto_la_SOURCES =
EXTRA_libcrypto_la_SOURCES =

include Makefile.am.elf-x86_64
include Makefile.am.macosx-x86_64

if !HOST_ASM_ELF_X86_64
if !HOST_ASM_MACOSX_X86_64
libcrypto_la_SOURCES += aes/aes_cbc.c
libcrypto_la_SOURCES += aes/aes_core.c
libcrypto_la_SOURCES += camellia/camellia.c
libcrypto_la_SOURCES += camellia/cmll_cbc.c
libcrypto_la_SOURCES += rc4/rc4_enc.c
libcrypto_la_SOURCES += rc4/rc4_skey.c
libcrypto_la_SOURCES += whrlpool/wp_block.c
endif
endif

libcrypto_la_SOURCES += cpt_err.c
libcrypto_la_SOURCES += cryptlib.c
libcrypto_la_SOURCES += cversion.c
libcrypto_la_SOURCES += ex_data.c
libcrypto_la_SOURCES += malloc-wrapper.c
libcrypto_la_SOURCES += mem_clr.c
libcrypto_la_SOURCES += mem_dbg.c
libcrypto_la_SOURCES += o_init.c
libcrypto_la_SOURCES += o_str.c
libcrypto_la_SOURCES += o_time.c
noinst_HEADERS += constant_time_locl.h
noinst_HEADERS += cryptlib.h
noinst_HEADERS += md32_common.h
noinst_HEADERS += o_time.h

# aes
libcrypto_la_SOURCES += aes/aes_cfb.c
libcrypto_la_SOURCES += aes/aes_ctr.c
libcrypto_la_SOURCES += aes/aes_ecb.c
libcrypto_la_SOURCES += aes/aes_ige.c
libcrypto_la_SOURCES += aes/aes_misc.c
libcrypto_la_SOURCES += aes/aes_ofb.c
libcrypto_la_SOURCES += aes/aes_wrap.c
noinst_HEADERS += aes/aes_locl.h

# asn1
libcrypto_la_SOURCES += asn1/a_bitstr.c
libcrypto_la_SOURCES += asn1/a_bool.c
libcrypto_la_SOURCES += asn1/a_bytes.c
libcrypto_la_SOURCES += asn1/a_d2i_fp.c
libcrypto_la_SOURCES += asn1/a_digest.c
libcrypto_la_SOURCES += asn1/a_dup.c
libcrypto_la_SOURCES += asn1/a_enum.c
libcrypto_la_SOURCES += asn1/a_i2d_fp.c
libcrypto_la_SOURCES += asn1/a_int.c
libcrypto_la_SOURCES += asn1/a_mbstr.c
libcrypto_la_SOURCES += asn1/a_object.c
libcrypto_la_SOURCES += asn1/a_octet.c
libcrypto_la_SOURCES += asn1/a_print.c
libcrypto_la_SOURCES += asn1/a_set.c
libcrypto_la_SOURCES += asn1/a_sign.c
libcrypto_la_SOURCES += asn1/a_strex.c
libcrypto_la_SOURCES += asn1/a_strnid.c
libcrypto_la_SOURCES += asn1/a_time.c
libcrypto_la_SOURCES += asn1/a_time_tm.c
libcrypto_la_SOURCES += asn1/a_type.c
libcrypto_la_SOURCES += asn1/a_utf8.c
libcrypto_la_SOURCES += asn1/a_verify.c
libcrypto_la_SOURCES += asn1/ameth_lib.c
libcrypto_la_SOURCES += asn1/asn1_err.c
libcrypto_la_SOURCES += asn1/asn1_gen.c
libcrypto_la_SOURCES += asn1/asn1_lib.c
libcrypto_la_SOURCES += asn1/asn1_par.c
libcrypto_la_SOURCES += asn1/asn_mime.c
libcrypto_la_SOURCES += asn1/asn_moid.c
libcrypto_la_SOURCES += asn1/asn_pack.c
libcrypto_la_SOURCES += asn1/bio_asn1.c
libcrypto_la_SOURCES += asn1/bio_ndef.c
libcrypto_la_SOURCES += asn1/d2i_pr.c
libcrypto_la_SOURCES += asn1/d2i_pu.c
libcrypto_la_SOURCES += asn1/evp_asn1.c
libcrypto_la_SOURCES += asn1/f_enum.c
libcrypto_la_SOURCES += asn1/f_int.c
libcrypto_la_SOURCES += asn1/f_string.c
libcrypto_la_SOURCES += asn1/i2d_pr.c
libcrypto_la_SOURCES += asn1/i2d_pu.c
libcrypto_la_SOURCES += asn1/n_pkey.c
libcrypto_la_SOURCES += asn1/nsseq.c
libcrypto_la_SOURCES += asn1/p5_pbe.c
libcrypto_la_SOURCES += asn1/p5_pbev2.c
libcrypto_la_SOURCES += asn1/p8_pkey.c
libcrypto_la_SOURCES += asn1/t_bitst.c
libcrypto_la_SOURCES += asn1/t_crl.c
libcrypto_la_SOURCES += asn1/t_pkey.c
libcrypto_la_SOURCES += asn1/t_req.c
libcrypto_la_SOURCES += asn1/t_spki.c
libcrypto_la_SOURCES += asn1/t_x509.c
libcrypto_la_SOURCES += asn1/t_x509a.c
libcrypto_la_SOURCES += asn1/tasn_dec.c
libcrypto_la_SOURCES += asn1/tasn_enc.c
libcrypto_la_SOURCES += asn1/tasn_fre.c
libcrypto_la_SOURCES += asn1/tasn_new.c
libcrypto_la_SOURCES += asn1/tasn_prn.c
libcrypto_la_SOURCES += asn1/tasn_typ.c
libcrypto_la_SOURCES += asn1/tasn_utl.c
libcrypto_la_SOURCES += asn1/x_algor.c
libcrypto_la_SOURCES += asn1/x_attrib.c
libcrypto_la_SOURCES += asn1/x_bignum.c
libcrypto_la_SOURCES += asn1/x_crl.c
libcrypto_la_SOURCES += asn1/x_exten.c
libcrypto_la_SOURCES += asn1/x_info.c
libcrypto_la_SOURCES += asn1/x_long.c
libcrypto_la_SOURCES += asn1/x_name.c
libcrypto_la_SOURCES += asn1/x_nx509.c
libcrypto_la_SOURCES += asn1/x_pkey.c
libcrypto_la_SOURCES += asn1/x_pubkey.c
libcrypto_la_SOURCES += asn1/x_req.c
libcrypto_la_SOURCES += asn1/x_sig.c
libcrypto_la_SOURCES += asn1/x_spki.c
libcrypto_la_SOURCES += asn1/x_val.c
libcrypto_la_SOURCES += asn1/x_x509.c
libcrypto_la_SOURCES += asn1/x_x509a.c
noinst_HEADERS += asn1/asn1_locl.h
noinst_HEADERS += asn1/charmap.h

# bf
libcrypto_la_SOURCES += bf/bf_cfb64.c
libcrypto_la_SOURCES += bf/bf_ecb.c
libcrypto_la_SOURCES += bf/bf_enc.c
libcrypto_la_SOURCES += bf/bf_ofb64.c
libcrypto_la_SOURCES += bf/bf_skey.c
noinst_HEADERS += bf/bf_locl.h
noinst_HEADERS += bf/bf_pi.h

# bio
libcrypto_la_SOURCES += bio/b_dump.c
if !HOST_WIN
libcrypto_la_SOURCES += bio/b_posix.c
endif
libcrypto_la_SOURCES += bio/b_print.c
libcrypto_la_SOURCES += bio/b_sock.c
if HOST_WIN
libcrypto_la_SOURCES += bio/b_win.c
endif
libcrypto_la_SOURCES += bio/bf_buff.c
libcrypto_la_SOURCES += bio/bf_nbio.c
libcrypto_la_SOURCES += bio/bf_null.c
libcrypto_la_SOURCES += bio/bio_cb.c
libcrypto_la_SOURCES += bio/bio_err.c
libcrypto_la_SOURCES += bio/bio_lib.c
libcrypto_la_SOURCES += bio/bss_acpt.c
libcrypto_la_SOURCES += bio/bss_bio.c
libcrypto_la_SOURCES += bio/bss_conn.c
libcrypto_la_SOURCES += bio/bss_dgram.c
libcrypto_la_SOURCES += bio/bss_fd.c
libcrypto_la_SOURCES += bio/bss_file.c
if !HOST_WIN
libcrypto_la_SOURCES += bio/bss_log.c
endif
libcrypto_la_SOURCES += bio/bss_mem.c
libcrypto_la_SOURCES += bio/bss_null.c
libcrypto_la_SOURCES += bio/bss_sock.c

# bn
libcrypto_la_SOURCES += bn/bn_add.c
libcrypto_la_SOURCES += bn/bn_asm.c
libcrypto_la_SOURCES += bn/bn_blind.c
libcrypto_la_SOURCES += bn/bn_const.c
libcrypto_la_SOURCES += bn/bn_ctx.c
libcrypto_la_SOURCES += bn/bn_depr.c
libcrypto_la_SOURCES += bn/bn_div.c
libcrypto_la_SOURCES += bn/bn_err.c
libcrypto_la_SOURCES += bn/bn_exp.c
libcrypto_la_SOURCES += bn/bn_exp2.c
libcrypto_la_SOURCES += bn/bn_gcd.c
libcrypto_la_SOURCES += bn/bn_gf2m.c
libcrypto_la_SOURCES += bn/bn_kron.c
libcrypto_la_SOURCES += bn/bn_lib.c
libcrypto_la_SOURCES += bn/bn_mod.c
libcrypto_la_SOURCES += bn/bn_mont.c
libcrypto_la_SOURCES += bn/bn_mpi.c
libcrypto_la_SOURCES += bn/bn_mul.c
libcrypto_la_SOURCES += bn/bn_nist.c
libcrypto_la_SOURCES += bn/bn_prime.c
libcrypto_la_SOURCES += bn/bn_print.c
libcrypto_la_SOURCES += bn/bn_rand.c
libcrypto_la_SOURCES += bn/bn_recp.c
libcrypto_la_SOURCES += bn/bn_shift.c
libcrypto_la_SOURCES += bn/bn_sqr.c
libcrypto_la_SOURCES += bn/bn_sqrt.c
libcrypto_la_SOURCES += bn/bn_word.c
libcrypto_la_SOURCES += bn/bn_x931p.c
noinst_HEADERS += bn/bn_lcl.h
noinst_HEADERS += bn/bn_prime.h

# buffer
libcrypto_la_SOURCES += buffer/buf_err.c
libcrypto_la_SOURCES += buffer/buf_str.c
libcrypto_la_SOURCES += buffer/buffer.c

# camellia
libcrypto_la_SOURCES += camellia/cmll_cfb.c
libcrypto_la_SOURCES += camellia/cmll_ctr.c
libcrypto_la_SOURCES += camellia/cmll_ecb.c
libcrypto_la_SOURCES += camellia/cmll_misc.c
libcrypto_la_SOURCES += camellia/cmll_ofb.c
noinst_HEADERS += camellia/camellia.h
noinst_HEADERS += camellia/cmll_locl.h

# cast
libcrypto_la_SOURCES += cast/c_cfb64.c
libcrypto_la_SOURCES += cast/c_ecb.c
libcrypto_la_SOURCES += cast/c_enc.c
libcrypto_la_SOURCES += cast/c_ofb64.c
libcrypto_la_SOURCES += cast/c_skey.c
noinst_HEADERS += cast/cast_lcl.h
noinst_HEADERS += cast/cast_s.h

# chacha
EXTRA_libcrypto_la_SOURCES += chacha/chacha-merged.c
libcrypto_la_SOURCES += chacha/chacha.c

# cmac
libcrypto_la_SOURCES += cmac/cm_ameth.c
libcrypto_la_SOURCES += cmac/cm_pmeth.c
libcrypto_la_SOURCES += cmac/cmac.c

# comp
libcrypto_la_SOURCES += comp/c_rle.c
libcrypto_la_SOURCES += comp/c_zlib.c
libcrypto_la_SOURCES += comp/comp_err.c
libcrypto_la_SOURCES += comp/comp_lib.c

# conf
libcrypto_la_SOURCES += conf/conf_api.c
libcrypto_la_SOURCES += conf/conf_def.c
libcrypto_la_SOURCES += conf/conf_err.c
libcrypto_la_SOURCES += conf/conf_lib.c
libcrypto_la_SOURCES += conf/conf_mall.c
libcrypto_la_SOURCES += conf/conf_mod.c
libcrypto_la_SOURCES += conf/conf_sap.c
noinst_HEADERS += conf/conf_def.h

# des
libcrypto_la_SOURCES += des/cbc_cksm.c
libcrypto_la_SOURCES += des/cbc_enc.c
libcrypto_la_SOURCES += des/cfb64ede.c
libcrypto_la_SOURCES += des/cfb64enc.c
libcrypto_la_SOURCES += des/cfb_enc.c
libcrypto_la_SOURCES += des/des_enc.c
libcrypto_la_SOURCES += des/ecb3_enc.c
libcrypto_la_SOURCES += des/ecb_enc.c
libcrypto_la_SOURCES += des/ede_cbcm_enc.c
libcrypto_la_SOURCES += des/enc_read.c
libcrypto_la_SOURCES += des/enc_writ.c
libcrypto_la_SOURCES += des/fcrypt.c
libcrypto_la_SOURCES += des/fcrypt_b.c
EXTRA_libcrypto_la_SOURCES += des/ncbc_enc.c
libcrypto_la_SOURCES += des/ofb64ede.c
libcrypto_la_SOURCES += des/ofb64enc.c
libcrypto_la_SOURCES += des/ofb_enc.c
libcrypto_la_SOURCES += des/pcbc_enc.c
libcrypto_la_SOURCES += des/qud_cksm.c
libcrypto_la_SOURCES += des/rand_key.c
libcrypto_la_SOURCES += des/set_key.c
libcrypto_la_SOURCES += des/str2key.c
libcrypto_la_SOURCES += des/xcbc_enc.c
noinst_HEADERS += des/des_locl.h
noinst_HEADERS += des/spr.h

# dh
libcrypto_la_SOURCES += dh/dh_ameth.c
libcrypto_la_SOURCES += dh/dh_asn1.c
libcrypto_la_SOURCES += dh/dh_check.c
libcrypto_la_SOURCES += dh/dh_depr.c
libcrypto_la_SOURCES += dh/dh_err.c
libcrypto_la_SOURCES += dh/dh_gen.c
libcrypto_la_SOURCES += dh/dh_key.c
libcrypto_la_SOURCES += dh/dh_lib.c
libcrypto_la_SOURCES += dh/dh_pmeth.c
libcrypto_la_SOURCES += dh/dh_prn.c

# dsa
libcrypto_la_SOURCES += dsa/dsa_ameth.c
libcrypto_la_SOURCES += dsa/dsa_asn1.c
libcrypto_la_SOURCES += dsa/dsa_depr.c
libcrypto_la_SOURCES += dsa/dsa_err.c
libcrypto_la_SOURCES += dsa/dsa_gen.c
libcrypto_la_SOURCES += dsa/dsa_key.c
libcrypto_la_SOURCES += dsa/dsa_lib.c
libcrypto_la_SOURCES += dsa/dsa_ossl.c
libcrypto_la_SOURCES += dsa/dsa_pmeth.c
libcrypto_la_SOURCES += dsa/dsa_prn.c
libcrypto_la_SOURCES += dsa/dsa_sign.c
libcrypto_la_SOURCES += dsa/dsa_vrf.c
noinst_HEADERS += dsa/dsa_locl.h

# dso
libcrypto_la_SOURCES += dso/dso_dlfcn.c
libcrypto_la_SOURCES += dso/dso_err.c
libcrypto_la_SOURCES += dso/dso_lib.c
libcrypto_la_SOURCES += dso/dso_null.c
libcrypto_la_SOURCES += dso/dso_openssl.c

# ec
libcrypto_la_SOURCES += ec/ec2_mult.c
libcrypto_la_SOURCES += ec/ec2_oct.c
libcrypto_la_SOURCES += ec/ec2_smpl.c
libcrypto_la_SOURCES += ec/ec_ameth.c
libcrypto_la_SOURCES += ec/ec_asn1.c
libcrypto_la_SOURCES += ec/ec_check.c
libcrypto_la_SOURCES += ec/ec_curve.c
libcrypto_la_SOURCES += ec/ec_cvt.c
libcrypto_la_SOURCES += ec/ec_err.c
libcrypto_la_SOURCES += ec/ec_key.c
libcrypto_la_SOURCES += ec/ec_lib.c
libcrypto_la_SOURCES += ec/ec_mult.c
libcrypto_la_SOURCES += ec/ec_oct.c
libcrypto_la_SOURCES += ec/ec_pmeth.c
libcrypto_la_SOURCES += ec/ec_print.c
libcrypto_la_SOURCES += ec/eck_prn.c
libcrypto_la_SOURCES += ec/ecp_mont.c
libcrypto_la_SOURCES += ec/ecp_nist.c
libcrypto_la_SOURCES += ec/ecp_oct.c
libcrypto_la_SOURCES += ec/ecp_smpl.c
noinst_HEADERS += ec/ec_lcl.h

# ecdh
libcrypto_la_SOURCES += ecdh/ech_err.c
libcrypto_la_SOURCES += ecdh/ech_key.c
libcrypto_la_SOURCES += ecdh/ech_lib.c
noinst_HEADERS += ecdh/ech_locl.h

# ecdsa
libcrypto_la_SOURCES += ecdsa/ecs_asn1.c
libcrypto_la_SOURCES += ecdsa/ecs_err.c
libcrypto_la_SOURCES += ecdsa/ecs_lib.c
libcrypto_la_SOURCES += ecdsa/ecs_ossl.c
libcrypto_la_SOURCES += ecdsa/ecs_sign.c
libcrypto_la_SOURCES += ecdsa/ecs_vrf.c
noinst_HEADERS += ecdsa/ecs_locl.h

# engine
libcrypto_la_SOURCES += engine/eng_all.c
libcrypto_la_SOURCES += engine/eng_cnf.c
libcrypto_la_SOURCES += engine/eng_ctrl.c
libcrypto_la_SOURCES += engine/eng_dyn.c
libcrypto_la_SOURCES += engine/eng_err.c
libcrypto_la_SOURCES += engine/eng_fat.c
libcrypto_la_SOURCES += engine/eng_init.c
libcrypto_la_SOURCES += engine/eng_lib.c
libcrypto_la_SOURCES += engine/eng_list.c
libcrypto_la_SOURCES += engine/eng_openssl.c
libcrypto_la_SOURCES += engine/eng_pkey.c
libcrypto_la_SOURCES += engine/eng_table.c
libcrypto_la_SOURCES += engine/tb_asnmth.c
libcrypto_la_SOURCES += engine/tb_cipher.c
libcrypto_la_SOURCES += engine/tb_dh.c
libcrypto_la_SOURCES += engine/tb_digest.c
libcrypto_la_SOURCES += engine/tb_dsa.c
libcrypto_la_SOURCES += engine/tb_ecdh.c
libcrypto_la_SOURCES += engine/tb_ecdsa.c
libcrypto_la_SOURCES += engine/tb_pkmeth.c
libcrypto_la_SOURCES += engine/tb_rand.c
libcrypto_la_SOURCES += engine/tb_rsa.c
libcrypto_la_SOURCES += engine/tb_store.c
noinst_HEADERS += engine/eng_int.h

# err
libcrypto_la_SOURCES += err/err.c
libcrypto_la_SOURCES += err/err_all.c
libcrypto_la_SOURCES += err/err_prn.c

# evp
libcrypto_la_SOURCES += evp/bio_b64.c
libcrypto_la_SOURCES += evp/bio_enc.c
libcrypto_la_SOURCES += evp/bio_md.c
libcrypto_la_SOURCES += evp/c_all.c
libcrypto_la_SOURCES += evp/digest.c
libcrypto_la_SOURCES += evp/e_aes.c
libcrypto_la_SOURCES += evp/e_aes_cbc_hmac_sha1.c
libcrypto_la_SOURCES += evp/e_bf.c
libcrypto_la_SOURCES += evp/e_camellia.c
libcrypto_la_SOURCES += evp/e_cast.c
libcrypto_la_SOURCES += evp/e_chacha.c
libcrypto_la_SOURCES += evp/e_chacha20poly1305.c
libcrypto_la_SOURCES += evp/e_des.c
libcrypto_la_SOURCES += evp/e_des3.c
libcrypto_la_SOURCES += evp/e_gost2814789.c
libcrypto_la_SOURCES += evp/e_idea.c
libcrypto_la_SOURCES += evp/e_null.c
libcrypto_la_SOURCES += evp/e_old.c
libcrypto_la_SOURCES += evp/e_rc2.c
libcrypto_la_SOURCES += evp/e_rc4.c
libcrypto_la_SOURCES += evp/e_rc4_hmac_md5.c
libcrypto_la_SOURCES += evp/e_xcbc_d.c
libcrypto_la_SOURCES += evp/encode.c
libcrypto_la_SOURCES += evp/evp_aead.c
libcrypto_la_SOURCES += evp/evp_enc.c
libcrypto_la_SOURCES += evp/evp_err.c
libcrypto_la_SOURCES += evp/evp_key.c
libcrypto_la_SOURCES += evp/evp_lib.c
libcrypto_la_SOURCES += evp/evp_pbe.c
libcrypto_la_SOURCES += evp/evp_pkey.c
libcrypto_la_SOURCES += evp/m_dss.c
libcrypto_la_SOURCES += evp/m_dss1.c
libcrypto_la_SOURCES += evp/m_ecdsa.c
libcrypto_la_SOURCES += evp/m_gost2814789.c
libcrypto_la_SOURCES += evp/m_gostr341194.c
libcrypto_la_SOURCES += evp/m_md4.c
libcrypto_la_SOURCES += evp/m_md5.c
libcrypto_la_SOURCES += evp/m_null.c
libcrypto_la_SOURCES += evp/m_ripemd.c
libcrypto_la_SOURCES += evp/m_sha1.c
libcrypto_la_SOURCES += evp/m_sigver.c
libcrypto_la_SOURCES += evp/m_streebog.c
libcrypto_la_SOURCES += evp/m_wp.c
libcrypto_la_SOURCES += evp/names.c
libcrypto_la_SOURCES += evp/p5_crpt.c
libcrypto_la_SOURCES += evp/p5_crpt2.c
libcrypto_la_SOURCES += evp/p_dec.c
libcrypto_la_SOURCES += evp/p_enc.c
libcrypto_la_SOURCES += evp/p_lib.c
libcrypto_la_SOURCES += evp/p_open.c
libcrypto_la_SOURCES += evp/p_seal.c
libcrypto_la_SOURCES += evp/p_sign.c
libcrypto_la_SOURCES += evp/p_verify.c
libcrypto_la_SOURCES += evp/pmeth_fn.c
libcrypto_la_SOURCES += evp/pmeth_gn.c
libcrypto_la_SOURCES += evp/pmeth_lib.c
noinst_HEADERS += evp/evp_locl.h

# gost
libcrypto_la_SOURCES += gost/gost2814789.c
libcrypto_la_SOURCES += gost/gost89_keywrap.c
libcrypto_la_SOURCES += gost/gost89_params.c
libcrypto_la_SOURCES += gost/gost89imit_ameth.c
libcrypto_la_SOURCES += gost/gost89imit_pmeth.c
libcrypto_la_SOURCES += gost/gost_asn1.c
libcrypto_la_SOURCES += gost/gost_err.c
libcrypto_la_SOURCES += gost/gostr341001.c
libcrypto_la_SOURCES += gost/gostr341001_ameth.c
libcrypto_la_SOURCES += gost/gostr341001_key.c
libcrypto_la_SOURCES += gost/gostr341001_params.c
libcrypto_la_SOURCES += gost/gostr341001_pmeth.c
libcrypto_la_SOURCES += gost/gostr341194.c
libcrypto_la_SOURCES += gost/streebog.c
noinst_HEADERS += gost/gost.h
noinst_HEADERS += gost/gost_asn1.h
noinst_HEADERS += gost/gost_locl.h

# hmac
libcrypto_la_SOURCES += hmac/hm_ameth.c
libcrypto_la_SOURCES += hmac/hm_pmeth.c
libcrypto_la_SOURCES += hmac/hmac.c

# idea
libcrypto_la_SOURCES += idea/i_cbc.c
libcrypto_la_SOURCES += idea/i_cfb64.c
libcrypto_la_SOURCES += idea/i_ecb.c
libcrypto_la_SOURCES += idea/i_ofb64.c
libcrypto_la_SOURCES += idea/i_skey.c
noinst_HEADERS += idea/idea_lcl.h

# krb5
libcrypto_la_SOURCES += krb5/krb5_asn.c

# lhash
libcrypto_la_SOURCES += lhash/lh_stats.c
libcrypto_la_SOURCES += lhash/lhash.c

# md4
libcrypto_la_SOURCES += md4/md4_dgst.c
libcrypto_la_SOURCES += md4/md4_one.c
noinst_HEADERS += md4/md4_locl.h

# md5
libcrypto_la_SOURCES += md5/md5_dgst.c
libcrypto_la_SOURCES += md5/md5_one.c
noinst_HEADERS += md5/md5_locl.h

# modes
libcrypto_la_SOURCES += modes/cbc128.c
libcrypto_la_SOURCES += modes/ccm128.c
libcrypto_la_SOURCES += modes/cfb128.c
libcrypto_la_SOURCES += modes/ctr128.c
libcrypto_la_SOURCES += modes/cts128.c
libcrypto_la_SOURCES += modes/gcm128.c
libcrypto_la_SOURCES += modes/ofb128.c
libcrypto_la_SOURCES += modes/xts128.c
noinst_HEADERS += modes/modes_lcl.h

# objects
libcrypto_la_SOURCES += objects/o_names.c
libcrypto_la_SOURCES += objects/obj_dat.c
libcrypto_la_SOURCES += objects/obj_err.c
libcrypto_la_SOURCES += objects/obj_lib.c
libcrypto_la_SOURCES += objects/obj_xref.c
noinst_HEADERS += objects/obj_dat.h
noinst_HEADERS += objects/obj_xref.h

# ocsp
libcrypto_la_SOURCES += ocsp/ocsp_asn.c
libcrypto_la_SOURCES += ocsp/ocsp_cl.c
libcrypto_la_SOURCES += ocsp/ocsp_err.c
libcrypto_la_SOURCES += ocsp/ocsp_ext.c
libcrypto_la_SOURCES += ocsp/ocsp_ht.c
libcrypto_la_SOURCES += ocsp/ocsp_lib.c
libcrypto_la_SOURCES += ocsp/ocsp_prn.c
libcrypto_la_SOURCES += ocsp/ocsp_srv.c
libcrypto_la_SOURCES += ocsp/ocsp_vfy.c

# pem
libcrypto_la_SOURCES += pem/pem_all.c
libcrypto_la_SOURCES += pem/pem_err.c
libcrypto_la_SOURCES += pem/pem_info.c
libcrypto_la_SOURCES += pem/pem_lib.c
libcrypto_la_SOURCES += pem/pem_oth.c
libcrypto_la_SOURCES += pem/pem_pk8.c
libcrypto_la_SOURCES += pem/pem_pkey.c
libcrypto_la_SOURCES += pem/pem_seal.c
libcrypto_la_SOURCES += pem/pem_sign.c
libcrypto_la_SOURCES += pem/pem_x509.c
libcrypto_la_SOURCES += pem/pem_xaux.c
libcrypto_la_SOURCES += pem/pvkfmt.c

# pkcs12
libcrypto_la_SOURCES += pkcs12/p12_add.c
libcrypto_la_SOURCES += pkcs12/p12_asn.c
libcrypto_la_SOURCES += pkcs12/p12_attr.c
libcrypto_la_SOURCES += pkcs12/p12_crpt.c
libcrypto_la_SOURCES += pkcs12/p12_crt.c
libcrypto_la_SOURCES += pkcs12/p12_decr.c
libcrypto_la_SOURCES += pkcs12/p12_init.c
libcrypto_la_SOURCES += pkcs12/p12_key.c
libcrypto_la_SOURCES += pkcs12/p12_kiss.c
libcrypto_la_SOURCES += pkcs12/p12_mutl.c
libcrypto_la_SOURCES += pkcs12/p12_npas.c
libcrypto_la_SOURCES += pkcs12/p12_p8d.c
libcrypto_la_SOURCES += pkcs12/p12_p8e.c
libcrypto_la_SOURCES += pkcs12/p12_utl.c
libcrypto_la_SOURCES += pkcs12/pk12err.c

# pkcs7
libcrypto_la_SOURCES += pkcs7/bio_pk7.c
libcrypto_la_SOURCES += pkcs7/pk7_asn1.c
libcrypto_la_SOURCES += pkcs7/pk7_attr.c
libcrypto_la_SOURCES += pkcs7/pk7_doit.c
libcrypto_la_SOURCES += pkcs7/pk7_lib.c
libcrypto_la_SOURCES += pkcs7/pk7_mime.c
libcrypto_la_SOURCES += pkcs7/pk7_smime.c
libcrypto_la_SOURCES += pkcs7/pkcs7err.c

# poly1305
EXTRA_libcrypto_la_SOURCES += poly1305/poly1305-donna.c
libcrypto_la_SOURCES += poly1305/poly1305.c

# rand
libcrypto_la_SOURCES += rand/rand_err.c
libcrypto_la_SOURCES += rand/rand_lib.c
libcrypto_la_SOURCES += rand/randfile.c

# rc2
libcrypto_la_SOURCES += rc2/rc2_cbc.c
libcrypto_la_SOURCES += rc2/rc2_ecb.c
libcrypto_la_SOURCES += rc2/rc2_skey.c
libcrypto_la_SOURCES += rc2/rc2cfb64.c
libcrypto_la_SOURCES += rc2/rc2ofb64.c
noinst_HEADERS += rc2/rc2_locl.h

# rc4
noinst_HEADERS += rc4/rc4_locl.h

# ripemd
libcrypto_la_SOURCES += ripemd/rmd_dgst.c
libcrypto_la_SOURCES += ripemd/rmd_one.c
noinst_HEADERS += ripemd/rmd_locl.h
noinst_HEADERS += ripemd/rmdconst.h

# rsa
libcrypto_la_SOURCES += rsa/rsa_ameth.c
libcrypto_la_SOURCES += rsa/rsa_asn1.c
libcrypto_la_SOURCES += rsa/rsa_chk.c
libcrypto_la_SOURCES += rsa/rsa_crpt.c
libcrypto_la_SOURCES += rsa/rsa_depr.c
libcrypto_la_SOURCES += rsa/rsa_eay.c
libcrypto_la_SOURCES += rsa/rsa_err.c
libcrypto_la_SOURCES += rsa/rsa_gen.c
libcrypto_la_SOURCES += rsa/rsa_lib.c
libcrypto_la_SOURCES += rsa/rsa_none.c
libcrypto_la_SOURCES += rsa/rsa_oaep.c
libcrypto_la_SOURCES += rsa/rsa_pk1.c
libcrypto_la_SOURCES += rsa/rsa_pmeth.c
libcrypto_la_SOURCES += rsa/rsa_prn.c
libcrypto_la_SOURCES += rsa/rsa_pss.c
libcrypto_la_SOURCES += rsa/rsa_saos.c
libcrypto_la_SOURCES += rsa/rsa_sign.c
libcrypto_la_SOURCES += rsa/rsa_ssl.c
libcrypto_la_SOURCES += rsa/rsa_x931.c
noinst_HEADERS += rsa/rsa_locl.h

# sha
libcrypto_la_SOURCES += sha/sha1_one.c
libcrypto_la_SOURCES += sha/sha1dgst.c
libcrypto_la_SOURCES += sha/sha256.c
libcrypto_la_SOURCES += sha/sha512.c
noinst_HEADERS += sha/sha_locl.h

# stack
libcrypto_la_SOURCES += stack/stack.c

# ts
libcrypto_la_SOURCES += ts/ts_asn1.c
libcrypto_la_SOURCES += ts/ts_conf.c
libcrypto_la_SOURCES += ts/ts_err.c
libcrypto_la_SOURCES += ts/ts_lib.c
libcrypto_la_SOURCES += ts/ts_req_print.c
libcrypto_la_SOURCES += ts/ts_req_utils.c
libcrypto_la_SOURCES += ts/ts_rsp_print.c
libcrypto_la_SOURCES += ts/ts_rsp_sign.c
libcrypto_la_SOURCES += ts/ts_rsp_utils.c
libcrypto_la_SOURCES += ts/ts_rsp_verify.c
libcrypto_la_SOURCES += ts/ts_verify_ctx.c

# txt_db
libcrypto_la_SOURCES += txt_db/txt_db.c

# ui
libcrypto_la_SOURCES += ui/ui_err.c
libcrypto_la_SOURCES += ui/ui_lib.c
if !HOST_WIN
libcrypto_la_SOURCES += ui/ui_openssl.c
endif
if HOST_WIN
libcrypto_la_SOURCES += ui/ui_openssl_win.c
endif
libcrypto_la_SOURCES += ui/ui_util.c
noinst_HEADERS += ui/ui_locl.h

# whrlpool
libcrypto_la_SOURCES += whrlpool/wp_dgst.c
noinst_HEADERS += whrlpool/wp_locl.h

# x509
libcrypto_la_SOURCES += x509/by_dir.c
libcrypto_la_SOURCES += x509/by_file.c
libcrypto_la_SOURCES += x509/by_mem.c
libcrypto_la_SOURCES += x509/x509_att.c
libcrypto_la_SOURCES += x509/x509_cmp.c
libcrypto_la_SOURCES += x509/x509_d2.c
libcrypto_la_SOURCES += x509/x509_def.c
libcrypto_la_SOURCES += x509/x509_err.c
libcrypto_la_SOURCES += x509/x509_ext.c
libcrypto_la_SOURCES += x509/x509_lu.c
libcrypto_la_SOURCES += x509/x509_obj.c
libcrypto_la_SOURCES += x509/x509_r2x.c
libcrypto_la_SOURCES += x509/x509_req.c
libcrypto_la_SOURCES += x509/x509_set.c
libcrypto_la_SOURCES += x509/x509_trs.c
libcrypto_la_SOURCES += x509/x509_txt.c
libcrypto_la_SOURCES += x509/x509_v3.c
libcrypto_la_SOURCES += x509/x509_vfy.c
libcrypto_la_SOURCES += x509/x509_vpm.c
libcrypto_la_SOURCES += x509/x509cset.c
libcrypto_la_SOURCES += x509/x509name.c
libcrypto_la_SOURCES += x509/x509rset.c
libcrypto_la_SOURCES += x509/x509spki.c
libcrypto_la_SOURCES += x509/x509type.c
libcrypto_la_SOURCES += x509/x_all.c
noinst_HEADERS += x509/x509_lcl.h

# x509v3
libcrypto_la_SOURCES += x509v3/pcy_cache.c
libcrypto_la_SOURCES += x509v3/pcy_data.c
libcrypto_la_SOURCES += x509v3/pcy_lib.c
libcrypto_la_SOURCES += x509v3/pcy_map.c
libcrypto_la_SOURCES += x509v3/pcy_node.c
libcrypto_la_SOURCES += x509v3/pcy_tree.c
libcrypto_la_SOURCES += x509v3/v3_akey.c
libcrypto_la_SOURCES += x509v3/v3_akeya.c
libcrypto_la_SOURCES += x509v3/v3_alt.c
libcrypto_la_SOURCES += x509v3/v3_bcons.c
libcrypto_la_SOURCES += x509v3/v3_bitst.c
libcrypto_la_SOURCES += x509v3/v3_conf.c
libcrypto_la_SOURCES += x509v3/v3_cpols.c
libcrypto_la_SOURCES += x509v3/v3_crld.c
libcrypto_la_SOURCES += x509v3/v3_enum.c
libcrypto_la_SOURCES += x509v3/v3_extku.c
libcrypto_la_SOURCES += x509v3/v3_genn.c
libcrypto_la_SOURCES += x509v3/v3_ia5.c
libcrypto_la_SOURCES += x509v3/v3_info.c
libcrypto_la_SOURCES += x509v3/v3_int.c
libcrypto_la_SOURCES += x509v3/v3_lib.c
libcrypto_la_SOURCES += x509v3/v3_ncons.c
libcrypto_la_SOURCES += x509v3/v3_ocsp.c
libcrypto_la_SOURCES += x509v3/v3_pci.c
libcrypto_la_SOURCES += x509v3/v3_pcia.c
libcrypto_la_SOURCES += x509v3/v3_pcons.c
libcrypto_la_SOURCES += x509v3/v3_pku.c
libcrypto_la_SOURCES += x509v3/v3_pmaps.c
libcrypto_la_SOURCES += x509v3/v3_prn.c
libcrypto_la_SOURCES += x509v3/v3_purp.c
libcrypto_la_SOURCES += x509v3/v3_skey.c
libcrypto_la_SOURCES += x509v3/v3_sxnet.c
libcrypto_la_SOURCES += x509v3/v3_utl.c
libcrypto_la_SOURCES += x509v3/v3err.c
noinst_HEADERS += x509v3/ext_dat.h
noinst_HEADERS += x509v3/pcy_int.h
