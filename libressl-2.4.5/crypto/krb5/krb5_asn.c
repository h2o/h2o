/* $OpenBSD: krb5_asn.c,v 1.3 2015/02/09 16:04:46 jsing Exp $ */
/* Written by Vern Staats <staatsvr@asc.hpc.mil> for the OpenSSL project,
** using ocsp/{*.h,*asn*.c} as a starting point
*/
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/krb5_asn.h>


static const ASN1_TEMPLATE KRB5_ENCDATA_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_ENCDATA, etype),
		.field_name = "etype",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
		.tag = 1,
		.offset = offsetof(KRB5_ENCDATA, kvno),
		.field_name = "kvno",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 2,
		.offset = offsetof(KRB5_ENCDATA, cipher),
		.field_name = "cipher",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM KRB5_ENCDATA_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_ENCDATA_seq_tt,
	.tcount = sizeof(KRB5_ENCDATA_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_ENCDATA),
	.sname = "KRB5_ENCDATA",
};


KRB5_ENCDATA *
d2i_KRB5_ENCDATA(KRB5_ENCDATA **a, const unsigned char **in, long len)
{
	return (KRB5_ENCDATA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_ENCDATA_it);
}

int
i2d_KRB5_ENCDATA(KRB5_ENCDATA *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_ENCDATA_it);
}

KRB5_ENCDATA *
KRB5_ENCDATA_new(void)
{
	return (KRB5_ENCDATA *)ASN1_item_new(&KRB5_ENCDATA_it);
}

void
KRB5_ENCDATA_free(KRB5_ENCDATA *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_ENCDATA_it);
}


static const ASN1_TEMPLATE KRB5_PRINCNAME_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_PRINCNAME, nametype),
		.field_name = "nametype",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF,
		.tag = 1,
		.offset = offsetof(KRB5_PRINCNAME, namestring),
		.field_name = "namestring",
		.item = &ASN1_GENERALSTRING_it,
	},
};

const ASN1_ITEM KRB5_PRINCNAME_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_PRINCNAME_seq_tt,
	.tcount = sizeof(KRB5_PRINCNAME_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_PRINCNAME),
	.sname = "KRB5_PRINCNAME",
};


KRB5_PRINCNAME *
d2i_KRB5_PRINCNAME(KRB5_PRINCNAME **a, const unsigned char **in, long len)
{
	return (KRB5_PRINCNAME *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_PRINCNAME_it);
}

int
i2d_KRB5_PRINCNAME(KRB5_PRINCNAME *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_PRINCNAME_it);
}

KRB5_PRINCNAME *
KRB5_PRINCNAME_new(void)
{
	return (KRB5_PRINCNAME *)ASN1_item_new(&KRB5_PRINCNAME_it);
}

void
KRB5_PRINCNAME_free(KRB5_PRINCNAME *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_PRINCNAME_it);
}


/* [APPLICATION 1] = 0x61 */
static const ASN1_TEMPLATE KRB5_TKTBODY_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_TKTBODY, tktvno),
		.field_name = "tktvno",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(KRB5_TKTBODY, realm),
		.field_name = "realm",
		.item = &ASN1_GENERALSTRING_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 2,
		.offset = offsetof(KRB5_TKTBODY, sname),
		.field_name = "sname",
		.item = &KRB5_PRINCNAME_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 3,
		.offset = offsetof(KRB5_TKTBODY, encdata),
		.field_name = "encdata",
		.item = &KRB5_ENCDATA_it,
	},
};

const ASN1_ITEM KRB5_TKTBODY_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_TKTBODY_seq_tt,
	.tcount = sizeof(KRB5_TKTBODY_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_TKTBODY),
	.sname = "KRB5_TKTBODY",
};


KRB5_TKTBODY *
d2i_KRB5_TKTBODY(KRB5_TKTBODY **a, const unsigned char **in, long len)
{
	return (KRB5_TKTBODY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_TKTBODY_it);
}

int
i2d_KRB5_TKTBODY(KRB5_TKTBODY *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_TKTBODY_it);
}

KRB5_TKTBODY *
KRB5_TKTBODY_new(void)
{
	return (KRB5_TKTBODY *)ASN1_item_new(&KRB5_TKTBODY_it);
}

void
KRB5_TKTBODY_free(KRB5_TKTBODY *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_TKTBODY_it);
}


static const ASN1_TEMPLATE KRB5_TICKET_item_tt =  {
	.flags = ASN1_TFLG_EXPTAG | ASN1_TFLG_APPLICATION,
	.tag = 1,
	.offset = 0,
	.field_name = "KRB5_TICKET",
	.item = &KRB5_TKTBODY_it,
};

const ASN1_ITEM KRB5_TICKET_it = {
	.itype = ASN1_ITYPE_PRIMITIVE,
	.utype = -1,
	.templates = &KRB5_TICKET_item_tt,
	.tcount = 0,
	.funcs = NULL,
	.size = 0,
	.sname = "KRB5_TICKET",
};


KRB5_TICKET *
d2i_KRB5_TICKET(KRB5_TICKET **a, const unsigned char **in, long len)
{
	return (KRB5_TICKET *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_TICKET_it);
}

int
i2d_KRB5_TICKET(KRB5_TICKET *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_TICKET_it);
}

KRB5_TICKET *
KRB5_TICKET_new(void)
{
	return (KRB5_TICKET *)ASN1_item_new(&KRB5_TICKET_it);
}

void
KRB5_TICKET_free(KRB5_TICKET *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_TICKET_it);
}


/* [APPLICATION 14] = 0x6e */
static const ASN1_TEMPLATE KRB5_APREQBODY_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_APREQBODY, pvno),
		.field_name = "pvno",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(KRB5_APREQBODY, msgtype),
		.field_name = "msgtype",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 2,
		.offset = offsetof(KRB5_APREQBODY, apoptions),
		.field_name = "apoptions",
		.item = &ASN1_BIT_STRING_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 3,
		.offset = offsetof(KRB5_APREQBODY, ticket),
		.field_name = "ticket",
		.item = &KRB5_TICKET_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 4,
		.offset = offsetof(KRB5_APREQBODY, authenticator),
		.field_name = "authenticator",
		.item = &KRB5_ENCDATA_it,
	},
};

const ASN1_ITEM KRB5_APREQBODY_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_APREQBODY_seq_tt,
	.tcount = sizeof(KRB5_APREQBODY_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_APREQBODY),
	.sname = "KRB5_APREQBODY",
};


KRB5_APREQBODY *
d2i_KRB5_APREQBODY(KRB5_APREQBODY **a, const unsigned char **in, long len)
{
	return (KRB5_APREQBODY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_APREQBODY_it);
}

int
i2d_KRB5_APREQBODY(KRB5_APREQBODY *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_APREQBODY_it);
}

KRB5_APREQBODY *
KRB5_APREQBODY_new(void)
{
	return (KRB5_APREQBODY *)ASN1_item_new(&KRB5_APREQBODY_it);
}

void
KRB5_APREQBODY_free(KRB5_APREQBODY *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_APREQBODY_it);
}

static const ASN1_TEMPLATE KRB5_APREQ_item_tt =  {
	.flags = ASN1_TFLG_EXPTAG | ASN1_TFLG_APPLICATION,
	.tag = 14,
	.offset = 0,
	.field_name = "KRB5_APREQ",
	.item = &KRB5_APREQBODY_it,
};

const ASN1_ITEM KRB5_APREQ_it = {
	.itype = ASN1_ITYPE_PRIMITIVE,
	.utype = -1,
	.templates = &KRB5_APREQ_item_tt,
	.tcount = 0,
	.funcs = NULL,
	.size = 0,
	.sname = "KRB5_APREQ",
};


KRB5_APREQ *
d2i_KRB5_APREQ(KRB5_APREQ **a, const unsigned char **in, long len)
{
	return (KRB5_APREQ *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_APREQ_it);
}

int
i2d_KRB5_APREQ(KRB5_APREQ *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_APREQ_it);
}

KRB5_APREQ *
KRB5_APREQ_new(void)
{
	return (KRB5_APREQ *)ASN1_item_new(&KRB5_APREQ_it);
}

void
KRB5_APREQ_free(KRB5_APREQ *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_APREQ_it);
}


/*  Authenticator stuff 	*/

static const ASN1_TEMPLATE KRB5_CHECKSUM_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_CHECKSUM, ctype),
		.field_name = "ctype",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(KRB5_CHECKSUM, checksum),
		.field_name = "checksum",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM KRB5_CHECKSUM_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_CHECKSUM_seq_tt,
	.tcount = sizeof(KRB5_CHECKSUM_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_CHECKSUM),
	.sname = "KRB5_CHECKSUM",
};


KRB5_CHECKSUM *
d2i_KRB5_CHECKSUM(KRB5_CHECKSUM **a, const unsigned char **in, long len)
{
	return (KRB5_CHECKSUM *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_CHECKSUM_it);
}

int
i2d_KRB5_CHECKSUM(KRB5_CHECKSUM *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_CHECKSUM_it);
}

KRB5_CHECKSUM *
KRB5_CHECKSUM_new(void)
{
	return (KRB5_CHECKSUM *)ASN1_item_new(&KRB5_CHECKSUM_it);
}

void
KRB5_CHECKSUM_free(KRB5_CHECKSUM *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_CHECKSUM_it);
}


static const ASN1_TEMPLATE KRB5_ENCKEY_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_ENCKEY, ktype),
		.field_name = "ktype",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(KRB5_ENCKEY, keyvalue),
		.field_name = "keyvalue",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM KRB5_ENCKEY_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_ENCKEY_seq_tt,
	.tcount = sizeof(KRB5_ENCKEY_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_ENCKEY),
	.sname = "KRB5_ENCKEY",
};


KRB5_ENCKEY *
d2i_KRB5_ENCKEY(KRB5_ENCKEY **a, const unsigned char **in, long len)
{
	return (KRB5_ENCKEY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_ENCKEY_it);
}

int
i2d_KRB5_ENCKEY(KRB5_ENCKEY *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_ENCKEY_it);
}

KRB5_ENCKEY *
KRB5_ENCKEY_new(void)
{
	return (KRB5_ENCKEY *)ASN1_item_new(&KRB5_ENCKEY_it);
}

void
KRB5_ENCKEY_free(KRB5_ENCKEY *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_ENCKEY_it);
}


/* SEQ OF SEQ; see ASN1_EXP_SEQUENCE_OF_OPT() below */
static const ASN1_TEMPLATE KRB5_AUTHDATA_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_AUTHDATA, adtype),
		.field_name = "adtype",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(KRB5_AUTHDATA, addata),
		.field_name = "addata",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM KRB5_AUTHDATA_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_AUTHDATA_seq_tt,
	.tcount = sizeof(KRB5_AUTHDATA_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_AUTHDATA),
	.sname = "KRB5_AUTHDATA",
};


KRB5_AUTHDATA *
d2i_KRB5_AUTHDATA(KRB5_AUTHDATA **a, const unsigned char **in, long len)
{
	return (KRB5_AUTHDATA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_AUTHDATA_it);
}

int
i2d_KRB5_AUTHDATA(KRB5_AUTHDATA *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_AUTHDATA_it);
}

KRB5_AUTHDATA *
KRB5_AUTHDATA_new(void)
{
	return (KRB5_AUTHDATA *)ASN1_item_new(&KRB5_AUTHDATA_it);
}

void
KRB5_AUTHDATA_free(KRB5_AUTHDATA *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_AUTHDATA_it);
}


/* [APPLICATION 2] = 0x62 */
static const ASN1_TEMPLATE KRB5_AUTHENTBODY_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(KRB5_AUTHENTBODY, avno),
		.field_name = "avno",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(KRB5_AUTHENTBODY, crealm),
		.field_name = "crealm",
		.item = &ASN1_GENERALSTRING_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 2,
		.offset = offsetof(KRB5_AUTHENTBODY, cname),
		.field_name = "cname",
		.item = &KRB5_PRINCNAME_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
		.tag = 3,
		.offset = offsetof(KRB5_AUTHENTBODY, cksum),
		.field_name = "cksum",
		.item = &KRB5_CHECKSUM_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 4,
		.offset = offsetof(KRB5_AUTHENTBODY, cusec),
		.field_name = "cusec",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 5,
		.offset = offsetof(KRB5_AUTHENTBODY, ctime),
		.field_name = "ctime",
		.item = &ASN1_GENERALIZEDTIME_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
		.tag = 6,
		.offset = offsetof(KRB5_AUTHENTBODY, subkey),
		.field_name = "subkey",
		.item = &KRB5_ENCKEY_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
		.tag = 7,
		.offset = offsetof(KRB5_AUTHENTBODY, seqnum),
		.field_name = "seqnum",
		.item = &ASN1_INTEGER_it,
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
		.tag = 8,
		.offset = offsetof(KRB5_AUTHENTBODY, authorization),
		.field_name = "authorization",
		.item = &KRB5_AUTHDATA_it,
	},
};

const ASN1_ITEM KRB5_AUTHENTBODY_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = KRB5_AUTHENTBODY_seq_tt,
	.tcount = sizeof(KRB5_AUTHENTBODY_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(KRB5_AUTHENTBODY),
	.sname = "KRB5_AUTHENTBODY",
};


KRB5_AUTHENTBODY *
d2i_KRB5_AUTHENTBODY(KRB5_AUTHENTBODY **a, const unsigned char **in, long len)
{
	return (KRB5_AUTHENTBODY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_AUTHENTBODY_it);
}

int
i2d_KRB5_AUTHENTBODY(KRB5_AUTHENTBODY *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_AUTHENTBODY_it);
}

KRB5_AUTHENTBODY *
KRB5_AUTHENTBODY_new(void)
{
	return (KRB5_AUTHENTBODY *)ASN1_item_new(&KRB5_AUTHENTBODY_it);
}

void
KRB5_AUTHENTBODY_free(KRB5_AUTHENTBODY *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_AUTHENTBODY_it);
}

static const ASN1_TEMPLATE KRB5_AUTHENT_item_tt =  {
	.flags = ASN1_TFLG_EXPTAG | ASN1_TFLG_APPLICATION,
	.tag = 2,
	.offset = 0,
	.field_name = "KRB5_AUTHENT",
	.item = &KRB5_AUTHENTBODY_it,
};

const ASN1_ITEM KRB5_AUTHENT_it = {
	.itype = ASN1_ITYPE_PRIMITIVE,
	.utype = -1,
	.templates = &KRB5_AUTHENT_item_tt,
	.tcount = 0,
	.funcs = NULL,
	.size = 0,
	.sname = "KRB5_AUTHENT",
};


KRB5_AUTHENT *
d2i_KRB5_AUTHENT(KRB5_AUTHENT **a, const unsigned char **in, long len)
{
	return (KRB5_AUTHENT *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &KRB5_AUTHENT_it);
}

int
i2d_KRB5_AUTHENT(KRB5_AUTHENT *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &KRB5_AUTHENT_it);
}

KRB5_AUTHENT *
KRB5_AUTHENT_new(void)
{
	return (KRB5_AUTHENT *)ASN1_item_new(&KRB5_AUTHENT_it);
}

void
KRB5_AUTHENT_free(KRB5_AUTHENT *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &KRB5_AUTHENT_it);
}
