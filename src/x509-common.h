/*
 *  Copyright (C) 2022 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_COMMON_H__
#define __X509_COMMON_H__

#include "x509-utils.h"

typedef enum {
	CLASS_UNIVERSAL        = 0x00,
	CLASS_APPLICATION      = 0x01,
	CLASS_CONTEXT_SPECIFIC = 0x02,
	CLASS_PRIVATE          = 0x03
} tag_class;

typedef enum {
	ASN1_TYPE_BOOLEAN         = 0x01,
	ASN1_TYPE_INTEGER         = 0x02,
	ASN1_TYPE_BIT_STRING      = 0x03,
	ASN1_TYPE_OCTET_STRING    = 0x04,
	ASN1_TYPE_NULL            = 0x05,
	ASN1_TYPE_OID             = 0x06,
	ASN1_TYPE_ENUMERATED      = 0x0a,
	ASN1_TYPE_SEQUENCE        = 0x10,
	ASN1_TYPE_SET             = 0x11,
	ASN1_TYPE_PrintableString = 0x13,
	ASN1_TYPE_T61String       = 0x14,
	ASN1_TYPE_IA5String       = 0x16,
	ASN1_TYPE_UTCTime         = 0x17,
	ASN1_TYPE_GeneralizedTime = 0x18,
} asn1_type;


typedef enum {
	HASH_ALG_UNKNOWN      =  0,
	HASH_ALG_MD2          =  1,
	HASH_ALG_MD4	      =  2,
	HASH_ALG_MD5	      =  3,
	HASH_ALG_MDC2	      =  4,
	HASH_ALG_SHA1	      =  5,
	HASH_ALG_WHIRLPOOL    =  6,
	HASH_ALG_RIPEMD160    =  7,
	HASH_ALG_RIPEMD128    =  8,
	HASH_ALG_RIPEMD256    =  9,
	HASH_ALG_SHA224	      = 10,
	HASH_ALG_SHA256	      = 11,
	HASH_ALG_SHA384	      = 12,
	HASH_ALG_SHA512	      = 13,
	HASH_ALG_SHA512_224   = 14,
	HASH_ALG_SHA512_256   = 15,
	HASH_ALG_SHA3_224     = 16,
	HASH_ALG_SHA3_256     = 17,
	HASH_ALG_SHA3_384     = 18,
	HASH_ALG_SHA3_512     = 19,
	HASH_ALG_SHAKE128     = 20,
	HASH_ALG_SHAKE256     = 21,
	HASH_ALG_SM3          = 22,
	HASH_ALG_GOSTR3411_94 = 23,
	HASH_ALG_STREEBOG256  = 24,
	HASH_ALG_STREEBOG512  = 25,
	HASH_ALG_HBELT        = 26,
	HASH_ALG_BASH256      = 27,
	HASH_ALG_BASH384      = 28,
	HASH_ALG_BASH512      = 29
} hash_alg_id;


/*
 * For a given signature algorithm, optional parameters specific to the
 * algorithm may be given inside the AlgorithmIdentfier structure. Below,
 * we map each signature algorithm OID to a simple identifier and a
 * specific structure we use to export the info we parsed.
 */
typedef enum {
	SIG_ALG_UNKNOWN            =  0,
	SIG_ALG_DSA                =  1,
	SIG_ALG_RSA_SSA_PSS        =  2,
	SIG_ALG_RSA_PKCS1_V1_5     =  3,
	SIG_ALG_ED25519            =  4,
	SIG_ALG_ED448              =  5,
	SIG_ALG_SM2                =  6,
	SIG_ALG_GOSTR3410_2012_256 =  7,
	SIG_ALG_GOSTR3410_2012_512 =  8,
	SIG_ALG_GOSTR3410_2001     =  9,
	SIG_ALG_GOSTR3410_94       = 10,
	SIG_ALG_BIGN               = 11,
	SIG_ALG_ECDSA              = 12,
	SIG_ALG_RSA_9796_2_PAD     = 13,
	SIG_ALG_MONKEYSPHERE       = 14,
	SIG_ALG_BELGIAN_RSA        = 15,
} sig_alg_id;


typedef enum {
	MGF_ALG_UNKNOWN   = 0,
	MGF_ALG_MGF1      = 1  /* default for RSA SSA PSS */
} mgf_alg_id;


typedef enum {
	SPKI_ALG_UNKNOWN            =  0,
	SPKI_ALG_ECPUBKEY           =  1,
	SPKI_ALG_ED25519            =  2,
	SPKI_ALG_ED448              =  3,
	SPKI_ALG_X25519             =  4,
	SPKI_ALG_X448               =  5,
	SPKI_ALG_RSA                =  6,
	SPKI_ALG_DSA                =  7,
	SPKI_ALG_GOSTR3410_2012_256 =  8, /* 1.2.643.7.1.1.1.1 */
	SPKI_ALG_GOSTR3410_2012_512 =  9, /* 1.2.643.7.1.1.1.2 */
	SPKI_ALG_GOSTR3410_2001     = 10,
	SPKI_ALG_GOSTR3410_94       = 11,
	SPKI_ALG_BIGN_PUBKEY        = 12,
} spki_alg_id;


typedef enum {
	CURVE_UNKNOWN					=  0,
	CURVE_BIGN256v1					=  1,
	CURVE_BIGN384v1					=  2,
	CURVE_BIGN512v1					=  3,
	CURVE_C2PNB163V1				=  4,
	CURVE_SECT571K1					=  5,
	CURVE_SECT163K1					=  6,
	CURVE_SECP192K1					=  7,
	CURVE_SECP224K1					=  8,
	CURVE_SECP256K1					=  9,
	CURVE_SECP192R1					= 10,
	CURVE_SECP224R1					= 11,
	CURVE_SECP256R1					= 12,
	CURVE_SECP384R1					= 13,
	CURVE_SECP521R1					= 14,
	CURVE_BRAINPOOLP192R1				= 15,
	CURVE_BRAINPOOLP224R1				= 16,
	CURVE_BRAINPOOLP256R1				= 17,
	CURVE_BRAINPOOLP384R1				= 18,
	CURVE_BRAINPOOLP512R1				= 19,
	CURVE_BRAINPOOLP192T1				= 20,
	CURVE_BRAINPOOLP224T1				= 21,
	CURVE_BRAINPOOLP256T1				= 22,
	CURVE_BRAINPOOLP320R1				= 23,
	CURVE_BRAINPOOLP320T1				= 24,
	CURVE_BRAINPOOLP384T1				= 25,
	CURVE_BRAINPOOLP512T1				= 26,
	CURVE_SM2P256TEST				= 27,
	CURVE_SM2P256V1					= 28,
	CURVE_FRP256V1					= 29,
	CURVE_WEI25519					= 30,
	CURVE_WEI448					= 31,
	CURVE_GOST256					= 32,
	CURVE_GOST512					= 33,
	CURVE_GOST_R3410_2012_256_PARAMSETA		= 34,
	CURVE_GOST_R3410_2001_TESTPARAMSET		= 35,
	CURVE_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET	= 36,
	CURVE_GOST_R3410_2001_CRYPTOPRO_B_PARAMSET	= 37,
	CURVE_GOST_R3410_2001_CRYPTOPRO_C_PARAMSET	= 38,
	CURVE_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET	= 39,
	CURVE_GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET	= 40,
	CURVE_GOST_R3410_2012_256_PARAMSETB		= 41,
	CURVE_GOST_R3410_2012_256_PARAMSETC		= 42,
	CURVE_GOST_R3410_2012_256_PARAMSETD		= 43,
	CURVE_GOST_R3410_2012_512_PARAMSETTEST		= 44,
	CURVE_GOST_R3410_2012_512_PARAMSETA		= 45,
	CURVE_GOST_R3410_2012_512_PARAMSETB		= 46,
	CURVE_GOST_R3410_2012_512_PARAMSETC		= 47,
} curve_id;


typedef enum {
	GOST94_PARAMS_UNKNOWN         = 0,
	GOST94_PARAMS_TEST            = 1,
	GOST94_PARAMS_CRYPTOPRO_A     = 2,
	GOST94_PARAMS_CRYPTOPRO_B     = 3,
	GOST94_PARAMS_CRYPTOPRO_C     = 4,
	GOST94_PARAMS_CRYPTOPRO_D     = 5,
	GOST94_PARAMS_CRYPTOPRO_XCHA  = 6,
	GOST94_PARAMS_CRYPTOPRO_XCHB  = 7,
	GOST94_PARAMS_CRYPTOPRO_XCHC  = 8
} _gost94_pub_params_id;


typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u32 alg_der_oid_len;
	hash_alg_id hash_id;
} _hash_alg;

typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u32 alg_der_oid_len;
	const mgf_alg_id mgf_id;
} _mgf;

typedef struct {
	const _hash_alg *hash;
	const _mgf *mgf;
	const _hash_alg *mgf_hash;
	u32 salt_len;
	u32 trailer_field;
} _rsassa_pss;

typedef struct {
	const u8 *crv_name;
	const u8 *crv_printable_oid;
	const u8 *crv_der_oid;
	const u32 crv_der_oid_len;
	const u32 crv_order_bit_len;
	curve_id crv_id;
} _curve;


/*
 *                           SPKI
 *
 * Now, we need some specific structure to export information
 * extracted from SPKI for the various kind of subject public
 * key we support. We define a structure per type, and put
 * everything in a spki_params union.
 */

/*
 * RFC 5480, RFC 8813. implicitCurve and specifiedCurve MUST NOT be used; we
 * only support namedCurve, i.e. a curve_id is always set in the structure.
 */
typedef struct { /* SPKI_ALG_ECPUBKEY */
	curve_id curve;
	u32 curve_order_bit_len;

	int compression; /* 0x04: none, 0x02/0x03: compression w/ even/odd y */
	u32 ecc_raw_x_off;
	u32 ecc_raw_x_len;
	u32 ecc_raw_y_off; /* meaningful only if compression is 0x04 */
	u32 ecc_raw_y_len; /* meaningful only if compression is 0x04, 0 otherwise */
} spki_ecpubkey_params;

typedef struct { /* SPKI_ALG_ED25519 */
	curve_id curve;
	u32 curve_order_bit_len;

	u32 ed25519_raw_pub_off;
	u32 ed25519_raw_pub_len;
} spki_ed25519_params;

typedef struct { /* SPKI_ALG_ED448 */
	curve_id curve;
	u32 curve_order_bit_len;

	u32 ed448_raw_pub_off;
	u32 ed448_raw_pub_len;
} spki_ed448_params;

typedef struct { /* SPKI_ALG_X25519 */
	curve_id curve;
	u32 curve_order_bit_len;

	u32 x25519_raw_pub_off;
	u32 x25519_raw_pub_len;
} spki_x25519_params;

typedef struct { /* SPKI_ALG_X448 */
	curve_id curve;
	u32 curve_order_bit_len;

	u32 x448_raw_pub_off;
	u32 x448_raw_pub_len;
} spki_x448_params;

typedef struct { /* SPKI_ALG_RSA */
	/*
	 * Set when advertised in params (e.g. EA-RSA optionally has that).
	 * Otherwise, it is left to 0 when not advertised (cannot be 0 when
	 * advertised)
	 */
	u32 rsa_advertised_bit_len;

	u32 rsa_raw_modulus_off; /* modulus */
	u32 rsa_raw_modulus_len;
	u32 rsa_raw_pub_exp_off; /* public exponent */
	u32 rsa_raw_pub_exp_len;
} spki_rsa_params;

typedef struct { /* For SPKI_ALG_DSA */
	u32 dsa_raw_pub_off; /* public key */
	u32 dsa_raw_pub_len;
	u32 dsa_raw_p_off; /* group modulus */
	u32 dsa_raw_p_len;
	u32 dsa_raw_q_off; /* subgroup order */
	u32 dsa_raw_q_len;
	u32 dsa_raw_g_off; /* subgroup generator */
	u32 dsa_raw_g_len;
} spki_dsa_params;

/* RFC 4357, RFC 4491 */
typedef struct { /* SPKI_ALG_GOSTR3410_94 */
	u32 gost94_raw_pub_off;
	u32 gost94_raw_pub_len;
	_gost94_pub_params_id gost94_params_id;
} spki_gost94_params;

/* RFC 4491 */
typedef struct { /* SPKI_ALG_GOSTR3410_2001 */
	curve_id curve; /* publicKeyParamSet  in GOST parlance */
	u32 curve_order_bit_len;

	u32 gost2001_raw_x_pub_off; /* X */
	u32 gost2001_raw_x_pub_len; /* MUST be 32 */
	u32 gost2001_raw_y_pub_off; /* Y */
	u32 gost2001_raw_y_pub_len; /* MUST be 32 */
} spki_gost2001_params;

/* draft-deremin-rfc4491-bis-06 */
typedef struct { /* SPKI_ALG_GOSTR3410_2012_256 */
	curve_id curve; /* publicKeyParamSet in GOST parlance */
	u32 curve_order_bit_len;

	u32 gost2012_256_raw_x_pub_off; /* X */
	u32 gost2012_256_raw_x_pub_len; /* MUST be 32 */
	u32 gost2012_256_raw_y_pub_off; /* Y */
	u32 gost2012_256_raw_y_pub_len; /* MUST be 32 */
} spki_gost2012_256_params;

/* draft-deremin-rfc4491-bis-06 */
typedef struct { /* SPKI_ALG_GOSTR3410_2012_512 */
	curve_id curve; /* publicKeyParamSet  in GOST parlance */
	u32 curve_order_bit_len;

	u32 gost2012_512_raw_x_pub_off; /* X */
	u32 gost2012_512_raw_x_pub_len; /* MUST be 64 */
	u32 gost2012_512_raw_y_pub_off; /* Y */
	u32 gost2012_512_raw_y_pub_len; /* MUST be 64 */
} spki_gost2012_512_params;

/*
 * 7 certs with that SPKI. The only singularity is the
 * optional parameter providing the modulus length
 */
typedef spki_rsa_params spki_ea_rsa_params; /* SPKI_ALG_EA_RSA */

typedef struct { /* SPKI_ALG_BIGN_PUBKEY */
	curve_id curve;
	u32 curve_order_bit_len;

	/*
	 * BIGN pubkey is a bitstring encoding the public point on
	 * 512/8, 768/8, 1024/8 bytes based on the curve. The x
	 * and y coordinates of the public point are concatenated.
	 * For ease of use, we provide offset and length of
	 * each coordinates.
	 */
	u32 bign_raw_x_pub_off;
	u32 bign_raw_x_pub_len;
	u32 bign_raw_y_pub_off;
	u32 bign_raw_y_pub_len;
} spki_bign_params;

typedef struct { /* SPKI_ALG_AVEST */
	u32 avest_raw_pub_off;
	u32 avest_raw_pub_len;
} spki_avest_params;

/* we have only 2 different certs with that spki. */
typedef spki_rsa_params spki_weird_rsa_params; /* SPKI_ALG_WEIRD_RSA */

typedef union {
	spki_ecpubkey_params	 ecpubkey;     /* SPKI_ALG_ECPUBKEY	      */
	spki_ed25519_params	 ed25519;      /* SPKI_ALG_ED25519	      */
	spki_ed448_params	 ed448;	       /* SPKI_ALG_ED448	      */
	spki_x25519_params	 x25519;       /* SPKI_ALG_X25519	      */
	spki_x448_params	 x448;	       /* SPKI_ALG_X448		      */
	spki_rsa_params		 rsa;	       /* SPKI_ALG_RSA		      */
	spki_ea_rsa_params	 ea_rsa;       /* SPKI_ALG_EA_RSA	      */
	spki_dsa_params		 dsa;	       /* SPKI_ALG_DSA		      */
	spki_gost94_params	 gost94;       /* SPKI_ALG_GOSTR3410_94	      */
	spki_gost2001_params	 gost2001;     /* SPKI_ALG_GOSTR3410_2001     */
	spki_gost2012_256_params gost2012_256; /* SPKI_ALG_GOSTR3410_2012_256 */
	spki_gost2012_512_params gost2012_512; /* SPKI_ALG_GOSTR3410_2012_512 */
	spki_bign_params	 bign;	       /* SPKI_ALG_BIGN_PUBKEY	      */
	spki_avest_params	 avest;        /* SPKI_ALG_AVEST	      */
} spki_params;





/*
 *                           SIG
 *
 * Now, we need some specific structure to export information
 * extracted from signature algorithm identifier, associated
 * optional parameters and signature value. We define a structure
 * per sig alg type, and put everything in a sig_params union.
 */

typedef struct { /* SIG_ALG_DSA */
	u32 r_raw_off;
	u32 r_raw_len; /* depends on hash alg output size */
	u32 s_raw_off;
	u32 s_raw_len; /* depends on hash alg output size */
} sig_dsa_params;

typedef struct { /* SIG_ALG_RSA_SSA_PSS */
	u32 sig_raw_off;
	u32 sig_raw_len;

	mgf_alg_id mgf_alg;
	hash_alg_id mgf_hash_alg;
	u8 salt_len;
	u8 trailer_field;
} sig_rsa_ssa_pss_params;

typedef struct { /* SIG_ALG_RSA_PKCS1_V1_5 */
	u32 sig_raw_off;
	u32 sig_raw_len;
} sig_rsa_pkcs1_v1_5_params;

typedef sig_rsa_pkcs1_v1_5_params sig_rsa_9796_2_pad_params; /* SIG_ALG_RSA_9796_2_PAD */
typedef sig_rsa_pkcs1_v1_5_params sig_belgian_rsa_params; /* SIG_ALG_BELGIAN_RSA */

typedef struct { /* SIG_ALG_ED25519 */
	u32 r_raw_off;
	u32 r_raw_len; /* expects 32 */
	u32 s_raw_off;
	u32 s_raw_len; /* expects 32 */
} sig_ed25519_params;

typedef struct { /* SIG_ALG_ED448 */
	u32 r_raw_off;
	u32 r_raw_len; /* expects 57 */
	u32 s_raw_off;
	u32 s_raw_len; /* expects 57 */
} sig_ed448_params;

typedef struct { /* SIG_ALG_SM2 */
	u32 r_raw_off;
	u32 r_raw_len; /* expects 32 */
	u32 s_raw_off;
	u32 s_raw_len; /* expects 32 */
} sig_sm2_params;

typedef struct { /* SIG_ALG_GOSTR3410_2012_256 */
	u32 r_raw_off;
	u32 r_raw_len;  /* expect 32 */
	u32 s_raw_off;
	u32 s_raw_len;  /* expect 32 */
} sig_gost_r3410_2012_256_params;

typedef struct { /* SIG_ALG_GOSTR3410_2012_512 */
	u32 r_raw_off;
	u32 r_raw_len;  /* expect 64 */
	u32 s_raw_off;
	u32 s_raw_len;  /* expect 64 */
} sig_gost_r3410_2012_512_params;

typedef struct { /* SIG_ALG_GOSTR3410_2001 */
	u32 r_raw_off;
	u32 r_raw_len;  /* expect 32 */
	u32 s_raw_off;
	u32 s_raw_len;  /* expect 32 */
} sig_gost_r3410_2001_params;

typedef struct { /* SIG_ALG_GOSTR3410_94 */
	u32 r_raw_off;
	u32 r_raw_len; /* expect 32 */
	u32 s_raw_off;
	u32 s_raw_len; /* expect 32 */
} sig_gost_r3410_94_params;

typedef struct { /* SIG_ALG_BIGN */
	u32 sig_raw_off;
	u32 sig_raw_len; /* depends on curve */
} sig_bign_params;

typedef struct { /* SIG_ALG_ECDSA */
	u32 r_raw_off;
	u32 r_raw_len; /* depends on curve */
	u32 s_raw_off;
	u32 s_raw_len; /* depends on curve */
} sig_ecdsa_params;

typedef struct { /* SIG_ALG_MONKEYSPHERE */
	u32 sig_raw_off;
	u32 sig_raw_len;
} sig_monkeysphere_params;

typedef union {
	sig_dsa_params                 dsa;                 /* SIG_ALG_DSA */
	sig_rsa_ssa_pss_params         rsa_ssa_pss;         /* SIG_ALG_RSA_SSA_PSS */
	sig_rsa_pkcs1_v1_5_params      rsa_pkcs1_v1_5;      /* SIG_ALG_RSA_PKCS1_V1_5 */
	sig_ed25519_params             ed25519;             /* SIG_ALG_ED25519 */
	sig_ed448_params               ed448;               /* SIG_ALG_ED448 */
	sig_sm2_params                 sm2;                 /* SIG_ALG_SM2 */
	sig_gost_r3410_2012_256_params gost_r3410_2012_256; /* SIG_ALG_GOSTR3410_2012_256 */
	sig_gost_r3410_2012_512_params gost_r3410_2012_512; /* SIG_ALG_GOSTR3410_2012_512 */
	sig_gost_r3410_2001_params     gost_r3410_2001;     /* SIG_ALG_GOSTR3410_2001 */
	sig_gost_r3410_94_params       gost_r3410_94;       /* SIG_ALG_GOSTR3410_94 */
	sig_bign_params                bign;                /* SIG_ALG_BIGN */
	sig_ecdsa_params               ecdsa;               /* SIG_ALG_ECDSA */
	sig_rsa_9796_2_pad_params      rsa_9796_2_pad;      /* SIG_ALG_RSA_9796_2_PAD */
	sig_monkeysphere_params        monkeysphere;        /* SIG_ALG_MONKEYSPHERE */
	sig_belgian_rsa_params         belgian_rsa;         /* SIG_ALG_BELGIAN_RSA */
} sig_params;

/* Signature and sig alg parameters parsing functions */
int parse_sig_ed448(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_ed25519(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_ecdsa(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_sm2(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_dsa(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_rsa_pkcs1_v15(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_rsa_ssa_pss(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_rsa_9796_2_pad(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_rsa_belgian(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_gost94(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_gost2001(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_gost2012_512(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_gost2012_256(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_bign(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
int parse_sig_monkey(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);

int parse_algoid_sig_params_ecdsa_with(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_sig_params_ecdsa_with_specified(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_sig_params_sm2(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_sig_params_eddsa(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_params_rsa(const u8 *cert, u32 off, u32 len);
int parse_algoid_sig_params_rsa(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_sig_params_rsassa_pss(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_sig_params_none(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 ATTRIBUTE_UNUSED len);
int parse_algoid_sig_params_bign_with_hspec(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
int parse_algoid_params_none(const u8 *cert, u32 off, u32 len);


typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u32 alg_der_oid_len;

	sig_alg_id sig_id;
	hash_alg_id hash_id;

	int (*parse_algoid_sig_params)(sig_params *params, hash_alg_id *hash_alg, const u8 *cert, u32 off, u32 len);
	int (*parse_sig)(sig_params *params, const u8 *cert, u32 off, u32 len, u32 *eaten);
} _sig_alg;

extern const _sig_alg *known_sig_algs[];
extern const u16 num_known_sig_algs;

extern const _curve *known_curves[];

const _sig_alg * find_sig_alg_by_oid(const u8 *buf, u32 len);
const _hash_alg * find_hash_by_oid(const u8 *buf, u32 len);
const _curve * find_curve_by_oid(const u8 *buf, u32 len);


int get_length(const u8 *buf, u32 len,
	       u32 *adv_len, u32 *eaten);

int parse_id_len(const u8 *buf, u32 len,
		 tag_class exp_class, u32 exp_type,
		 u32 *parsed, u32 *content_len);

int parse_explicit_id_len(const u8 *buf, u32 len,
			  u32 exp_ext_type,
			  tag_class exp_int_class, u32 exp_int_type,
			  u32 *parsed, u32 *data_len);

int parse_null(const u8 *buf, u32 len,
	       u32 *parsed);

int parse_OID(const u8 *buf, u32 len,
	      u32 *parsed);

int parse_integer(const u8 *buf, u32 len,
		  tag_class exp_class, u32 exp_type,
		  u32 *hdr_len, u32 *data_len);

int parse_non_negative_integer(const u8 *buf, u32 len,
			       tag_class exp_class, u32 exp_type,
			       u32 *hdr_len, u32 *data_len);

int parse_boolean(const u8 *buf, u32 len, u32 *eaten);




int parse_generalizedTime(const u8 *buf, u32 len, u32 *eaten,
			  u16 *year, u8 *month, u8 *day,
			  u8 *hour, u8 *min, u8 *sec);

#define NAME_TYPE_rfc822Name     0x81
#define NAME_TYPE_dNSName        0x82
#define NAME_TYPE_URI            0x86
#define NAME_TYPE_iPAddress      0x87
#define NAME_TYPE_registeredID   0x88
#define NAME_TYPE_otherName      0xa0
#define NAME_TYPE_x400Address    0xa3
#define NAME_TYPE_directoryName  0xa4
#define NAME_TYPE_ediPartyName   0xa5

int parse_GeneralName(const u8 *buf, u32 len, u32 *eaten, int *empty);

int parse_SerialNumber(const u8 *cert, u32 off, u32 len,
		       tag_class exp_class, u32 exp_type,
		       u32 *eaten);

int verify_correct_time_use(u8 time_type, u16 yyyy);

int parse_Time(const u8 *buf, u32 len, u8 *t_type, u32 *eaten,
	       u16 *year, u8 *month, u8 *day,
	       u8 *hour, u8 *min, u8 *sec);

int verify_correct_time_use(u8 time_type, u16 yyyy);

int parse_AKICertSerialNumber(const u8 *cert, u32 off, u32 len,
			      tag_class exp_class, u32 exp_type,
			      u32 *eaten);

int parse_crldp_reasons(const u8 *buf, u32 len, u32 exp_type, u32 *eaten);

int parse_DistributionPoint(const u8 *buf, u32 len,
			    int *crldp_has_all_reasons, u32 *eaten);

int parse_AIA(const u8 *cert, u32 off, u32 len, int critical);

int parse_ia5_string(const u8 *buf, u32 len, u32 lb, u32 ub);

int parse_x509_Name(const u8 *buf, u32 len, u32 *eaten, int *empty);

int parse_DisplayText(const u8 *buf, u32 len, u32 *eaten);

int parse_nine_bit_named_bit_list(const u8 *buf, u32 len, u16 *val);

int parse_GeneralName(const u8 *buf, u32 len, u32 *eaten, int *empty);

int parse_GeneralNames(const u8 *buf, u32 len, tag_class exp_class,
		       u32 exp_type, u32 *eaten);

u64 time_components_to_comparable_u64(u16 na_year, u8 na_month, u8 na_day,
				      u8 na_hour, u8 na_min, u8 na_sec);

#endif /* __X509_COMMON_H__ */
