/*
 *  Copyright (C) 2019 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_PARSER_H__
#define __X509_PARSER_H__

#include <stdint.h>
#include <unistd.h>
#include <string.h>

#if defined(__FRAMAC__)
#define ATTRIBUTE_UNUSED
#else
#define ATTRIBUTE_UNUSED __attribute__((unused))
#endif

typedef uint8_t	  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * FIXME: document error values
 */

typedef enum {
	X509_PARSER_ERROR_VERSION_ABSENT            = -1,
	X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH = -2,
	X509_PARSER_ERROR_VERSION_NOT_3             = -3,
} x509_parser_errors;


/* Knob to skip over currently unknown RDN elements */
#define TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_RDN_OIDS

/*
 * Each certificate extension is made of an OID and an associated data value
 * for which we need a specific parsing function to validate the structure
 * of the data. This means that by default a certificate will be rejected if
 * an extensions is unknown. We define two macros to allow parsing to continue
 * when encoutering unsupported extensions (for which we do not have a specific
 * parsing function for data value)
 *
 * The first (TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS) handles
 * common extensions found in certificates which we know of but currently
 * have no parsing functions. Those extensions OID are explicitly referenced
 * in known_ext_oids table. When the knob is defined, the extensions data is
 * skipped to continue parsing, i.e. the structure of the data it carries is
 * NOT VERIFIED AT ALL. The check that the extension only appear once in the
 * certificate is performed.
 *
 * The second (TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS) is used as a
 * catch-all for extensions that are not known. When the knob is defined:
 *
 *  - unknown extensions data structure is NOT VERIFIED AT ALL
 *  - NO CHECK is performed to verify that the extension appears only once
 *    in the certificate.
 */
#define TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS
#define TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS

/*
 * Double the defined upper upper bound value of on common RDN components
 * (CN, O and OU) length from 64 to 128.
 */
#define TEMPORARY_LAXIST_RDN_UPPER_BOUND

/* Allow CA certificates w/o SKI. */
#define TEMPORARY_LAXIST_CA_WO_SKI

/* Allow emailAddress using UTF-8 encoding instead for IA5String. */
#define TEMPORARY_LAXIST_EMAILADDRESS_WITH_UTF8_ENCODING

/*
 * Same for otherwise unsupported extensions but for which we have an
 * internal reference to the OID
 */
#define TEMPORARY_BAD_EXT_OIDS

/*
 * Same for otherwise unsupported RDN but for which we have an internal
 * reference to the OID
 */
#define TEMPORARY_BAD_OID_RDN

/* Allow certificates w/ full directoryString . */
#define TEMPORARY_LAXIST_DIRECTORY_STRING

/*
 * Allow negative serial value
 */
#define TEMPORARY_LAXIST_SERIAL_NEGATIVE

/*
 * Allow large serial value. Limit is 20 bytes but some implementation
 * use larger serial.
 */
#define TEMPORARY_LAXIST_SERIAL_LENGTH

/*
 * Serial value is not expected to be 0. This knob make such certificate
 * valid.
 */
#define TEMPORARY_LAXIST_SERIAL_NULL

/*
 * Allow certificates w/ full basic constraints boolean explicitly set to false.
 * As this is the DEFAULT value, DER forbids encoding of that value.
 */
#define TEMPORARY_LAXIST_CA_BASIC_CONSTRAINTS_BOOLEAN_EXPLICIT_FALSE

/*
 * Allow certificates w/ extension's critical flag explicitly set to false.
 * As this is the DEFAULT value, DER forbids encoding of that value.
 */
#define TEMPORARY_LAXIST_EXTENSION_CRITICAL_FLAG_BOOLEAN_EXPLICIT_FALSE

/*
 * Allow certificates w/ SKI extension critical flag set. Section 4.2.1.1. of
 * RFC 5280 forbids that with a MUST.
 */
#define TEMPORARY_LAXIST_SKI_CRITICAL_FLAG_SET

/*
 * Allow serial DN component encoded as an IA5String whereas RFC 5280
 * requires such element to be encoded using printable string.
 */
#define TEMPORARY_LAXIST_SERIAL_RDN_AS_IA5STRING

/*
 * Do not kick certificates with empty RSA pubkey algoid params or empty sig
 * algoid parmas instead of the expected NULL.
 */
#define TEMPORARY_LAXIST_RSA_PUBKEY_AND_SIG_NO_PARAMS_INSTEAD_OF_NULL

/*
 * The following can be defined to enable an error trace to be
 * printed on standard output. The error path is made of the
 * lines in the representing the call graph leading to the
 * error.
 */
// #define ERROR_TRACE_ENABLE

/*
 * Max allowed buffer size for ASN.1 structures. Also note that
 * the type used for length in the whole code is an u32, so it
 * is pointless to set something higher than 2^32 - 1
 */
#define MAX_UINT32 (0xffffffffUL)
#define ASN1_MAX_BUFFER_SIZE (MAX_UINT32)

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


typedef struct {
	/* tbcCertificate */
	u32 tbs_start;
	u32 tbs_len;

	/* Version */
	int version;

	/* Serial */
	u32 serial_start;
	u32 serial_len;

	/* inner sig alg (tbsCertificate.signature) */
	u32 tbs_sig_alg_start;
	u32 tbs_sig_alg_len;
	u32 tbs_sig_alg_oid_start; /* OID for sig alg */
	u32 tbs_sig_alg_oid_len;
	u32 tbs_sig_alg_oid_params_start; /* params for sig alg */
	u32 tbs_sig_alg_oid_params_len;

	/* Issuer */
	u32 issuer_start;
	u32 issuer_len;

	/* Validity */
	u64 not_before;
	u64 not_after;

	/* Subject */
	u32 subject_start;
	u32 subject_len;
	int empty_subject;

	/* 1 if subject and issuer fields are binary equal */
	int subject_issuer_identical;

	/* SubjectPublicKeyInfo */
	u32 spki_start;
	u32 spki_len;
	u32 spki_alg_oid_start;
	u32 spki_alg_oid_len;
	u32 spki_alg_oid_params_start;
	u32 spki_alg_oid_params_len;
	u32 spki_pub_key_start;
	u32 spki_pub_key_len;
	spki_alg_id spki_alg;
	spki_params spki_alg_params;

	/* Extensions */

	    /* SKI related info, if present */
	    int has_ski;
	    u32 ski_start;
	    u32 ski_len;

	    /* AKI related info, if present */
	    int has_aki;
	    int aki_has_keyIdentifier;
	    u32 aki_keyIdentifier_start;
	    u32 aki_keyIdentifier_len;
	    int aki_has_generalNames_and_serial;
	    u32 aki_generalNames_start;
	    u32 aki_generalNames_len;
	    u32 aki_serial_start;
	    u32 aki_serial_len;

	    /* SAN */
	    int has_san;
	    int san_critical;

	    /* Basic constraints */
	    int bc_critical;
	    int ca_true;
	    int pathLenConstraint_set;

	    /* keyUsage */
	    int has_keyUsage;
	    int keyCertSign_set;
	    int cRLSign_set;

	    /* extendedKeyUsage (EKU) */
	    int has_eku;

	    /* CRLDP */
	    int has_crldp;
	    int one_crldp_has_all_reasons;

	    /* Name Constraints */
	    int has_name_constraints;


	/* signature alg */
	u32 sig_alg_start; /* outer sig alg */
	u32 sig_alg_len;
	sig_alg_id sig_alg; /* ID of signature alg */
	hash_alg_id hash_alg;
	sig_params sig_alg_params; /* depends on sig_alg */

	/* raw signature value */
	u32 sig_start;
	u32 sig_len;
} cert_parsing_ctx;

/*
 * Return 0 if parsing went OK, a non zero value otherwise.
 * 'len' must exactly match the size of the certificate
 * in the buffer 'buf' (i.e. nothing is expected behind).
 */
int parse_x509_cert(cert_parsing_ctx *ctx, const u8 *buf, u32 len);

/*
 * This wrapper around parse_x509_cert() does not expect the buffer
 * to exactly contain a DER-encoded certificate, but to start with
 * one. It returns the length of the first sequence found in the
 * buffer, no matter if the certificate (this sequence) is valid
 * or not. It only requires the buffer to start with a sequence.
 * A value of 1 is returned in 'remain' if the buffer does not
 * start with a sequence.
 */
int parse_x509_cert_relaxed(cert_parsing_ctx *ctx, const u8 *buf, u32 len, u32 *eaten);

#endif /* __X509_PARSER_H__ */
