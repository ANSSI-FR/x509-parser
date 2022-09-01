/*
 *  Copyright (C) 2022 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_PARSER_INTERNAL_DECL_H__
#define __X509_PARSER_INTERNAL_DECL_H__

#include "x509-parser.h"


/*
 * This file contains all the static and internal declarations of the project to
 * reduce the size of x509-parser.c file. No implementation is allowed in this
 * file. Offenders will be prosecuted.
 *
 * In this file, M-x toggle-truncate-lines is your friend ;-)
 */

/*
 * We need to pass some array as macro argument. Protection is needed in that
 * case.
 */
#define P99_PROTECT(...) __VA_ARGS__

typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u8 alg_der_oid_len;
	hash_alg_id hash_id;
} _hash_alg;

typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u8 alg_der_oid_len;
	const mgf_alg_id mgf_id;
} _mgf;

typedef struct {
	const _hash_alg *hash;
	const _mgf *mgf;
	const _hash_alg *mgf_hash;
	u8 salt_len;
	u8 trailer_field;
} _rsassa_pss;

typedef struct {
	const u8 *crv_name;
	const u8 *crv_printable_oid;
	const u8 *crv_der_oid;
	const u8 crv_der_oid_len;
	const u16 crv_order_bit_len;
	curve_id crv_id;
} _curve;

/* Signature and sig alg parameters parsing functions */
static int parse_sig_ed448(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_ed25519(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_ecdsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_sm2(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_dsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_rsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_gost94(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_gost2001(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_gost2012_512(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_gost2012_256(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_bign(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
static int parse_sig_monkey(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);

static int parse_algoid_sig_params_ecdsa_with(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_sig_params_ecdsa_with_specified(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_sig_params_sm2(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_sig_params_eddsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_sig_params_rsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_sig_params_rsassa_pss(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_sig_params_none(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 ATTRIBUTE_UNUSED len);
static int parse_algoid_sig_params_bign_with_hspec(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);

/* subject public key and spki params parsing functions */
static int parse_pubkey_ed448(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_x448(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_ed25519(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_x25519(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_ec(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_rsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_gostr3410_94(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_gostr3410_2001(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_gostr3410_2012_256(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_gostr3410_2012_512(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_dsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_pubkey_bign(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);

static int parse_algoid_pubkey_params_ecPublicKey(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_ed25519(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_ed448(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_x25519(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_x448(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_rsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_gost_r3410_2012_256(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_gost_r3410_2012_512(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_gost_r3410_2001(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_gost_r3410_94(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_dsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 len);
static int parse_algoid_pubkey_params_ea_rsa(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 ATTRIBUTE_UNUSED len);
static int parse_algoid_pubkey_params_none(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 ATTRIBUTE_UNUSED len);
static int parse_algoid_pubkey_params_bign(cert_parsing_ctx *ctx, const u8 *cert, u16 off, u16 ATTRIBUTE_UNUSED len);





/********************************************************************
 * Hash algs
 ********************************************************************/

#define DECL_HASH_ALG(TTalg, UUname, VVoid, WWoidbuf, XXtype) \
static const u8 _##TTalg##_hash_name[] = UUname;             \
static const u8 _##TTalg##_hash_printable_oid[] = VVoid;     \
static const u8 _##TTalg##_hash_der_oid[] = WWoidbuf;        \
							     \
static const _hash_alg _##TTalg##_hash_alg = {               \
	.alg_name = _##TTalg##_hash_name,                    \
	.alg_printable_oid = _##TTalg##_hash_printable_oid,  \
	.alg_der_oid = _##TTalg##_hash_der_oid,              \
	.alg_der_oid_len = sizeof(_##TTalg##_hash_der_oid),  \
	.hash_id = (XXtype),				     \
}

DECL_HASH_ALG(md2, "MD2", "1.2.840.113549.2.2", P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02 }), HASH_ALG_MD2);
DECL_HASH_ALG(md4, "MD4", "1.2.840.113549.2.4", P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04 }), HASH_ALG_MD4);
DECL_HASH_ALG(md5, "MD5", "1.2.840.113549.2.5", P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05 }), HASH_ALG_MD5);
DECL_HASH_ALG(mdc2, "MDC2", "1.3.14.3.2.19", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x13 }), HASH_ALG_MDC2);
DECL_HASH_ALG(sha1, "SHA1", "1.3.14.3.2.26", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a }), HASH_ALG_SHA1);
DECL_HASH_ALG(ripemd160, "RIPEMD160", "1.3.36.3.2.1", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01 }), HASH_ALG_RIPEMD160);
DECL_HASH_ALG(ripemd160_iso, "RIPEMD160", "1.0.10118.3.49", P99_PROTECT({ 0x06, 0x06, 0x28, 0xCF, 0x06, 0x03, 0x00, 0x31 }), HASH_ALG_RIPEMD160);
DECL_HASH_ALG(ripemd128, "RIPEMD128", "1.3.36.3.2.2", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x02 }), HASH_ALG_RIPEMD128);
DECL_HASH_ALG(ripemd128_iso, "RIPEMD128", "1.0.10118.3.50", P99_PROTECT({ 0x06, 0x06, 0x28, 0xCF, 0x06, 0x03, 0x00, 0x32 }), HASH_ALG_RIPEMD128);
DECL_HASH_ALG(ripemd256, "RIPEMD256", "1.3.36.3.2.3", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x03 }), HASH_ALG_RIPEMD256);
DECL_HASH_ALG(sha224, "SHA224", "2.16.840.1.101.3.4.2.4", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 }), HASH_ALG_SHA224);
DECL_HASH_ALG(sha256, "SHA256", "2.16.840.1.101.3.4.2.1", P99_PROTECT({  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }), HASH_ALG_SHA256);
DECL_HASH_ALG(sha384, "SHA384", "2.16.840.1.101.3.4.2.2", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 }), HASH_ALG_SHA384);
DECL_HASH_ALG(sha512, "SHA512", "2.16.840.1.101.3.4.2.3", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 }), HASH_ALG_SHA512);
DECL_HASH_ALG(sha512_224, "SHA512_224", "2.16.840.1.101.3.4.2.5", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05 }), HASH_ALG_SHA512_224);
DECL_HASH_ALG(sha512_256, "SHA512_256", "2.16.840.1.101.3.4.2.6", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,0x04, 0x02, 0x06 }), HASH_ALG_SHA512_256);
DECL_HASH_ALG(sha3_224, "SHA3_224", "2.16.840.1.101.3.4.2.7", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07 }), HASH_ALG_SHA3_224);
DECL_HASH_ALG(sha3_256, "SHA3_256", "2.16.840.1.101.3.4.2.8", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08 }), HASH_ALG_SHA3_256);
DECL_HASH_ALG(sha3_384, "SHA3_384", "2.16.840.1.101.3.4.2.9", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09 }), HASH_ALG_SHA3_384);
DECL_HASH_ALG(sha3_512, "SHA3_512", "2.16.840.1.101.3.4.2.10", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a }), HASH_ALG_SHA3_512);
DECL_HASH_ALG(shake128, "SHAKE128", "2.16.840.1.101.3.4.2.11", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b }), HASH_ALG_SHAKE128);
DECL_HASH_ALG(shake256, "SHAKE256", "2.16.840.1.101.3.4.2.12", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c }), HASH_ALG_SHAKE256);
DECL_HASH_ALG(hbelt, "HBELT", "1.2.112.0.2.0.34.101.31.81", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51 }), HASH_ALG_HBELT);
DECL_HASH_ALG(whirlpool, "WHIRLPOOL", "1.0.10118.3.55", P99_PROTECT({ 0x06, 0x06, 0x28, 0xCF, 0x06, 0x03, 0x00, 0x37 }), HASH_ALG_WHIRLPOOL);
DECL_HASH_ALG(streebog256, "STREEBOG256", "1.2.643.7.1.1.2.2", P99_PROTECT({ 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02 }), HASH_ALG_STREEBOG256);
DECL_HASH_ALG(streebog256_bis, "STREEBOG256", "1.0.10118.3.60", P99_PROTECT({ 0x06, 0x06, 0x28, 0xCF, 0x06, 0x03, 0x00, 0x3c }), HASH_ALG_STREEBOG256);
DECL_HASH_ALG(streebog512, "STREEBOG512", "1.2.643.7.1.1.2.3", P99_PROTECT({ 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03 }), HASH_ALG_STREEBOG512);
DECL_HASH_ALG(streebog512_bis, "STREEBOG512", "1.0.10118.3.59", P99_PROTECT({ 0x06, 0x06, 0x28, 0xCF, 0x06, 0x03, 0x00, 0x3b}), HASH_ALG_STREEBOG512);
DECL_HASH_ALG(sm3, "SM3", "1.0.10118.3.65", P99_PROTECT({ 0x06, 0x06, 0x28, 0xCF, 0x06, 0x03, 0x00, 0x41 }), HASH_ALG_SM3);
DECL_HASH_ALG(gostR3411_94, "GOST R 34.11-94", "1.2.643.2.2.9", P99_PROTECT({ 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x09 }), HASH_ALG_GOSTR3411_94);
DECL_HASH_ALG(gostR3411_94_bis, "GOST R 34.11-94", "1.2.643.2.2.30.1", P99_PROTECT({ 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 }), HASH_ALG_GOSTR3411_94); /* unclear see RFC 4357 */

static const _hash_alg *known_hashes[] = {
	&_md2_hash_alg,
	&_md4_hash_alg,
	&_md5_hash_alg,
	&_mdc2_hash_alg,
	&_sha1_hash_alg,
	&_ripemd160_hash_alg,
	&_ripemd160_iso_hash_alg,
	&_ripemd128_hash_alg,
	&_ripemd128_iso_hash_alg,
	&_ripemd256_hash_alg,
	&_sha224_hash_alg,
	&_sha256_hash_alg,
	&_sha384_hash_alg,
	&_sha512_hash_alg,
	&_sha512_224_hash_alg,
	&_sha512_256_hash_alg,
	&_sha3_224_hash_alg,
	&_sha3_256_hash_alg,
	&_sha3_384_hash_alg,
	&_sha3_512_hash_alg,
	&_shake128_hash_alg,
	&_shake256_hash_alg,
	&_hbelt_hash_alg,
	&_whirlpool_hash_alg,
	&_gostR3411_94_hash_alg,
	&_gostR3411_94_bis_hash_alg,
	&_streebog256_hash_alg,
	&_streebog256_bis_hash_alg,
	&_streebog512_hash_alg,
	&_streebog512_bis_hash_alg,
	&_sm3_hash_alg,
};

#define NUM_KNOWN_HASHES (sizeof(known_hashes) / sizeof(known_hashes[0]))





/********************************************************************
 * MGF algs (for RSA SSA PSS)
 ********************************************************************/

static const u8 _mgf_alg_mgf1_name[] = "MGF1";
static const u8 _mgf_alg_mgf1_printable_oid[] = "1.2.840.113549.1.1.8";
static const u8 _mgf_alg_mgf1_der_oid[] = { 0x06, 0x09, 0x2a, 0x86,
					    0x48, 0x86, 0xf7, 0x0d,
					    0x01, 0x01, 0x08 };

static const _mgf _mgf1_alg = {
	.alg_name = _mgf_alg_mgf1_name,
	.alg_printable_oid = _mgf_alg_mgf1_printable_oid,
	.alg_der_oid = _mgf_alg_mgf1_der_oid,
	.alg_der_oid_len = sizeof(_mgf_alg_mgf1_der_oid),
	.mgf_id = MGF_ALG_MGF1
};





/********************************************************************
 * Elliptic curves
 ********************************************************************/

#define DECL_CURVE(TTcurve, UUname, VVoid, WWoidbuf, XXtype, YYbitlen)    \
static const u8 _##TTcurve##_curve_name[] = UUname;                       \
static const u8 _##TTcurve##_curve_printable_oid[] = VVoid;               \
static const u8 _##TTcurve##_curve_der_oid[] = WWoidbuf;                  \
									  \
static const _curve _curve_##TTcurve = {                                  \
	.crv_name = _##TTcurve##_curve_name,                              \
	.crv_printable_oid = _##TTcurve##_curve_printable_oid,            \
	.crv_der_oid = _##TTcurve##_curve_der_oid,                        \
	.crv_der_oid_len = sizeof(_##TTcurve##_curve_der_oid),            \
	.crv_order_bit_len = (YYbitlen),				  \
	.crv_id = (XXtype),						  \
}

DECL_CURVE(Curve25519, "Curve25519", "1.3.6.1.4.1.11591.15.1", P99_PROTECT({ 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 }), CURVE_WEI25519, 256);
DECL_CURVE(Curve448, "Curve448", "1.3.6.1.4.1.11591.15.2", P99_PROTECT({ 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x02 }), CURVE_WEI448, 448);
DECL_CURVE(bign_curve256v1, "bign-curve256v1", "1.2.112.0.2.0.34.101.45.3.1", P99_PROTECT({ 0x06, 0x0a, 0x2a, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x2d, 0x03, 0x01 }), CURVE_BIGN256v1, 256);
DECL_CURVE(bign_curve384v1, "bign-curve384v1", "1.2.112.0.2.0.34.101.45.3.2", P99_PROTECT({ 0x06, 0x0a, 0x2a, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x2d, 0x03, 0x02 }), CURVE_BIGN384v1, 384);
DECL_CURVE(bign_curve512v1, "bign-curve512v1", "1.2.112.0.2.0.34.101.45.3.3", P99_PROTECT({ 0x06, 0x0a, 0x2a, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x2d, 0x03, 0x03 }), CURVE_BIGN512v1, 512);
DECL_CURVE(prime192v1, "prime192v1", "1.2.840.10045.3.0.1", P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01 }), CURVE_SECP192R1, 192);
DECL_CURVE(c2pnb163v1, "c2pnb163v1", "1.2.840.10045.3.0.1", P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x01 }), CURVE_C2PNB163V1, 163);
DECL_CURVE(sect571k1, "sect571k1", "1.3.132.0.38", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x26 }), CURVE_SECT571K1, 571);
DECL_CURVE(sect163k1, "sect163k1", "1.3.132.0.1", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x01 }), CURVE_SECT163K1, 163);
DECL_CURVE(secp192k1, "secp192k1", "1.3.132.0.31", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x1f }), CURVE_SECP192K1, 192);
DECL_CURVE(secp224k1, "secp224k1", "1.3.132.0.32", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x20 }), CURVE_SECP224K1, 224);
DECL_CURVE(secp256k1, "secp256k1", "1.3.132.0.10", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a }), CURVE_SECP256K1, 256);
DECL_CURVE(secp224r1, "secp224r1", "1.3.132.0.33", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21 }), CURVE_SECP224R1, 224);
DECL_CURVE(secp256r1, "secp256r1", "1.2.840.10045.3.1.7", P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }), CURVE_SECP256R1, 256);
DECL_CURVE(secp384r1, "secp384r1", "1.3.132.0.34", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }), CURVE_SECP384R1, 384);
DECL_CURVE(secp521r1, "secp521r1", "1.3.132.0.35", P99_PROTECT({ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 }), CURVE_SECP521R1, 521);
DECL_CURVE(brainpoolP192R1, "brainpoolP192R1", "1.3.36.3.3.2.8.1.1.3", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03 }), CURVE_BRAINPOOLP192R1, 192);
DECL_CURVE(brainpoolP224R1, "brainpoolP224R1", "1.3.36.3.3.2.8.1.1.5", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05 }), CURVE_BRAINPOOLP224R1, 224);
DECL_CURVE(brainpoolP256R1, "brainpoolP256R1", "1.3.36.3.3.2.8.1.1.7", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 }), CURVE_BRAINPOOLP256R1, 256);
DECL_CURVE(brainpoolP320R1, "brainpoolP320R1", "1.3.36.3.3.2.8.1.1.9", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09 }), CURVE_BRAINPOOLP320R1, 320);
DECL_CURVE(brainpoolP384R1, "brainpoolP384R1", "1.3.36.3.3.2.8.1.1.11", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08,0x01, 0x01, 0x0b }), CURVE_BRAINPOOLP384R1, 384);
DECL_CURVE(brainpoolP512R1, "brainpoolP512R1", "1.3.36.3.3.2.8.1.1.13", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d }), CURVE_BRAINPOOLP512R1, 512);
DECL_CURVE(brainpoolP192T1, "brainpoolP192T1", "1.3.36.3.3.2.8.1.1.4", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04 }), CURVE_BRAINPOOLP192T1, 192);
DECL_CURVE(brainpoolP224T1, "brainpoolP224T1", "1.3.36.3.3.2.8.1.1.6", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06 }), CURVE_BRAINPOOLP224T1, 224);
DECL_CURVE(brainpoolP256T1, "brainpoolP256T1", "1.3.36.3.3.2.8.1.1.8", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08 }), CURVE_BRAINPOOLP256T1, 256);
DECL_CURVE(brainpoolP320T1, "brainpoolP320T1", "1.3.36.3.3.2.8.1.1.10", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0a }), CURVE_BRAINPOOLP320T1, 320);
DECL_CURVE(brainpoolP384T1, "brainpoolP384T1", "1.3.36.3.3.2.8.1.1.12", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0c }), CURVE_BRAINPOOLP384T1, 384);
DECL_CURVE(brainpoolP512T1, "brainpoolP512T1", "1.3.36.3.3.2.8.1.1.14", P99_PROTECT({ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0e }), CURVE_BRAINPOOLP512T1, 512);
DECL_CURVE(sm2p256v1, "sm2p256v1", "1.2.156.10197.1.301", P99_PROTECT({ 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d }), CURVE_SM2P256V1, 256);
DECL_CURVE(frp256v1, "frp256v1", "1.2.250.1.223.101.256.1", P99_PROTECT({ 0x06, 0x0A, 0x2A, 0x81, 0x7A, 0x01, 0x81, 0x5F, 0x65, 0x82, 0x00, 0x01 }), CURVE_FRP256V1, 256);
DECL_CURVE(gost_R3410_2001_CryptoPro_A_ParamSet, "gost_R3410_2001_CryptoPro_A_ParamSet", "1.2.643.2.2.35.1", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 }), CURVE_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET, 256);
DECL_CURVE(gost_R3410_2001_CryptoPro_B_ParamSet, "gost_R3410_2001_CryptoPro_B_ParamSet", "1.2.643.2.2.35.2", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02 }), CURVE_GOST_R3410_2001_CRYPTOPRO_B_PARAMSET, 256);
DECL_CURVE(gost_R3410_2001_CryptoPro_C_ParamSet, "gost_R3410_2001_CryptoPro_C_ParamSet", "1.2.643.2.2.35.3", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03 }), CURVE_GOST_R3410_2001_CRYPTOPRO_C_PARAMSET, 256);
DECL_CURVE(gost_R3410_2001_CryptoPro_XchA_ParamSet, "gost_R3410_2001_CryptoPro_XchA_ParamSet", "1.2.643.2.2.36.0", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00 }), CURVE_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET, 256);
DECL_CURVE(gost_R3410_2001_CryptoPro_XchB_ParamSet, "gost_R3410_2001_CryptoPro_XchB_ParamSet", "1.2.643.2.2.36.1", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01 }), CURVE_GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET, 256);
DECL_CURVE(gost_R3410_2001_TestParamSet, "gost_R3410_2001_TestParamSet", "1.2.643.2.2.35.0", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x00 }), CURVE_GOST_R3410_2001_TESTPARAMSET, 256);
DECL_CURVE(gost_R3410_2012_256_paramSetA, "gost_R3410_2012_256_paramSetA", "1.2.643.7.1.2.1.1.1", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01 }), CURVE_GOST_R3410_2012_256_PARAMSETA, 257);
DECL_CURVE(gost_R3410_2012_256_paramSetB, "gost_R3410_2012_256_paramSetB", "1.2.643.7.1.2.1.1.2", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02 }), CURVE_GOST_R3410_2012_256_PARAMSETB, 256);
DECL_CURVE(gost_R3410_2012_256_paramSetC, "gost_R3410_2012_256_paramSetC", "1.2.643.7.1.2.1.1.3", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02 }), CURVE_GOST_R3410_2012_256_PARAMSETC, 256);
DECL_CURVE(gost_R3410_2012_256_paramSetD, "gost_R3410_2012_256_paramSetD", "1.2.643.7.1.2.1.1.4", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x04 }), CURVE_GOST_R3410_2012_256_PARAMSETD, 256);
DECL_CURVE(gost_R3410_2012_512_paramSetA, "gost_R3410_2012_512_paramSetA", "1.2.643.7.1.2.1.2.1", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01 }), CURVE_GOST_R3410_2012_512_PARAMSETA, 512);
DECL_CURVE(gost_R3410_2012_512_paramSetB, "gost_R3410_2012_512_paramSetB", "1.2.643.7.1.2.1.2.2", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02 }), CURVE_GOST_R3410_2012_512_PARAMSETB, 512);
DECL_CURVE(gost_R3410_2012_512_paramSetC, "gost_R3410_2012_512_paramSetC", "1.2.643.7.1.2.1.2.3", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x03 }), CURVE_GOST_R3410_2012_512_PARAMSETC, 512);
DECL_CURVE(gost_R3410_2012_512_paramSetTest, "gost_R3410_2012_512_paramSetTest",  "1.2.643.7.1.2.1.2.0", P99_PROTECT({ 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x00 }), CURVE_GOST_R3410_2012_512_PARAMSETTEST, 511);

static const _curve *known_curves[] = {
	&_curve_secp224r1,
	&_curve_secp256r1,
	&_curve_secp384r1,
	&_curve_secp521r1,
	&_curve_prime192v1,
	&_curve_c2pnb163v1,
	&_curve_sect571k1,
	&_curve_sect163k1,
	&_curve_secp192k1,
	&_curve_secp224k1,
	&_curve_secp256k1,

	&_curve_brainpoolP192R1,
	&_curve_brainpoolP224R1,
	&_curve_brainpoolP256R1,
	&_curve_brainpoolP320R1,
	&_curve_brainpoolP384R1,
	&_curve_brainpoolP512R1,
	&_curve_brainpoolP192T1,
	&_curve_brainpoolP224T1,
	&_curve_brainpoolP256T1,
	&_curve_brainpoolP320T1,
	&_curve_brainpoolP384T1,
	&_curve_brainpoolP512T1,

	&_curve_sm2p256v1,

	&_curve_bign_curve256v1,
	&_curve_bign_curve384v1,
	&_curve_bign_curve512v1,

	&_curve_frp256v1,

	&_curve_gost_R3410_2001_CryptoPro_A_ParamSet,
	&_curve_gost_R3410_2001_CryptoPro_B_ParamSet,
	&_curve_gost_R3410_2001_CryptoPro_C_ParamSet,
	&_curve_gost_R3410_2001_CryptoPro_XchA_ParamSet,
	&_curve_gost_R3410_2001_CryptoPro_XchB_ParamSet,
	&_curve_gost_R3410_2001_TestParamSet,
	&_curve_gost_R3410_2012_256_paramSetA,
	&_curve_gost_R3410_2012_256_paramSetB,
	&_curve_gost_R3410_2012_256_paramSetC,
	&_curve_gost_R3410_2012_256_paramSetD,
	&_curve_gost_R3410_2012_512_paramSetA,
	&_curve_gost_R3410_2012_512_paramSetB,
	&_curve_gost_R3410_2012_512_paramSetC,
	&_curve_gost_R3410_2012_512_paramSetTest,

	&_curve_Curve25519,
	&_curve_Curve448,
};

#define NUM_KNOWN_CURVES (sizeof(known_curves) / sizeof(known_curves[0]))





/********************************************************************
 * Signature algs
 ********************************************************************/

typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u8 alg_der_oid_len;

	sig_alg_id sig_id;
	hash_alg_id hash_id;

	int (*parse_algoid_sig_params)(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx, const u8 *cert, u16 off, u16 len);
	int (*parse_sig)(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx, const u8 *cert, u16 off, u16 len, u16 *eaten);
} _sig_alg;

#define DECL_SIG_ALG(TTalg, SSsig, HHhash, YYparse_sig, ZZparse_algoid, UUname, VVoid, WWoidbuf) \
static const u8 _##TTalg##_sig_name[] = UUname;             \
static const u8 _##TTalg##_sig_printable_oid[] = VVoid;     \
static const u8 _##TTalg##_sig_der_oid[] = WWoidbuf;        \
							    \
static const _sig_alg _##TTalg##_sig_alg = {                \
	.alg_name = _##TTalg##_sig_name,                    \
	.alg_printable_oid = _##TTalg##_sig_printable_oid,  \
	.alg_der_oid = _##TTalg##_sig_der_oid,              \
	.alg_der_oid_len = sizeof(_##TTalg##_sig_der_oid),  \
	.sig_id = (SSsig),				    \
	.hash_id = (HHhash),				    \
	.parse_sig = (YYparse_sig),			    \
	.parse_algoid_sig_params = (ZZparse_algoid),	    \
}

/*
 *-----------------------------------+---------------------------+----------------------+-----------------------+---------------------------------------------+-----------------------------------------------+-----------------------------+----------------------...
 *           struct name             | signature alg             | hash alg if known    | sig parsing func      | sig algs params parsing func                | pretty name for sig alg                       | printable OID               | OID in DER format
 *-----------------------------------+---------------------------+----------------------+-----------------------+---------------------------------------------+-----------------------------------------------+-----------------------------+----------------------...
 */
DECL_SIG_ALG(ecdsa_sha1              , SIG_ALG_ECDSA             , HASH_ALG_SHA1        , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-SHA1"                             , "1.2.840.10045.4.1"         , P99_PROTECT({ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01 }));
DECL_SIG_ALG(ecdsa_sha224            , SIG_ALG_ECDSA             , HASH_ALG_SHA224      , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-SHA224"                           , "1.2.840.10045.4.3.1"       , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01 }));
DECL_SIG_ALG(ecdsa_sha256            , SIG_ALG_ECDSA             , HASH_ALG_SHA256      , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-SHA256"                           , "1.2.840.10045.4.3.2"       , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }));
DECL_SIG_ALG(ecdsa_sha384            , SIG_ALG_ECDSA             , HASH_ALG_SHA384      , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-SHA384"                           , "1.2.840.10045.4.3.3"       , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 }));
DECL_SIG_ALG(ecdsa_sha512            , SIG_ALG_ECDSA             , HASH_ALG_SHA512      , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-SHA512"                           , "1.2.840.10045.4.3.4"       , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 }));
DECL_SIG_ALG(ecdsa_with_sha3_256     , SIG_ALG_ECDSA             , HASH_ALG_SHA3_256    , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "id-ecdsa-with-sha3-256"                      , "2.16.840.1.101.3.4.3.10"   , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0a }));
DECL_SIG_ALG(ecdsa_with_shake128     , SIG_ALG_ECDSA             , HASH_ALG_SHAKE128    , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-shake128"                         , "1.3.6.1.5.5.7.6.32"        , P99_PROTECT({ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20 })); /* RFC 8692 */
DECL_SIG_ALG(ecdsa_with_shake256     , SIG_ALG_ECDSA             , HASH_ALG_SHAKE256    , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with          , "ecdsa-with-shake256"                         , "1.3.6.1.5.5.7.6.32"        , P99_PROTECT({ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20 })); /* RFC 8692 */
DECL_SIG_ALG(ecdsa_with_specified    , SIG_ALG_ECDSA             , HASH_ALG_UNKNOWN     , parse_sig_ecdsa       , parse_algoid_sig_params_ecdsa_with_specified, "ecdsa-with-specified"                        , "1.2.840.10045.4.3"         , P99_PROTECT({ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03 })); /* draft-ietf-pkix-sha2-dsa-ecdsa-03 */
DECL_SIG_ALG(ed25519                 , SIG_ALG_ED25519           , HASH_ALG_SHA512      , parse_sig_ed25519     , parse_algoid_sig_params_eddsa               , "Ed25519"                                     , "1.3.101.112"               , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x70 }));
DECL_SIG_ALG(ed448                   , SIG_ALG_ED448             , HASH_ALG_SHAKE256    , parse_sig_ed448       , parse_algoid_sig_params_eddsa               , "Ed448"                                       , "1.3.101.113"               , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x71 }));
DECL_SIG_ALG(sm2_sm3                 , SIG_ALG_SM2               , HASH_ALG_SM3         , parse_sig_sm2         , parse_algoid_sig_params_sm2                 , "SM2 w/ SM3"                                  , "1.2.156.10197.1.501"       , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75 }));
DECL_SIG_ALG(rsa_mdc2                , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_MDC2        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "mdc2WithRSA"                                 , "2.5.8.3.100"               , P99_PROTECT({ 0x06, 0x04, 0x55, 0x08, 0x03, 0x64 }));
DECL_SIG_ALG(rsa_md2                 , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_MD2         , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "md2WithRSAEncryption"                        , "1.2.840.113549.1.1.2"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02 }));
DECL_SIG_ALG(rsa_md4                 , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_MD4         , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "md4WithRSAEncryption"                        , "1.2.840.113549.1.1.3"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x03 }));
DECL_SIG_ALG(rsa_md5                 , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_MD5         , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "md5WithRSAEncryption"                        , "1.2.840.113549.1.1.4"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04 }));
DECL_SIG_ALG(sha1WithRSAEnc          , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha1WithRSAEncryption"                       , "1.2.840.113549.1.1.5"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 }));
DECL_SIG_ALG(sha1WithRSAEnc_bis      , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha1WithRSAEncryption (bis)"                 , "1.3.14.3.2.29"             , P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d }));
DECL_SIG_ALG(sha1WithRSAEnc_alt      , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha1WithRSAEncryption_alt"                   , "1.2.836.113549.1.1.5"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x44, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 })); /* XXX CRAP. typo or SEU ? */
DECL_SIG_ALG(sha1WithRSAEnc_alt2     , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha1WithRSAEncryption_alt2"                  , "1.2.4936.113549.1.1.5"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0xa6, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 })); /* XXX CRAP. typo or SEU ? */
DECL_SIG_ALG(sha1WithRSAEnc_ter      , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha1WithRSAEncryption (ter)"                 , "1.2.840.113549.0.1.5"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x00, 0x01, 0x05 })); /* CRAP */
DECL_SIG_ALG(rsa_sha1_crap           , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "Another unspecified RSA-SHA1 oid"            , "1.2.856.113549.1.1.5"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x58, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 })); /* CRAP */
DECL_SIG_ALG(rsa_sha1_crap_bis       , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "crappy sha1-with-rsa-signature"              , "1.2.872.113549.1.1.5"      , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x68, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 })); /* CRAP */
DECL_SIG_ALG(shaWithRSASig_9796_2    , SIG_ALG_RSA_9796_2_PAD    , HASH_ALG_SHA1        , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "shaWithRSASignature-9796-2"                  , "1.3.14.3.2.15"             , P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x0f })); /* Oddball using ISO/IEC 9796-2 padding rules */
DECL_SIG_ALG(rsa_sha224              , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA224      , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha224WithRSAEncryption"                     , "1.2.840.113549.1.1.14"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e }));
DECL_SIG_ALG(rsa_sha256              , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA256      , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha256WithRSAEncryption"                     , "1.2.840.113549.1.1.11"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }));
DECL_SIG_ALG(rsa_sha384              , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA384      , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha384WithRSAEncryption"                     , "1.2.840.113549.1.1.12"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c }));
DECL_SIG_ALG(rsa_sha512              , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA512      , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "sha512WithRSAEncryption"                     , "1.2.840.113549.1.1.13"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d }));
DECL_SIG_ALG(rsa_ripemd160           , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_RIPEMD160   , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "rsaSignatureWithripemd160"                   , "1.3.36.3.3.1.2"            , P99_PROTECT({ 0x06, 0x06, 0x2b, 0x24, 0x03, 0x03, 0x01, 0x02 }));
DECL_SIG_ALG(rsa_ripemd128           , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_RIPEMD128   , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "rsaSignatureWithripemd128"                   , "1.3.36.3.3.1.3"            , P99_PROTECT({ 0x06, 0x06, 0x2b, 0x24, 0x03, 0x03, 0x01, 0x03 }));
DECL_SIG_ALG(rsa_ripemd256           , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_RIPEMD256   , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "rsaSignatureWithripemd256"                   , "1.3.36.3.3.1.3"            , P99_PROTECT({ 0x06, 0x06, 0x2b, 0x24, 0x03, 0x03, 0x01, 0x03 }));
DECL_SIG_ALG(pkcs1_v15_w_sha3_224    , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA3_224    , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "id-rsassa-pkcs1-v1-5-with-sha3-224"          , "2.16.840.1.101.3.4.3.13"   , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0d }));
DECL_SIG_ALG(pkcs1_v15_w_sha3_256    , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA3_256    , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "id-rsassa-pkcs1-v1-5-with-sha3-256"          , "2.16.840.1.101.3.4.3.14"   , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e }));
DECL_SIG_ALG(pkcs1_v15_w_sha3_384    , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA3_384    , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "id-rsassa-pkcs1-v1-5-with-sha3-384"          , "2.16.840.1.1.1.3.4.3.15"   , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0f,  }));
DECL_SIG_ALG(pkcs1_v15_w_sha3_512    , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_SHA3_512    , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "id-rsassa-pkcs1-v1-5-with-sha3-512"          , "2.16.840.1.1.1.3.4.3.16"   , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10,  }));
DECL_SIG_ALG(rsassa_pss              , SIG_ALG_RSA_SSA_PSS       , HASH_ALG_UNKNOWN     , parse_sig_rsa         , parse_algoid_sig_params_rsassa_pss          , "RSASSA-PSS"                                  , "1.2.840.113549.1.1.10"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a }));
DECL_SIG_ALG(rsassa_pss_shake128     , SIG_ALG_RSA_SSA_PSS       , HASH_ALG_SHAKE128    , parse_sig_rsa         , parse_algoid_sig_params_none                , "RSASSA-PSS-SHAKE128"                         , "1.3.6.1.5.5.7.6.30"        , P99_PROTECT({ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e }));  /* RFC 8692 */
DECL_SIG_ALG(rsassa_pss_shake256     , SIG_ALG_RSA_SSA_PSS       , HASH_ALG_SHAKE256    , parse_sig_rsa         , parse_algoid_sig_params_none                , "RSASSA-PSS-SHAKE256"                         , "1.3.6.1.5.5.7.6.31"        , P99_PROTECT({ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f }));  /* RFC 8692 */
DECL_SIG_ALG(belgian_rsa             , SIG_ALG_BELGIAN_RSA       , HASH_ALG_UNKNOWN     , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "Undoc. Belgian RSA sig oid"                  , "2.16.56.2.1.4.1.1.3880.1"  , P99_PROTECT({ 0x06, 0x0b, 0x60, 0x38, 0x02, 0x01, 0x04, 0x01, 0x01, 0x82, 0xaf, 0x16, 0x01 })); /* Belgian CRAP */
DECL_SIG_ALG(rsalabs1                , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_UNKNOWN     , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "Unknown RSA Labs OID"                        , "1.2.840.113549.1.1.99"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x63 }));
DECL_SIG_ALG(rsalabs2                , SIG_ALG_RSA_PKCS1_V1_5    , HASH_ALG_UNKNOWN     , parse_sig_rsa         , parse_algoid_sig_params_rsa                 , "Unspecified RSA oid"                         , "1.2.840.113605.1.1.11"     , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x45, 0x01, 0x01, 0x0b }));
DECL_SIG_ALG(dsa_sha1                , SIG_ALG_DSA               , HASH_ALG_SHA1        , parse_sig_dsa         , parse_algoid_sig_params_none                , "dsaWithSHA1"                                 , "1.3.14.3.2.27"             , P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1b }));
DECL_SIG_ALG(dsa_sha1_old            , SIG_ALG_DSA               , HASH_ALG_SHA1        , parse_sig_dsa         , parse_algoid_sig_params_none                , "dsaWithSHA1-old"                             , "1.3.14.3.2.12"             , P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x0c }));
DECL_SIG_ALG(dsa_sha1_jdk            , SIG_ALG_DSA               , HASH_ALG_SHA1        , parse_sig_dsa         , parse_algoid_sig_params_none                , "dsaWithSHA1-jdk"                             , "1.3.14.3.2.13"             , P99_PROTECT({ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x0d })); /* oid-info.com has "Incorrectly used by the JDK 1.1 in place of 1.3.14.3.2.27" */
DECL_SIG_ALG(dsa_sha1_bis            , SIG_ALG_DSA               , HASH_ALG_SHA1        , parse_sig_dsa         , parse_algoid_sig_params_none                , "dsa-with-sha1"                               , "1.2.840.10040.4.3"         , P99_PROTECT({ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03 }));
DECL_SIG_ALG(dsa_with_sha224         , SIG_ALG_DSA               , HASH_ALG_SHA224      , parse_sig_dsa         , parse_algoid_sig_params_none                , "id-dsa-with-sha224"                          , "2.16.840.1.101.3.4.3.1"    , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01 }));
DECL_SIG_ALG(dsa_with_sha256         , SIG_ALG_DSA               , HASH_ALG_SHA256      , parse_sig_dsa         , parse_algoid_sig_params_none                , "id-dsa-with-sha256"                          , "2.16.840.1.101.3.4.3.2"    , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02 }));
DECL_SIG_ALG(dsa_with_sha384         , SIG_ALG_DSA               , HASH_ALG_SHA384      , parse_sig_dsa         , parse_algoid_sig_params_none                , "id-dsa-with-sha384"                          , "2.16.840.1.101.3.4.3.3"    , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03 }));
DECL_SIG_ALG(dsa_with_sha512         , SIG_ALG_DSA               , HASH_ALG_SHA512      , parse_sig_dsa         , parse_algoid_sig_params_none                , "id-dsa-with-sha512"                          , "2.16.840.1.101.3.4.3.4"    , P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04 }));
DECL_SIG_ALG(gost_R3411_94_R3410_2001, SIG_ALG_GOSTR3410_2001    , HASH_ALG_GOSTR3411_94, parse_sig_gost2001    , parse_algoid_sig_params_none                , "sig_gostR3411-94-with-gostR3410-2001"        , "1.2.643.2.2.3"             , P99_PROTECT({ 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x03 }));
DECL_SIG_ALG(gost_R3411_94_R3410_94  , SIG_ALG_GOSTR3410_94      , HASH_ALG_GOSTR3411_94, parse_sig_gost94      , parse_algoid_sig_params_none                , "sig_gostR3411-94-with-gostR3410-94"          , "1.2.643.2.2.4"             , P99_PROTECT({ 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x04 }));
DECL_SIG_ALG(gost_R3410_2012_256     , SIG_ALG_GOSTR3410_2012_256, HASH_ALG_STREEBOG256 , parse_sig_gost2012_256, parse_algoid_sig_params_none                , "sig_gost3410-2012-256"                       , "1.2.643.7.1.1.3.2"         , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02 }));
DECL_SIG_ALG(gost_R3410_2012_512     , SIG_ALG_GOSTR3410_2012_512, HASH_ALG_STREEBOG512 , parse_sig_gost2012_512, parse_algoid_sig_params_none                , "sig_gost3410-2012-512"                       , "1.2.643.7.1.1.3.3"         , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x03 }));
DECL_SIG_ALG(bign_with_hbelt         , SIG_ALG_BIGN              , HASH_ALG_HBELT       , parse_sig_bign        , parse_algoid_sig_params_none                , "bign (STB 34.101.45-2013) using hbelt hash"  , "1.2.112.0.2.0.34.101.45.12", P99_PROTECT({ 0x06, 0x09, 0x2a, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x2d, 0x0c }));
DECL_SIG_ALG(bign_with_hspec         , SIG_ALG_BIGN              , HASH_ALG_UNKNOWN     , parse_sig_bign        , parse_algoid_sig_params_bign_with_hspec     , "bign (STB 34.101.45-2013) w/ given hash func", "1.2.112.0.2.0.34.101.45.11", P99_PROTECT({ 0x06, 0x09, 0x2a, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x2d, 0x0b }));
DECL_SIG_ALG(monkeysphere            , SIG_ALG_MONKEYSPHERE      , HASH_ALG_UNKNOWN     , parse_sig_monkey      , parse_algoid_sig_params_none                , "unknown OID from The Monkeysphere Project"   , "1.3.6.1.4.1.37210.1.1"     , P99_PROTECT({ 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x5a, 0x01, 0x01 }));

static const _sig_alg *known_sig_algs[] = {
	&_ecdsa_sha1_sig_alg,
	&_ecdsa_sha224_sig_alg,
	&_ecdsa_sha256_sig_alg,
	&_ecdsa_sha384_sig_alg,
	&_ecdsa_sha512_sig_alg,
	&_ecdsa_with_sha3_256_sig_alg,
	&_ecdsa_with_shake128_sig_alg,
	&_ecdsa_with_shake256_sig_alg,

	&_rsassa_pss_sig_alg,
	&_rsassa_pss_shake128_sig_alg,
	&_rsassa_pss_shake256_sig_alg,

	&_rsa_mdc2_sig_alg,
	&_rsa_md2_sig_alg,
	&_rsa_md4_sig_alg,
	&_rsa_md5_sig_alg,
	&_rsa_sha224_sig_alg,
	&_rsa_sha256_sig_alg,
	&_rsa_sha384_sig_alg,
	&_rsa_sha512_sig_alg,
	&_sha1WithRSAEnc_sig_alg,
	&_sha1WithRSAEnc_bis_sig_alg,
	&_sha1WithRSAEnc_alt_sig_alg,
	&_sha1WithRSAEnc_alt2_sig_alg,
	&_sha1WithRSAEnc_ter_sig_alg,
	&_shaWithRSASig_9796_2_sig_alg,
	&_rsa_ripemd160_sig_alg,
	&_rsa_ripemd128_sig_alg,
	&_rsa_ripemd256_sig_alg,
	&_pkcs1_v15_w_sha3_224_sig_alg,
	&_pkcs1_v15_w_sha3_256_sig_alg,
	&_pkcs1_v15_w_sha3_384_sig_alg,
	&_pkcs1_v15_w_sha3_512_sig_alg,

	&_dsa_sha1_sig_alg,
	&_dsa_sha1_old_sig_alg,
	&_dsa_sha1_jdk_sig_alg,
	&_dsa_with_sha224_sig_alg,
	&_dsa_with_sha256_sig_alg,
	&_dsa_with_sha384_sig_alg,
	&_dsa_with_sha512_sig_alg,

	&_ed25519_sig_alg,
	&_ed448_sig_alg,

	&_sm2_sm3_sig_alg,

	&_gost_R3410_2012_256_sig_alg,
	&_gost_R3410_2012_512_sig_alg,
	&_gost_R3411_94_R3410_2001_sig_alg,
	&_gost_R3411_94_R3410_94_sig_alg,

	&_bign_with_hbelt_sig_alg,
	&_bign_with_hspec_sig_alg,

	&_monkeysphere_sig_alg,
	&_belgian_rsa_sig_alg,
	&_rsalabs1_sig_alg,
	&_rsalabs2_sig_alg,

	&_dsa_sha1_bis_sig_alg,
	&_ecdsa_with_specified_sig_alg,
	&_rsa_sha1_crap_sig_alg,
	&_rsa_sha1_crap_bis_sig_alg,
};

#define NUM_KNOWN_SIG_ALGS (sizeof(known_sig_algs) / sizeof(known_sig_algs[0]))






/********************************************************************
 * Subject public key algs
 ********************************************************************/

typedef struct {
	const u8 *alg_name;
	const u8 *alg_printable_oid;
	const u8 *alg_der_oid;
	const u8 alg_der_oid_len;

	spki_alg_id pubkey_id;

	int (*parse_algoid_pubkey_params)(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx, const u8 *cert, u16 off, u16 len);
	int (*parse_pubkey)(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx, const u8 *cert, u16 off, u16 len);
} _pubkey_alg;

#define DECL_PUBKEY_ALG(TTalg, XXtype, YYparse_pubkey, ZZparse_algoid, UUname, VVoid, WWoidbuf) \
static const u8 _##TTalg##_pubkey_name[] = UUname;            \
static const u8 _##TTalg##_pubkey_printable_oid[] = VVoid;    \
static const u8 _##TTalg##_pubkey_der_oid[] = WWoidbuf;       \
							      \
static const _pubkey_alg _##TTalg##_pubkey_alg = {            \
	.alg_name = _##TTalg##_pubkey_name,                   \
	.alg_printable_oid = _##TTalg##_pubkey_printable_oid, \
	.alg_der_oid = _##TTalg##_pubkey_der_oid,             \
	.alg_der_oid_len = sizeof(_##TTalg##_pubkey_der_oid), \
	.pubkey_id = (XXtype),				      \
	.parse_pubkey = (YYparse_pubkey),		      \
	.parse_algoid_pubkey_params = (ZZparse_algoid),	      \
}

/*
 *------------------------------------------+----------------------------+--------------------------------+-----------------------------------------------+----------------------------------+------------------------------+----------------------------------...
 *              struct name                 | pubkey alg                 | pubkey parsing func            | pubkey alg oid params parsing func            | pretty name for pubkey alg       | printable OID                | OID in DER format
 *------------------------------------------+----------------------------+--------------------------------+-----------------------------------------------+----------------------------------+------------------------------+----------------------------------...
 */
DECL_PUBKEY_ALG(pkcs1_rsaEncryption         , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_rsa                , "PKCS-1 rsaEncryption"           , "1.2.840.113549.1.1.1"       , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }));
DECL_PUBKEY_ALG(weird_rsa_pub_1             , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_rsa                , "Undocumented RSA pub key oid"   , "1.2.840.887.13.1.1.1"       , P99_PROTECT({ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0x77, 0x0d, 0x01, 0x01, 0x01 }));
DECL_PUBKEY_ALG(weird_rsa_pub_2             , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_rsa                , "another rsa pubkey oid"         , "1.18.840.113549.1.1.1"      , P99_PROTECT({ 0x06, 0x09, 0x3a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 })); /*CRAP*/
DECL_PUBKEY_ALG(rsa_gip_cps                 , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_rsa                , "GIP-CPS"                        , "1.2.250.1.71.2.6.1"         , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x81, 0x7a, 0x01, 0x47, 0x02, 0x06, 0x01 }));
DECL_PUBKEY_ALG(rsassa_pss_shake256         , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_none               , "RSASSA-PSS-SHAKE256"            , "1.3.6.1.5.5.7.6.31"         , P99_PROTECT({ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f }));
DECL_PUBKEY_ALG(rsassa_pss_shake128         , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_none               , "RSASSA-PSS-SHAKE128"            , "1.3.6.1.5.5.7.6.30"         , P99_PROTECT({ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e }));
DECL_PUBKEY_ALG(ea_rsa                      , SPKI_ALG_RSA               , parse_pubkey_rsa               , parse_algoid_pubkey_params_ea_rsa             , "id-ea-rsa"                      , "2.5.8.1.1"                  , P99_PROTECT({ 0x06, 0x04, 0x55, 0x08, 0x01, 0x01 }));
DECL_PUBKEY_ALG(ecpublickey                 , SPKI_ALG_ECPUBKEY          , parse_pubkey_ec                , parse_algoid_pubkey_params_ecPublicKey        , "ecPublicKey"                    , "1.2.840.10045.2.1"          , P99_PROTECT({ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,  0x02, 0x01 }));
DECL_PUBKEY_ALG(dsa_pubkey                  , SPKI_ALG_DSA               , parse_pubkey_dsa               , parse_algoid_pubkey_params_dsa                , "DSA subject public key"         , "1.2.840.10040.4.1"          , P99_PROTECT({ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 }));
DECL_PUBKEY_ALG(x448                        , SPKI_ALG_X448              , parse_pubkey_x448              , parse_algoid_pubkey_params_x448               , "X448"                           , "1.3.101.111"                , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x6f }));
DECL_PUBKEY_ALG(ed448                       , SPKI_ALG_ED448             , parse_pubkey_ed448             , parse_algoid_pubkey_params_ed448              , "Ed448"                          , "1.3.101.113"                , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x71 }));
DECL_PUBKEY_ALG(x25519                      , SPKI_ALG_X25519            , parse_pubkey_x25519            , parse_algoid_pubkey_params_x25519             , "X25519"                         , "1.3.101.110"                , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x6e }));
DECL_PUBKEY_ALG(ed25519                     , SPKI_ALG_ED25519           , parse_pubkey_ed25519           , parse_algoid_pubkey_params_ed25519            , "Ed25519"                        , "1.3.101.112"                , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x70 }));
DECL_PUBKEY_ALG(bign                        , SPKI_ALG_BIGN_PUBKEY       , parse_pubkey_bign              , parse_algoid_pubkey_params_bign               , "bign-pubkey"                    , "1.2.112.0.2.0.34.101.45.2.1", P99_PROTECT({ 0x06, 0x0a, 0x2a, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x2d, 0x02, 0x01 }));
DECL_PUBKEY_ALG(gost_R3410_94               , SPKI_ALG_GOSTR3410_94      , parse_pubkey_gostr3410_94      , parse_algoid_pubkey_params_gost_r3410_94      , "gostR3410-94 public key"        , "1.2.643.2.2.20"             , P99_PROTECT({ 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x14 }));
DECL_PUBKEY_ALG(gost_R3410_2001             , SPKI_ALG_GOSTR3410_2001    , parse_pubkey_gostr3410_2001    , parse_algoid_pubkey_params_gost_r3410_2001    , "gostR3410-2001 public key"      , "1.2.643.2.2.19"             , P99_PROTECT({ 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13 }));
DECL_PUBKEY_ALG(gost_R3410_2012_512         , SPKI_ALG_GOSTR3410_2012_512, parse_pubkey_gostr3410_2012_512, parse_algoid_pubkey_params_gost_r3410_2012_512, "gost3410-2012-512 public key"   , "1.2.643.7.1.1.1.2"          , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x02 }));
DECL_PUBKEY_ALG(gost_R3410_2012_256         , SPKI_ALG_GOSTR3410_2012_256, parse_pubkey_gostr3410_2012_256, parse_algoid_pubkey_params_gost_r3410_2012_256, "gost3410-2012-256 public key"   , "1.2.643.7.1.1.1.1"          , P99_PROTECT({ 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01 }));

static const _pubkey_alg *known_pubkey_algs[] = {
	&_ecpublickey_pubkey_alg,

	&_pkcs1_rsaEncryption_pubkey_alg,
	&_rsa_gip_cps_pubkey_alg,
	&_rsassa_pss_shake256_pubkey_alg,
	&_rsassa_pss_shake128_pubkey_alg,

	&_ed448_pubkey_alg,
	&_ed25519_pubkey_alg,

	&_x448_pubkey_alg,
	&_x25519_pubkey_alg,

	&_gost_R3410_94_pubkey_alg,
	&_gost_R3410_2001_pubkey_alg,
	&_gost_R3410_2012_512_pubkey_alg,
	&_gost_R3410_2012_256_pubkey_alg,

	&_bign_pubkey_alg,

	&_weird_rsa_pub_1_pubkey_alg,
	&_weird_rsa_pub_1_pubkey_alg,
	&_dsa_pubkey_pubkey_alg,
	&_ea_rsa_pubkey_alg,
};

#define NUM_KNOWN_PUBKEY_ALGS (sizeof(known_pubkey_algs) / sizeof(known_pubkey_algs[0]))





/********************************************************************
 * Gost 94 pubkey parameters
 ********************************************************************/

typedef struct {
	const u8 *params_name;
	const u8 *params_printable_oid;
	const u8 *params_der_oid;
	const u8 params_der_oid_len;

	_gost94_pub_params_id params_id;
} _gost94_pub_params;

#define DECL_GOST94_PARAMS(EEparams, AAid, BBname, CCoid, DDoidbuf)	    \
static const u8 _##EEparams##_gost_94_params_name[] = BBname;               \
static const u8 _##EEparams##_gost_94_params_printable_oid[] = CCoid;       \
static const u8 _##EEparams##_gost_94_params_der_oid[] = DDoidbuf;          \
									    \
static const _gost94_pub_params _##EEparams##_ParamSet = {                  \
	.params_name = _##EEparams##_gost_94_params_name,                   \
	.params_printable_oid = _##EEparams##_gost_94_params_printable_oid, \
	.params_der_oid = _##EEparams##_gost_94_params_der_oid,             \
	.params_der_oid_len = sizeof(_##EEparams##_gost_94_params_der_oid), \
	.params_id = (AAid),						    \
}

DECL_GOST94_PARAMS(GostR3410_94_Test,           GOST94_PARAMS_TEST	    , "GostR3410_94_TestParamSet",            "1.2.643.2.2.32.0", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x20, 0x00 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_A,    GOST94_PARAMS_CRYPTOPRO_A   , "GostR3410_94_CryptoPro_A_ParamSet",    "1.2.643.2.2.32.2", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x20, 0x02 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_B,    GOST94_PARAMS_CRYPTOPRO_B   , "GostR3410_94_CryptoPro_B_ParamSet",    "1.2.643.2.2.32.3", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x20, 0x03 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_C,    GOST94_PARAMS_CRYPTOPRO_C   , "GostR3410_94_CryptoPro_C_ParamSet",    "1.2.643.2.2.32.4", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x20, 0x04 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_D,    GOST94_PARAMS_CRYPTOPRO_D   , "GostR3410_94_CryptoPro_D_ParamSet",    "1.2.643.2.2.32.5", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x20, 0x05 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_XchA, GOST94_PARAMS_CRYPTOPRO_XCHA, "GostR3410_94_CryptoPro_XchA_ParamSet", "1.2.643.2.2.33.1", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x21, 0x01 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_XchB, GOST94_PARAMS_CRYPTOPRO_XCHB, "GostR3410_94_CryptoPro_XchB_ParamSet", "1.2.643.2.2.33.2", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x21, 0x02 }));
DECL_GOST94_PARAMS(GostR3410_94_CryptoPro_XchC, GOST94_PARAMS_CRYPTOPRO_XCHC, "GostR3410_94_CryptoPro_XchC_ParamSet", "1.2.643.2.2.33.3", P99_PROTECT({ 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x21, 0x03 }));

static const _gost94_pub_params *known_gost_94_params[] = {
	&_GostR3410_94_Test_ParamSet,
	&_GostR3410_94_CryptoPro_A_ParamSet,
	&_GostR3410_94_CryptoPro_B_ParamSet,
	&_GostR3410_94_CryptoPro_C_ParamSet,
	&_GostR3410_94_CryptoPro_D_ParamSet,
	&_GostR3410_94_CryptoPro_XchA_ParamSet,
	&_GostR3410_94_CryptoPro_XchB_ParamSet,
	&_GostR3410_94_CryptoPro_XchC_ParamSet,
};

#define NUM_KNOWN_GOST94_PARAMS (sizeof(known_gost_94_params) / sizeof(known_gost_94_params[0]))


#endif /* __X509_PARSER_INTERNAL_DECL_H__ */

