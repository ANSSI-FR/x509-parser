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

/* Allow weak/bad algs w/o to parse more certificate fields from our set. */
#define TEMPORARY_BADALGS

/*
 * Same for otherwise unsupported extensions but for which we have an
 * internal reference to the OID
 */
#define TEMPORARY_BAD_EXT_OIDS

/* Allow certificates w/ full directoryString . */
#define TEMPORARY_LAXIST_DIRECTORY_STRING

/*
 * The following can be defined to enable an error trace to be
 * printed on standard output. The error path is made of the
 * lines in the representing the call graph leading to the
 * error.
 */
// #define ERROR_TRACE_ENABLE

/*
 * Max allowed buffer size for ASN.1 structures. Also note that
 * the type used for length in the whole code is an u16, so it
 * is pointless to set something higher than 65535.
 */
#define ASN1_MAX_BUFFER_SIZE 65534

typedef struct {
	/* Positions/length of various elements in cert */
	u16 tbs_start;
	u16 tbs_len;
	u16 issuer_start;
	u16 issuer_len;
	u16 serial_start;
	u16 serial_len;
	u16 subject_start;
	u16 subject_len;
	u16 spki_start;
	u16 spki_len;
	u16 spki_alg_oid_start;
	u16 spki_alg_oid_len;
	u16 spki_pub_key_start;
	u16 spki_pub_key_len;
	u16 sig_alg_start;
	u16 sig_alg_len;
	u16 sig_start;
	u16 sig_len;

	/* Info we grabbed while parsing */
	int version;
	int empty_subject;
	int san_empty;
	int san_critical;
	int ca_true;
	int bc_critical;
	int has_ski;
	int has_keyUsage;
	int keyCertSign_set;
	int cRLSign_set;
	int pathLenConstraint_set;
	int has_name_constraints;
	int has_crldp;
	int one_crldp_has_all_reasons;
	int aki_has_keyIdentifier;
	int subject_issuer_identical;
} cert_parsing_ctx;

/*
 * Return 0 if parsing went OK, a non zero value otherwise.
 * 'len' must exactly match the size of the certificate
 * in the buffer 'buf' (i.e. nothing is expected behind).
 */
int parse_x509_cert(cert_parsing_ctx *ctx, const u8 *buf, u16 len);

/*
 * This wrapper around parse_x509_cert() does not expect the buffer
 * to exactly contain a DER-encoded certificate, but to start with
 * one. It returns the length of the first sequence found in the
 * buffer, no matter if the certificate (this sequence) is valid
 * or not. It only requires the buffer to start with a sequence.
 * A value of 1 is returned in 'remain' if the buffer does not
 * start with a sequence.
 */
int parse_x509_cert_relaxed(const u8 *buf, u16 len, u16 *eaten);


int parse_sig_ecdsa_export_r_s(const u8 *buf, u16 len,
			       u16 *r_start_off, u16 *r_len,
			       u16 *s_start_off, u16 *s_len,
			       u16 *eaten);

int parse_sig_eddsa_export_r_s(const u8 *buf, u16 len,
			       u16 *r_start_off, u16 *r_len,
			       u16 *s_start_off, u16 *s_len,
			       u16 *eaten);

#endif /* __X509_PARSER_H__ */
