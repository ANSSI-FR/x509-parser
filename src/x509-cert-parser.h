/*
 *  Copyright (C) 2019 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_CERT_PARSER_H__
#define __X509_CERT_PARSER_H__

#include "x509-config.h"
#include "x509-utils.h"
#include "x509-common.h"

typedef struct {
	/* tbcCertificate */
	u32 tbs_start;
	u32 tbs_len;

	/* Version */
	u8 version;

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

#endif /* __X509_CERT_PARSER_H__ */
