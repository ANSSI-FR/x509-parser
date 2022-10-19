/*
 *  Copyright (C) 2022 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_CRL_PARSER_H__
#define __X509_CRL_PARSER_H__

#include "x509-config.h"
#include "x509-utils.h"
#include "x509-common.h"

typedef struct {
	/* tbcCertificate */
	u32 tbs_start;
	u32 tbs_len;

	/* Version */
	u8 version;

	/* inner sig alg (tbsCrl.signature) */
	u32 tbs_sig_alg_start;
	u32 tbs_sig_alg_len;
	u32 tbs_sig_alg_oid_start; /* OID for sig alg */
	u32 tbs_sig_alg_oid_len;
	u32 tbs_sig_alg_oid_params_start; /* params for sig alg */
	u32 tbs_sig_alg_oid_params_len;

	/* Issuer */
	u32 issuer_start;
	u32 issuer_len;

	/* {this,next}Update */
	u64 this_update;
	u64 next_update;

	/* Extensions */

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

	    /* Freshest CRL (Delta CRL Distribution Point) */
	    int has_crldp;
	    int one_crldp_has_all_reasons;

	    /* Freshest CRL (Delta CRL Distribution Point) */
	    int has_crlnumber;
	    u32 crlnumber_start;
	    u32 crlnumber_len;

	    /* Flags which tells if CRL has revoked certs */
	    int has_revoked_certs;

	/* signature alg */
	u32 sig_alg_start; /* outer sig alg */
	u32 sig_alg_len;
	sig_alg_id sig_alg; /* ID of signature alg */
	hash_alg_id hash_alg;
	sig_params sig_alg_params; /* depends on sig_alg */

	/* raw signature value */
	u32 sig_start;
	u32 sig_len;
} crl_parsing_ctx;


/*
 * Return 0 if parsing went OK, a non zero value otherwise.
 * 'len' must exactly match the size of the CRL in the buffer 'buf'
 * (i.e. nothing is expected behind).
 */
int parse_x509_crl(crl_parsing_ctx *ctx, const u8 *buf, u32 len);

#endif /* __X509_CRL_PARSER_H__ */
