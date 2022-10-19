/*
 *  Copyright (C) 2022 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include "x509-crl-parser.h"

#define X509_FILE_NUM 5 /* See x509-utils.h for rationale */

/*
 * Reminder on CRL format:
 *
 *    CertificateList  ::=  SEQUENCE  {
 *        tbsCertList          TBSCertList,
 *        signatureAlgorithm   AlgorithmIdentifier,
 *        signatureValue       BIT STRING  }
 *
 *   TBSCertList  ::=  SEQUENCE  {
 *        version                 Version OPTIONAL,
 *                                     -- if present, MUST be v2
 *        signature               AlgorithmIdentifier,
 *        issuer                  Name,
 *        thisUpdate              Time,
 *        nextUpdate              Time OPTIONAL,
 *        revokedCertificates     SEQUENCE OF SEQUENCE  {
 *             userCertificate         CertificateSerialNumber,
 *             revocationDate          Time,
 *             crlEntryExtensions      Extensions OPTIONAL
 *                                      -- if present, version MUST be v2
 *                                  }  OPTIONAL,
 *        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                      -- if present, version MUST be v2
 *                                  }
 *
 * Structure of the module, by order of appearance :
 *
 *  - Code for parsing CRL Entry Extensions
 *  - Code for parsing revokedCertificates
 *  - Code for parsing CRL Extensions
 *  - Code for parsing tbsCertList
 *  - Code for parsing signatureAlgorithm
 *  - Code for parsing signatureValue
 *  - parse_x509_crl()
 */


/*****************************************************************************
 * Code for parsing CRL Entry extensions
 *****************************************************************************/

typedef enum {
	crl_reason_unspecified          = 0x00,
	crl_reason_keyCompromise        = 0x01,
	crl_reason_cACompromise         = 0x02,
	crl_reason_affiliationChanged   = 0x03,
	crl_reason_superseded           = 0x04,
	crl_reason_cessationOfOperation = 0x05,
	crl_reason_certificateHold      = 0x06,
	/* value 7 is not used */
	crl_reason_removeFromCRL        = 0x08,
	crl_reason_privilegeWithdrawn   = 0X09,
	crl_reason_aACompromise         = 0x0a
} crl_reason;

static const u8 _crl_entry_ext_oid_ReasonCode[] =      { 0x06, 0x03, 0x55, 0x1d, 0x15 };
static const u8 _crl_entry_ext_oid_InvalidityDate[] =  { 0x06, 0x03, 0x55, 0x1d, 0x18 };
static const u8 _crl_entry_ext_oid_CertIssuer[] =      { 0x06, 0x03, 0x55, 0x1d, 0x1d };

/*
 * Section 5.3.1.  Reason Code
 *
 *    -- reasonCode ::= { CRLReason }
 *
 *    CRLReason ::= ENUMERATED {
 *         unspecified             (0),
 *         keyCompromise           (1),
 *         cACompromise            (2),
 *         affiliationChanged      (3),
 *         superseded              (4),
 *         cessationOfOperation    (5),
 *         certificateHold         (6),
 *              -- value 7 is not used
 *         removeFromCRL           (8),
 *         privilegeWithdrawn      (9),
 *         aACompromise           (10) }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(crl+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_entry_ext_ReasonCode(crl_parsing_ctx *ctx,
					  const u8 *crl, u32 off, u32 len,
					  int critical)
{
	const u8 *buf = crl + off;
	crl_reason reasonCode;
	int ret = -1;

	if ((ctx == NULL) || (crl == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (critical) {
		/*
		 * Section 5.3.1 of RFC 5280 has "The reasonCode is a
		 * non-critical CRL entry extension"
		 */
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * The reasonCode enumerated should be encoded on exactly 3 bytes
	 * First one has enumerated type, followed by a length value of 1
	 * followed by the actual reason code.
	 */
	if ((len != 3) || (buf[0] != ASN1_TYPE_ENUMERATED) || (buf[1] != 0x01)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	reasonCode = buf[2];
	switch (reasonCode) {
	case crl_reason_unspecified:
	case crl_reason_keyCompromise:
	case crl_reason_cACompromise:
	case crl_reason_affiliationChanged:
	case crl_reason_superseded:
	case crl_reason_cessationOfOperation:
	case crl_reason_certificateHold:
	case crl_reason_removeFromCRL:
	case crl_reason_privilegeWithdrawn:
	case crl_reason_aACompromise:
		ret = 0;
		break;

	default:
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

out:
	return ret;
}

/*
 * Section 5.3.2 of RFC 5280:
 *
 * InvalidityDate ::=  GeneralizedTime
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(crl+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_entry_ext_InvalidityDate(crl_parsing_ctx *ctx,
					  const u8 *crl, u32 off, u32 len,
					  int critical)
{
	u8 month = 0, day = 0, hour = 0, min = 0, sec = 0;
	const u8 *buf = crl + off;
	u32 eaten;
	u16 year;
	int ret = -1;

	if ((ctx == NULL) || (crl == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (critical) {
		/*
		 * Section 5.3.1 of RFC 5280 has "The invalidity date is a
		 * non-critical CRL entry extension"
		 */
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = parse_generalizedTime(buf, len, &eaten,
				    &year, &month, &day, &hour, &min, &sec);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

out:
	return ret;
}


/*
 * Section 5.3.3 of RFC 5280:
 *
 * CertificateIssuer ::=     GeneralNames
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(crl+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_entry_ext_CertIssuer(crl_parsing_ctx *ctx,
					  const u8 *crl, u32 off, u32 len,
					  int critical)
{
	const u8 *buf = crl + off;
	u32 eaten;
	int ret;

	if ((ctx == NULL) || (crl == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (!critical) {
		/*
		 * Section 5.3.3 of RFC 5280 has "CRL issuers MUST mark this
		 * extension as critical since an implementation that ignored
		 * this extension could not correctly attribute CRL entries
		 * to certificates.  This specification RECOMMENDS that
		 * implementations recognize this extension."
		 */
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = parse_GeneralNames(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				 &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

out:
	return ret;
}

typedef struct {
	const u8 *oid;
	u8 oid_len;
	int (*parse_crl_entry_ext_params)(crl_parsing_ctx *ctx,
					  const u8 *crl, u32 off, u32 len, int critical);
} _crl_entry_ext_oid;

static const _crl_entry_ext_oid known_crl_entry_ext_oids[] = {
	{ .oid = _crl_entry_ext_oid_ReasonCode, /* Reason Code */
	  .oid_len = sizeof(_crl_entry_ext_oid_ReasonCode),
	  .parse_crl_entry_ext_params = parse_crl_entry_ext_ReasonCode,
	},
	{ .oid = _crl_entry_ext_oid_InvalidityDate, /* Invalidity Date */
	  .oid_len = sizeof(_crl_entry_ext_oid_InvalidityDate),
	  .parse_crl_entry_ext_params = parse_crl_entry_ext_InvalidityDate,
	},
	{ .oid = _crl_entry_ext_oid_CertIssuer, /* Certificate Issuer */
	  .oid_len = sizeof(_crl_entry_ext_oid_CertIssuer),
	  .parse_crl_entry_ext_params = parse_crl_entry_ext_CertIssuer,
	},
};

#define NUM_KNOWN_CRL_ENTRY_EXT_OIDS (sizeof(known_crl_entry_ext_oids) /     \
				      sizeof(known_crl_entry_ext_oids[0]))
#define MAX_EXT_NUM_PER_CRL_ENTRY NUM_KNOWN_CRL_ENTRY_EXT_OIDS

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_CRL_ENTRY_EXT_OIDS && \result == &known_crl_entry_ext_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static _crl_entry_ext_oid const * find_crl_entry_ext_by_oid(const u8 *buf, u32 len)
{
	const _crl_entry_ext_oid *found = NULL;
	const _crl_entry_ext_oid *cur = NULL;
	u16 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_CRL_ENTRY_EXT_OIDS ;
	  @ loop invariant 0 <= k <= NUM_KNOWN_CRL_ENTRY_EXT_OIDS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_CRL_ENTRY_EXT_OIDS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_CRL_ENTRY_EXT_OIDS; k++) {
		int ret;

		cur = &known_crl_entry_ext_oids[k];

		/*@ assert cur == &known_crl_entry_ext_oids[k];*/
		if (cur->oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->oid, buf, cur->oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}

/*@
  @ requires ext != \null;
  @ requires \valid(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)));
  @ requires \valid_read(ext);
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)));
  @ requires \separated(ext, parsed_oid_list);
  @
  @ ensures \result <= 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)];
  @*/
static int check_record_crl_entry_ext_unknown(const _crl_entry_ext_oid *ext,
					      const _crl_entry_ext_oid **parsed_oid_list)
{
	u16 pos = 0;
	int ret;

	/*@
	  @ loop invariant pos <= MAX_EXT_NUM_PER_CRL_ENTRY;
	  @ loop assigns ret, pos, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)];
	  @ loop variant MAX_EXT_NUM_PER_CRL_ENTRY - pos;
	  @*/
	while (pos < MAX_EXT_NUM_PER_CRL_ENTRY) {
		/*
		 * Check if we are at the end of already seen extensions. In
		 * that case, record the extension as a new one.
		 */
		if (parsed_oid_list[pos] == NULL) {
			parsed_oid_list[pos] = ext;
			break;
		}

		if (ext == parsed_oid_list[pos]) {
			ret = -X509_FILE_LINE_NUM_ERR;
			goto out;
		}

		pos += 1;
	}

	/*
	 * If we went to the end of our array, this means there are too many
	 * extensions in the certificate.
	 */
	if (pos >= MAX_EXT_NUM_PER_CRL_ENTRY) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (parsed_oid_list != NULL) ==> \valid(parsed_oid_list);
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)));
  @ requires \separated(ctx, crl+(..), parsed_oid_list, eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)], *eaten, *ctx;
  @*/
static int parse_x509_crl_entry_Extension(crl_parsing_ctx *ctx,
					  const u8 *crl, u32 off, u32 len,
					  const _crl_entry_ext_oid **parsed_oid_list,
					  u32 *eaten)
{
	u32 ext_hdr_len = 0, ext_data_len = 0;
	u32 hdr_len = 0, data_len = 0;
	u32 saved_ext_len = 0, oid_len = 0;
	u32 remain, parsed = 0;
	const u8 *buf = crl + off;
	const _crl_entry_ext_oid *ext = NULL;
	int critical = 0;
	int ret;

	(void)parsed_oid_list;

	if ((crl == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1))); */

	remain = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, remain,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &ext_hdr_len, &ext_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += ext_hdr_len;
	off += ext_hdr_len;
	remain -= ext_hdr_len;
	saved_ext_len = ext_hdr_len + ext_data_len;

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1))); */

	/*
	 * Let's parse the OID and then check if we have
	 * an associated handler for that extension.
	 */
	ret = parse_OID(buf, ext_data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1))); */

	ext = find_crl_entry_ext_by_oid(buf, oid_len);
	if (ext == NULL) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1))); */

	/*
	 * Now that we know the OID is one we support, we verify
	 * this is the first time we handle an instance of this
	 * type. Having multiple instances of a given extension
	 * in a certificate is forbidden by both section 4.2 of
	 * RFC5280 and section 8 of X.509, w/ respectively
	 *
	 * - "A certificate MUST NOT include more than one
	 *    instance of a particular extension."
	 * - "For all certificate extensions, CRL extensions,
	 *    and CRL entry extensions defined in this Directory
	 *    Specification, there shall be no more than one
	 *    instance of each extension type in any certificate,
	 *    CRL, or CRL entry, respectively."
	 *
	 * This is done by recording for each extension we
	 * processed the pointer to its vtable and compare
	 * it with current one.
	 */
	ret = check_record_crl_entry_ext_unknown(ext, parsed_oid_list);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += oid_len;
	off += oid_len;
	ext_data_len -= oid_len;

	/*
	 * Now that we got the OID, let's check critical
	 * field value if present. It's a boolean
	 * defaulting to FALSE (in which case, it is absent).
	 * We could parse it as an integer but that
	 * would be a lot of work for three simple bytes.
	 */
	ret = parse_boolean(buf, ext_data_len, &parsed);
	if (ret) {
		/*
		 * parse_boolean() returned an error which means this
		 * was either a boolean with invalid content or
		 * something else. If this was indeed a boolean, we can
		 * just leave. Otherwise, this just measn the critical
		 * flag was missing and the default value (false) applies,
		 * in which case, we can continue parsing.
		 */
		if (ext_data_len && (buf[0] == ASN1_TYPE_BOOLEAN)) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}
	} else {
		/*
		 * We now know it's a valid BOOLEAN, *but* in our
		 * case (DER), the DEFAULT FALSE means we cannot
		 * accept an encoded value of FALSE. Note that we
		 * sanity check the value we expect for the length
		 */
		if (parsed != 3) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

#ifndef TEMPORARY_LAXIST_EXTENSION_CRITICAL_FLAG_BOOLEAN_EXPLICIT_FALSE
		if (buf[2] == 0x00) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}
#endif

		/*
		 * We now know the BOOLEAN is present and has
		 * a value of TRUE. Record that.
		 */
		critical = 1;

		buf += parsed;
		off += parsed;
		ext_data_len -= parsed;
	}

	/*
	 * We should now be in front of the octet string
	 * containing the extnValue.
	 */
	ret = parse_id_len(buf, ext_data_len,
			   CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	ext_data_len -= hdr_len;

	/* Check nothing remains behind the extnValue */
	if (data_len != ext_data_len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Parse the parameters for that extension */
	/*@ assert ext->parse_crl_entry_ext_params \in {
	  parse_crl_entry_ext_ReasonCode,
	  parse_crl_entry_ext_InvalidityDate,
	  parse_crl_entry_ext_CertIssuer }; @*/
	/*@ calls parse_crl_entry_ext_ReasonCode,
	  parse_crl_entry_ext_InvalidityDate,
	  parse_crl_entry_ext_CertIssuer ; @*/
	ret = ext->parse_crl_entry_ext_params(ctx, crl, off, ext_data_len, critical);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	*eaten = saved_ext_len;
	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(eaten, ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_crl_entry_Extensions(crl_parsing_ctx *ctx,
					   const u8 *crl, u32 off, u32 len,
					   u32 *eaten)
{
	u32 data_len = 0, hdr_len = 0, remain = 0;
	const u8 *buf = crl + off;
	u32 saved_len = 0;
	const _crl_entry_ext_oid *parsed_crl_entry_ext_oid_list[MAX_EXT_NUM_PER_CRL_ENTRY];

	int ret;
	u16 i;

	if ((crl == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Extensions in X.509 CRL is an EXPLICITLY tagged sequence.
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	remain = data_len;
	buf += hdr_len;
	off += hdr_len;
	/*@ assert \valid_read(buf + (0 .. (remain - 1))); */

	saved_len = hdr_len + data_len;
	/*@ assert saved_len <= len; */
	/*@ assert data_len <= saved_len; */

#ifndef TEMPORARY_LAXIST_ALLOW_CRL_ENTRY_EXT_WITH_EMPTY_SEQ
	/* If present, it must contain at least one extension */
	if (data_len == 0) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
#endif

	/* Initialize list of already seen extensions */
	/*@
	  @ loop unroll MAX_EXT_NUM_PER_CRL_ENTRY;
	  @ loop assigns i, parsed_crl_entry_ext_oid_list[0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)];
	  @ loop invariant (i < MAX_EXT_NUM_PER_CRL_ENTRY) ==> \valid(&parsed_crl_entry_ext_oid_list[i]);
	  @ loop variant (MAX_EXT_NUM_PER_CRL_ENTRY - i);
	  @*/
	for (i = 0; i < MAX_EXT_NUM_PER_CRL_ENTRY; i++) {
		parsed_crl_entry_ext_oid_list[i] = NULL;
	}
	/*@ assert \initialized(parsed_crl_entry_ext_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1))); */

	/* Now, let's work on each extension in the sequence */
	/*@
	  @ loop assigns off, ret, buf, remain, parsed_crl_entry_ext_oid_list[0 .. (MAX_EXT_NUM_PER_CRL_ENTRY - 1)], *ctx;
	  @ loop invariant (remain != 0) ==> \valid_read(crl + (off .. (off + remain - 1)));
	  @ loop invariant (remain != 0) ==> ((u64)off + (u64)remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @*/
	while (remain) {
		u32 ext_len = 0;

		ret = parse_x509_crl_entry_Extension(ctx, crl, off, remain,
						     parsed_crl_entry_ext_oid_list,
						     &ext_len);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		remain -= ext_len;
		buf += ext_len;
		off += ext_len;
	}

	/*@ assert 1 <= saved_len <= len; */
	*eaten = saved_len;

	ret = 0;

out:
	return ret;
}



/*****************************************************************************
 * Code for parsing revokedCertificates
 *****************************************************************************/

/*
 * We call revokedCertificate the component found in revokedCertificates
 * sequence. revokedCertificate is itself a sequence:
 *
 *         revokedCertificates     SEQUENCE OF SEQUENCE  {
 *            userCertificate         CertificateSerialNumber,
 *            revocationDate          Time,
 *            crlEntryExtensions      Extensions OPTIONAL
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(eaten, crl+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_crl_revokedCertificate(crl_parsing_ctx *ctx,
					     const u8 *crl, u32 off, u32 len,
					     u32 *eaten)
{
	const u8 *buf = crl + off;
	u32 rev_len = 0;
	u16 rev_year = 0;
	u8 rev_month = 0, rev_day = 0, rev_hour = 0, rev_min = 0, rev_sec = 0;
	u8 t_type = 0;
	u32 hdr_len = 0, data_len = 0;
	u32 parsed = 0;
	u32 remain = len;
	u32 saved_rev_len = 0;
	int ret;

	if ((ctx == NULL) || (crl == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	remain = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, remain,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;
	off += hdr_len;
	saved_rev_len = hdr_len + data_len;

	/* userCertificate, i.e. revoked certificate serial number */
	ret = parse_SerialNumber(crl, off, remain, CLASS_UNIVERSAL,
				 ASN1_TYPE_INTEGER, &parsed);
	if (ret) {
	       ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
	       goto out;
	}

	buf += parsed;
	remain -= parsed;
	off += parsed;

	/* revocationDate */
	ret = parse_Time(buf, remain, &t_type, &rev_len, &rev_year, &rev_month,
			 &rev_day, &rev_hour, &rev_min, &rev_sec);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Check valid time type was used for year value */
	ret = verify_correct_time_use(t_type, rev_year);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += rev_len;
	remain -= rev_len;
	off += rev_len;

	/* crlEntryExtensions is only acceptable for v2 crl */
	if ((ctx->version != 0x01) && remain) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (remain) {
		ret = parse_x509_crl_entry_Extensions(ctx, crl, off, remain,
						      &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		remain -= parsed;
		off += parsed;
		buf += parsed;
	}

	*eaten = saved_rev_len;
	ret = 0;

out:
	return ret;
}


/*****************************************************************************
 * Code for parsing CRL Extensions
 *****************************************************************************/


/*
 * Authority Key Identifier extension for CRL. Defined in secion 5.2.1 of
 * RFC 5280. Like certificate's AKI extension, the CRL extension structure
 * is defined in section 4.2.1.1 of RFC 5280:
 *
 *   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 *      -- authorityCertIssuer and authorityCertSerialNumber MUST both
 *      -- be present or both be absent
 *
 *   KeyIdentifier ::= OCTET STRING
 *
 * The function below has code duplication with parse_ext_AKI but they
 * do not feed the same parsing context (CRL vs cert parsing context).
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->aki_has_keyIdentifier,
	    ctx->aki_keyIdentifier_start,
	    ctx->aki_keyIdentifier_len,
	    ctx->aki_has_generalNames_and_serial,
	    ctx->aki_generalNames_start,
	    ctx->aki_generalNames_len,
	    ctx->aki_serial_start,
	    ctx->aki_serial_len,
	    ctx->has_aki;
  @*/
static int parse_crl_ext_AKI(crl_parsing_ctx *ctx,
			     const u8 *crl, u32 off, u32 len,
			     int critical)
{
	u32 hdr_len = 0, data_len = 0;
	const u8 *buf = crl + off;
	u32 key_id_hdr_len = 0, key_id_data_len = 0, key_id_data_off = 0;
	u32 gen_names_off = 0, gen_names_len = 0;
	u32 cert_serial_off = 0, cert_serial_len = 0;
	u32 remain;
	u32 parsed = 0;
	int ret, has_keyIdentifier = 0, has_gen_names_and_serial = 0;

	if ((crl == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Section 4.2.1.1. of RFC 5280 has "Conforming CAs MUST mark this
	 * extension as non-critical"
	 */
	if (critical) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Check we are indeed dealing w/ a sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * First, the KeyIdentifier if present (KeyIdentifier ::= OCTET STRING)
	 */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &key_id_hdr_len, &key_id_data_len);
	if (!ret) {
		/* An empty KeyIdentifier does not make any sense. Drop it! */
		if (!key_id_data_len) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		key_id_data_off = off + key_id_hdr_len;
		buf += key_id_hdr_len + key_id_data_len;
		off += key_id_hdr_len + key_id_data_len;
		remain -= key_id_hdr_len + key_id_data_len;
		has_keyIdentifier = 1;
	}


	/*
	 * See if a (GeneralNames, CertificateSerialNumber) couple follows.
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName. We do
	 * not accept one w/o the other.
	 */
	ret = parse_GeneralNames(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
				 &parsed);
	if (!ret) {
		gen_names_off = off;
		gen_names_len = parsed;

		buf += parsed;
		off += parsed;
		remain -= parsed;
		/* CertificateSerialNumber ::= INTEGER */
		ret = parse_AKICertSerialNumber(crl, off, remain,
						CLASS_CONTEXT_SPECIFIC, 2,
						&cert_serial_len);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}
		/*@ assert cert_serial_len > 2; */

		has_gen_names_and_serial = 1;
		cert_serial_off = off;

		buf += cert_serial_len;
		off += cert_serial_len;
		remain -= cert_serial_len;
	}

	/* Nothing should remain behind */
	if (remain) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Only populate context when we know everything is ok. */
	ctx->aki_has_keyIdentifier = has_keyIdentifier;
	/*@ assert \initialized(&ctx->aki_has_keyIdentifier); */
	if (ctx->aki_has_keyIdentifier) {
		ctx->aki_keyIdentifier_start = key_id_data_off;
		/*@ assert \initialized(&ctx->aki_keyIdentifier_start); */
		ctx->aki_keyIdentifier_len = key_id_data_len;
		/*@ assert \initialized(&ctx->aki_keyIdentifier_len); */
	}
	ctx->aki_has_generalNames_and_serial = has_gen_names_and_serial;
	/*@ assert \initialized(&ctx->aki_has_generalNames_and_serial); */
	if (ctx->aki_has_generalNames_and_serial) {
		ctx->aki_generalNames_start = gen_names_off;
		/*@ assert \initialized(&ctx->aki_generalNames_start); */
		ctx->aki_generalNames_len = gen_names_len;
		/*@ assert \initialized(&ctx->aki_generalNames_len); */
		ctx->aki_serial_start = cert_serial_off + 2;  /* 2 bytes long hdr for a valid SN */
		/*@ assert \initialized(&ctx->aki_serial_start); */
		ctx->aki_serial_len = cert_serial_len - 2;
		/*@ assert \initialized(&ctx->aki_serial_len); */
	}
	ctx->has_aki = 1;
	/*@ assert \initialized(&ctx->has_aki); */
	ret = 0;

out:
	return ret;
}

/*
 * section 5.2.2. of RFC 5280. The extension is basically the same as X.509
 * Certificate Issuer Alternative Name, as defined in section 4.2.1.7 of
 * RFC 5280. Code is duplicated here compared to the parsing function
 * defined in cert module, expecting different exports strategy to occur in
 * the future for both modules.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_IAN(crl_parsing_ctx *ctx,
			     const u8 *crl, u32 off, u32 len,
			     int ATTRIBUTE_UNUSED critical)
{
	u32 data_len = 0, hdr_len = 0, remain = 0, eaten = 0;
	const u8 *buf = crl + off;
	int ret, unused = 0;

	if ((crl == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Section 4.2.1.7 of RFC 5280 has "Where present, conforming CAs
	 * SHOULD mark this extension as non-critical."
	 *
	 * FIXME! add a check?
	 */

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * As specified in section 4.2.1.6. of RFC 5280, "if the subjectAltName
	 * extension is present, the sequence MUST contain at least one entry.
	 * Unlike the subject field, conforming CAs MUST NOT issue certificates
	 * with subjectAltNames containing empty GeneralName fields.
	 *
	 * The first check is done here.
	 *
	 * FIXME! second check remains to be done. Possibly in adding an
	 * additional out parameter to parse_GeneralName(), to tell if an empty
	 * one is empty.
	 */
	if (!data_len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@
	  @ loop assigns ret, buf, remain, eaten, unused, off;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop invariant (off + remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_GeneralName(buf, remain, &eaten, &unused);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		remain -= eaten;
		off += eaten;
		buf += eaten;
	}

	ret = 0;

out:
	return ret;
}


/*
 * CRL Number CRL extension as defined in section 5.2.3 of RFC 5280
 *
 *  CRLNumber ::= INTEGER (0..MAX)
 *
 */
#define MAX_CRL_EXT_NUM_LEN 22 /* w/ header */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_crlnumber, ctx->crlnumber_start, ctx->crlnumber_len;
  @*/
static int parse_crl_ext_CRLnum(crl_parsing_ctx *ctx,
				const u8 *crl, u32 off, u32 len,
				int critical)
{
	const u8 *buf = crl + off;
	u32 parsed = 0, hdr_len = 0, data_len = 0;
	int ret;

	if ((crl == NULL) || (len == 0)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* RFC has: "The CRL number is a non-critical CRL extension" */
	if (critical) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Verify the integer is DER-encoded as it should */
	ret = parse_integer(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
			    &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
	parsed = hdr_len + data_len;
	/*@ assert parsed > 2; */

	/*
	 * We now have the guarantee the integer has the following format:
	 * [2 bytes for t/c and len][data_len bytes for encoded value]
	 */

	/*
	 * serialNumber value is expected to be at most 20 bytes long, which
	 * makes 22 bytes for the whole structure (if we include the associated
	 * two bytes header (a length of 20 is encoded on a single byte of
	 * header following the type/class byte.
	 */
	if (parsed > MAX_CRL_EXT_NUM_LEN) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* CRL number with a negative integer does not make sense */
	if (buf[2] & 0x80) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Export presence info, start and end of crl_num to context */
	ctx->has_crlnumber = 1;
	ctx->crlnumber_start = off + hdr_len;
	ctx->crlnumber_len = data_len;

	ret = 0;

out:
	return ret;
}

/*
 * section 5.2.4 of RFC 5280;
 *
 *   BaseCRLNumber ::= CRLNumber
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_DeltaCRL_indicator(crl_parsing_ctx *ctx,
					    const u8 *crl, u32 off, u32 len,
					    int critical)
{
	const u8 *buf = crl + off;
	u32 parsed = 0, hdr_len = 0, data_len = 0;
	int ret;

	if ((crl == NULL) || (len == 0)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* RFC has: "The delta CRL indicator is a critical CRL extension" and
	 * "When a conforming CRL issuer generates a delta CRL, the delta CRL
	 * MUST include a critical delta CRL indicator extension."
	 */
	if (!critical) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Verify the integer is DER-encoded as it should */
	ret = parse_integer(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
			    &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
	parsed = hdr_len + data_len;
	/*@ assert parsed > 2; */

	/*
	 * We now have the guarantee the integer has the following format:
	 * [2 bytes for t/c and len][data_len bytes for encoded value]
	 */

	/*
	 * serialNumber value is expected to be at most 20 bytes long, which
	 * makes 22 bytes for the whole structure (if we include the associated
	 * two bytes header (a length of 20 is encoded on a single byte of
	 * header following the type/class byte.
	 */
	if (parsed > MAX_CRL_EXT_NUM_LEN) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* CRL number with a negative integer does not make sense */
	if (buf[2] & 0x80) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * XXX FIXME export start and end of crl_num to context and
	 * mark the fact that CRL has deltaindicator extension
	 */
	(void)ctx;

out:
	return ret;
}

/*
 * Some structure (e.g. CRL IDP extension) have context specific booleans.
 * We define a specific function for that purpose but avoid using
 * parse_id_len() becasue the expected encoding is simple enough:
 *
 *  FALSE : { 0x80 | tag, 0x01, 0x00 }
 *  TRUE  : { 0x80 | tag, 0x01, 0xff }
 *
 *  with tag on 6 bits
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \separated(eaten, buf+(..));
  @ requires \valid(eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten == 3);
  @ ensures (\result == 0) ==> (len >= 3);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_context_specific_boolean(const u8 *buf, u32 len, u8 tag, u32 *eaten)
{
	u8 c, p, t;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (len < 3) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	c = (buf[0] >> 6) & 0x03; /* Extract class from 2 MSB */
	p = (buf[0] >> 5) & 0x01; /* Extract P/C bit */
	t = buf[0] & 0x1f;        /* Extract tag number from 6 LSB */

	if ((c != CLASS_CONTEXT_SPECIFIC) || (p != 0) || (t != tag)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (buf[1] != 0x01) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	switch (buf[2]) {
	case 0x00: /* FALSE */
	case 0xff: /* TRUE  */
		break;
	default:
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
		break;
	}

	*eaten = 3;

	ret = 0;

out:
	return ret;
}

/* Section 5.2.5 of RFC 5280 has:
 *
 *    IssuingDistributionPoint ::= SEQUENCE {
 *         distributionPoint          [0] DistributionPointName OPTIONAL,
 *         onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
 *         onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
 *         onlySomeReasons            [3] ReasonFlags OPTIONAL,
 *         indirectCRL                [4] BOOLEAN DEFAULT FALSE,
 *         onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
 *
 *         -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
 *         -- and onlyContainsAttributeCerts may be set to TRUE.
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_IDP(crl_parsing_ctx *ctx,
			     const u8 *crl, u32 off, u32 len,
			     int critical)
{
	u32 remain, hdr_len = 0, data_len = 0, eaten = 0;
	int has_dp = 0;
	int onlyContainsUserCerts;
	int onlyContainsCACerts;
	int indirectCRL;
	int onlyContainsAttributeCerts;
	const u8 *buf = crl + off;
	u8 dpn_type = 0;
	int ret;

	if ((crl == NULL) || (ctx == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * RFC has "The issuing distribution point is a critical CRL extension"
	 */
#ifndef TEMPORARY_LAXIST_ALLOW_IDP_CRL_EXT_WITHOUT_CRITICAL_BIT_SET
	if (!critical) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
#else
	(void)critical;
#endif

	remain = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, remain,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	remain -= hdr_len;
	buf += hdr_len;

	/*
	 * RFC 5280 section 5.2.5 has: "Conforming CRLs issuers MUST NOT issue
	 * CRLs where the DER encoding of the issuing distribution point
	 * extension is an empty sequence.  That is, if onlyContainsUserCerts,
	 * onlyContainsCACerts, indirectCRL, and onlyContainsAttributeCerts
	 * are all FALSE, then either the distributionPoint field or the
	 * onlySomeReasons field MUST be present.
	 */
	if (data_len == 0) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* We should have nothing behind */
	if (remain != data_len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * Check if we have a (optional) distributionPoint field
	 * (of type DistributionPointName)
	 */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &hdr_len, &data_len);
	if (!ret) {
		u32 dpn_remain = 0, dpn_eaten= 0;

		buf += hdr_len;
		remain -= hdr_len;
		dpn_remain = data_len;

		if (data_len == 0) {
			ret = -X509_FILE_LINE_NUM_ERR;
			goto out;
		}

		dpn_type = buf[0];

		/*
		 * distributionPoint field of type DistributionPointName
		 * can be either a fullName or a nameRelativeToCRLIssuer.
		 */
		switch (dpn_type) {
		case 0xa0: /* fullName (i.e. a GeneralNames) */
			ret = parse_GeneralNames(buf, dpn_remain,
						 CLASS_CONTEXT_SPECIFIC, 0,
						 &dpn_eaten);
			if (ret) {
				ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
				goto out;
			}

			dpn_remain -= dpn_eaten;
			buf += dpn_eaten;
			break;

		case 0xa1: /* nameRelativeToCRLIssuer (RDN) */
			/*
			 * This form of distributionPoint is never used
			 * in practice in real X.509 certs, so not
			 * supported here. Note that RFC5280 has the
			 * following: "Conforming CAs SHOULD NOT use
			 * nameRelativeToCRLIssuer to specify distribution
			 * point names."
			 */
			ret = -X509_FILE_LINE_NUM_ERR;
			goto out;
			break;

		default:
			ret = -X509_FILE_LINE_NUM_ERR;
			goto out;
			break;
		}

		if (dpn_remain) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		/* Record the fact we found a DP */
		has_dp = 1;

		remain -= data_len;
	}

	/* All boolean in the structure default to FALSE */
	onlyContainsUserCerts = 0;
	onlyContainsCACerts = 0;
	indirectCRL = 0;
	onlyContainsAttributeCerts = 0;

	/*
	 * See if onlyContainsUserCerts is asserted
	 * onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
	 */
	ret = parse_context_specific_boolean(buf, remain, 0x01, &eaten);
	if (!ret) {
		/*
		 * We got a boolean with valid tag. Because it defaults
		 * to FALSE, boolean should not be there at all if it
		 * has value false.
		 */
		if (buf[2] == 0x00) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		onlyContainsUserCerts = 1;

		remain -= eaten;
		buf += eaten;
	}

	/*
	 * See if onlyContainsUserCerts is asserted
	 * onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
	 */
	ret = parse_context_specific_boolean(buf, remain, 0x02, &eaten);
	if (!ret) {
		/*
		 * We got a boolean with valid tag. Because it defaults
		 * to FALSE, boolean should not be there at all if it
		 * has value false.
		 */
		if (buf[2] == 0x00) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		onlyContainsCACerts = 1;

		remain -= eaten;
		buf += eaten;
	}

	/*
	 * See if we have onlySomeReasons
	 * onlySomeReasons	      [3] ReasonFlags OPTIONAL,
	 */
	ret = parse_crldp_reasons(buf, remain, 0x03, &eaten);
	if (!ret) {
		buf += eaten;
		remain -= eaten;
	}

	/*
	 * See if onlyContainsUserCerts is asserted
	 * indirectCRL                [4] BOOLEAN DEFAULT FALSE,
	 */
	ret = parse_context_specific_boolean(buf, remain, 0x04, &eaten);
	if (!ret) {
		/*
		 * We got a boolean with valid tag. Because it defaults
		 * to FALSE, boolean should not be there at all if it
		 * has value false.
		 */
		if (buf[2] == 0x00) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		indirectCRL = 1;

		remain -= eaten;
		buf += eaten;
	}

	/*
	 * See if onlyContainsUserCerts is asserted
	 * onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
	 */
	ret = parse_context_specific_boolean(buf, remain, 0x05, &eaten);
	if (!ret) {
		/*
		 * We got a boolean with valid tag. Because it defaults
		 * to FALSE, boolean should not be there at all if it
		 * has value false.
		 */
		if (buf[2] == 0x00) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		onlyContainsAttributeCerts = 1;

		remain -= eaten;
		buf += eaten;
	}

	/*
	 * RFC 5280 section 5.2.5 has: "at most one of onlyContainsUserCerts,
	 * onlyContainsCACerts, and onlyContainsAttributeCerts may be set
	 * to TRUE.
	 */
	if ((onlyContainsUserCerts + onlyContainsCACerts + onlyContainsAttributeCerts) > 1) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (remain) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = 0;

	/* XXX FIXME: export that to CRL context */
	(void)dpn_type;
	(void)has_dp;
	(void)indirectCRL;

out:
	return ret;
}

/*
 * CRLDP extension is expected in certificates but not in CRL. We implement
 * it to catch errors.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_CRLDP(crl_parsing_ctx *ctx,
			       const u8 *crl, u32 off, u32 len,
			       int critical)
{
	int ret;

	(void)ctx;
	(void)crl;
	(void)off;
	(void)len;
	(void)critical;

	ret = -X509_FILE_LINE_NUM_ERR;
	ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
	return ret;
}


/*
 * This non-critical ExpiredCertsOnCRL CRL extension is defined by ITU:
 *
 * ExpiredCertsOnCRL ::= GeneralizedTime
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_expCertsOnCRL(crl_parsing_ctx *ctx,
				       const u8 *crl, u32 off, u32 len,
				       int critical)
{
	u8 month = 0, day = 0, hour = 0, min = 0, sec = 0;
	const u8 *buf = crl + off;
	u32 eaten;
	u16 year;
	int ret = -1;


	if ((crl == NULL) || (ctx == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (critical) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = parse_generalizedTime(buf, len, &eaten,
				    &year, &month, &day, &hour, &min, &sec);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

out:
	return ret;
}


/*
 * 5.2.6.  Freshest CRL (a.k.a. Delta CRL Distribution Point)
 *
 *     CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 * Note that the Freshest CRL extension uses the exact same syntax and
 * convention as CRLDP extension. The only minor difference is that section
 * 4.2.1.13 has that "The extension SHOULD be non-critical" and section
 * 4.2.1.15 has that "The extension MUST be marked as non-critical by
 * conforming CAs". This is the main difference between the function below
 * and parse_crl_ext_FreshestCRL().
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_crldp,
	    ctx->one_crldp_has_all_reasons;
  @*/
static int parse_crl_ext_FreshestCRL(crl_parsing_ctx *ctx,
				     const u8 *crl, u32 off, u32 len,
				     int critical)
{
	u32 hdr_len = 0, data_len = 0, remain;
	const u8 *buf = crl + off;
	int ret;

	if ((crl == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * RFC has: "Conforming CRL issuers MUST mark this extension as
	 * non-critical".
	 */
	if (critical) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ctx->has_crldp = 1;
	ctx->one_crldp_has_all_reasons = 0;

	/* Iterate on DistributionPoint */
	/*@
	  @ loop assigns ret, buf, remain, ctx->one_crldp_has_all_reasons;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		int crldp_has_all_reasons = 0;
		u32 eaten = 0;

		ret = parse_DistributionPoint(buf, remain,
					      &crldp_has_all_reasons, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		if (crldp_has_all_reasons) {
			ctx->one_crldp_has_all_reasons = 1;
		}

		remain -= eaten;
		buf += eaten;
	}

	ret = 0;

out:
	return ret;
}

/* Section 5.2.7 of RFC RFC 5280 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (critical != 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_AIA(crl_parsing_ctx ATTRIBUTE_UNUSED *ctx,
			     const u8 *crl, u32 off, u32 len, int critical)
{
	int ret;

	if (ctx == NULL) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = parse_AIA(crl, off, len, critical);
	if (ret) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

out:
	return ret;
}

/* This Microsoft CRL extension contains a Time entry */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_szOID_CRL_NEXT_PUBLISH(crl_parsing_ctx *ctx,
				     const u8 *crl, u32 off, u32 len,
				     int ATTRIBUTE_UNUSED critical)
{
	u8 t_month = 0, t_day = 0, t_hour = 0, t_min = 0, t_sec = 0;
	const u8 *buf = crl + off;
	u32 t_len = 0;
	u16 t_year = 0;
	u8 t_type = 0;
	int ret = -1;

	if ((ctx == NULL) || (crl == NULL) || (len == 0)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = parse_Time(buf, len, &t_type, &t_len, &t_year, &t_month,
			 &t_day, &t_hour, &t_min, &t_sec);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (t_len != len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

out:
	return ret;
}

/*
 * https://learn.microsoft.com/en-us/windows/win32/seccrypto/certification-authority-renewal
 *
 * We expect an integer value containing a DWORD
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_szOID_CERTSRV_CA_VERSION(crl_parsing_ctx *ctx,
						  const u8 *crl, u32 off, u32 len,
						  int ATTRIBUTE_UNUSED critical)
{
	u32 parsed = 0, hdr_len = 0, data_len = 0;
	const u8 *buf = crl + off;
	int ret = -1;

	if ((ctx == NULL) || (crl == NULL) || (len == 0)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = parse_non_negative_integer(buf, len,
					 CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* We expected the integer to fit in a DWORD */
	if (data_len > 4) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	parsed = hdr_len + data_len;
	if (parsed != len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	(void)critical;

out:
	return ret;
}

/*
 * XXX FIXME, move to header and disable. When defined the extension is
 * accepted without being parsed and validated. If not defined, an error
 * is returned when the extenion is encoutered.
 */
#define TEMPORARY_LAXIST_CRL_ALLOW_UNPARSED_MS_CRL_SELF_CDP

/*
 * XXX FIXME we currently do not have the definition for this MS extension. It
 * looks a bit more complicated than just a sequence of DP as in a common
 * CRLDP extension.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ assigns \nothing;
  @*/
static int parse_crl_ext_szOID_CRL_SELF_CDP(crl_parsing_ctx *ctx,
				     const u8 *crl, u32 off, u32 len,
				     int critical)
{
	(void)ctx;
	(void)crl;
	(void)off;
	(void)len;
	(void)critical;

#ifdef  TEMPORARY_LAXIST_CRL_ALLOW_UNPARSED_MS_CRL_SELF_CDP
	return 0;
#else
	return -1;
#endif
}


/* From RFC 5280 */

static const u8 _crl_ext_oid_AKI[] =           { 0x06, 0x03, 0x55, 0x1d, 0x23 };
static const u8 _crl_ext_oid_IAN[] =           { 0x06, 0x03, 0x55, 0x1d, 0x12 };
static const u8 _crl_ext_oid_CRLnum[] =        { 0x06, 0x03, 0x55, 0x1d, 0x14 };
static const u8 _crl_ext_oid_DeltaCRL[] =      { 0x06, 0x03, 0x55, 0x1d, 0x1b };
static const u8 _crl_ext_oid_IDP[] =           { 0x06, 0x03, 0x55, 0x1d, 0x1c };
static const u8 _crl_ext_oid_CRLDP[] =         { 0x06, 0x03, 0x55, 0x1d, 0x1f };
static const u8 _crl_ext_oid_FreshestCRL[] =   { 0x06, 0x03, 0x55, 0x1d, 0x2e };
static const u8 _crl_ext_oid_AIA[] =           { 0x06, 0x08, 0x2b, 0x06, 0x01,
						 0x05, 0x05, 0x07, 0x01, 0x01 };

/* From ITU */
static const u8 _crl_ext_oid_expCertsOnCRL[] = { 0x06, 0x03, 0x55, 0x1d, 0x3c };

/* From Microsoft */
static const u8 _crl_ext_oid_szOID_CRL_NEXT_PUBLISH[] = {
	0x06, 0x09, 0x2b, 0x06,	0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x04 };
static const u8 _crl_ext_oid_szOID_CERTSRV_CA_VERSION[] = {
	0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01 };
static const u8 _crl_ext_oid_szOID_CRL_SELF_CDP[] = {
	0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0e };



typedef struct {
	const u8 *oid;
	u8 oid_len;
	int (*parse_crl_ext_params)(crl_parsing_ctx *ctx,
				    const u8 *crl, u32 off, u32 len, int critical);
} _crl_ext_oid;

static const _crl_ext_oid known_crl_ext_oids[] = {
	{ .oid = _crl_ext_oid_AKI, /* Authority Key Identifier */
	  .oid_len = sizeof(_crl_ext_oid_AKI),
	  .parse_crl_ext_params = parse_crl_ext_AKI,
	},
	{ .oid = _crl_ext_oid_IAN, /* Issuer Alternative Name */
	  .oid_len = sizeof(_crl_ext_oid_IAN),
	  .parse_crl_ext_params = parse_crl_ext_IAN,
	},
	{ .oid = _crl_ext_oid_CRLnum, /* CRL Number */
	  .oid_len = sizeof(_crl_ext_oid_CRLnum),
	  .parse_crl_ext_params = parse_crl_ext_CRLnum,
	},
	{ .oid = _crl_ext_oid_DeltaCRL, /* Delta CRL Indicator */
	  .oid_len = sizeof(_crl_ext_oid_DeltaCRL),
	  .parse_crl_ext_params = parse_crl_ext_DeltaCRL_indicator,
	},
	{ .oid = _crl_ext_oid_IDP, /* Issuing Distribution Point */
	  .oid_len = sizeof(_crl_ext_oid_IDP),
	  .parse_crl_ext_params = parse_crl_ext_IDP,
	},
	{ .oid = _crl_ext_oid_CRLDP, /* CRLDP - not expected!!!! */
	  .oid_len = sizeof(_crl_ext_oid_CRLDP),
	  .parse_crl_ext_params = parse_crl_ext_CRLDP,
	},
	{ .oid = _crl_ext_oid_FreshestCRL, /* FreshestCRL */
	  .oid_len = sizeof(_crl_ext_oid_FreshestCRL),
	  .parse_crl_ext_params = parse_crl_ext_FreshestCRL,
	},
	{ .oid = _crl_ext_oid_AIA, /* Authority Information Access */
	  .oid_len = sizeof(_crl_ext_oid_AIA),
	  .parse_crl_ext_params = parse_crl_ext_AIA,
	},
	{ .oid = _crl_ext_oid_expCertsOnCRL, /* expired Certs On CRL */
	  .oid_len = sizeof(_crl_ext_oid_expCertsOnCRL),
	  .parse_crl_ext_params = parse_crl_ext_expCertsOnCRL,
	},
	{ .oid = _crl_ext_oid_szOID_CRL_NEXT_PUBLISH, /* szOID_CRL_NEXT_PUBLISH */
	  .oid_len = sizeof(_crl_ext_oid_szOID_CRL_NEXT_PUBLISH),
	  .parse_crl_ext_params = parse_crl_ext_szOID_CRL_NEXT_PUBLISH,
	},
	{ .oid = _crl_ext_oid_szOID_CERTSRV_CA_VERSION, /* szOID_CERTSRV_CA_VERSION */
	  .oid_len = sizeof(_crl_ext_oid_szOID_CERTSRV_CA_VERSION),
	  .parse_crl_ext_params = parse_crl_ext_szOID_CERTSRV_CA_VERSION,
	},
	{ .oid = _crl_ext_oid_szOID_CRL_SELF_CDP, /* szOID_CRL_SELF_CDP */
	  .oid_len = sizeof(_crl_ext_oid_szOID_CRL_SELF_CDP),
	  .parse_crl_ext_params = parse_crl_ext_szOID_CRL_SELF_CDP,
	},
};

#define NUM_KNOWN_CRL_EXT_OIDS (sizeof(known_crl_ext_oids) /       \
				sizeof(known_crl_ext_oids[0]))
#define MAX_EXT_NUM_PER_CRL NUM_KNOWN_CRL_EXT_OIDS


/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_CRL_EXT_OIDS && \result == &known_crl_ext_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static _crl_ext_oid const * find_crl_ext_by_oid(const u8 *buf, u32 len)
{
	const _crl_ext_oid *found = NULL;
	const _crl_ext_oid *cur = NULL;
	u16 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_CRL_EXT_OIDS ;
	  @ loop invariant 0 <= k <= NUM_KNOWN_CRL_EXT_OIDS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_CRL_EXT_OIDS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_CRL_EXT_OIDS; k++) {
		int ret;

		cur = &known_crl_ext_oids[k];

		/*@ assert cur == &known_crl_ext_oids[k];*/
		if (cur->oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->oid, buf, cur->oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}

/*@
  @ requires ext != \null;
  @ requires \valid(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1)));
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1)));
  @ requires \separated(ext, parsed_oid_list);
  @
  @ ensures \result <= 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CRL - 1)];
  @*/
static int check_record_crl_ext_unknown(const _crl_ext_oid *ext,
					const _crl_ext_oid **parsed_oid_list)
{
	u16 pos = 0;
	int ret;

	/*@
	  @ loop invariant pos <= MAX_EXT_NUM_PER_CRL;
	  @ loop assigns ret, pos, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CRL - 1)];
	  @ loop variant MAX_EXT_NUM_PER_CRL - pos;
	  @*/
	while (pos < MAX_EXT_NUM_PER_CRL) {
		/*
		 * Check if we are at the end of already seen extensions. In
		 * that case, record the extension as a new one. This also
		 * means this is the first time we see this extension.
		 */
		if (parsed_oid_list[pos] == NULL) {
			parsed_oid_list[pos] = ext;
			break;
		}

		/* Check if already seen */
		if (ext == parsed_oid_list[pos]) {
			ret = -X509_FILE_LINE_NUM_ERR;
			goto out;
		}

		pos += 1;
	}

	/*
	 * If we went to the end of our array, this means there are too many
	 * extensions in the certificate.
	 */
	if (pos >= MAX_EXT_NUM_PER_CRL) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = 0;

out:
	return ret;
}


/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (parsed_oid_list != NULL) ==> \valid(parsed_oid_list);
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1)));
  @ requires \separated(ctx, crl+(..),parsed_oid_list,eaten);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CRL - 1)], *eaten, *ctx;
  @*/
static int parse_x509_crl_Extension(crl_parsing_ctx *ctx,
				    const u8 *crl, u32 off, u32 len,
				    const _crl_ext_oid **parsed_oid_list,
				    u32 *eaten)
{
	u32 ext_hdr_len = 0, ext_data_len = 0;
	u32 hdr_len = 0, data_len = 0;
	u32 saved_ext_len = 0, oid_len = 0;
	u32 remain, parsed = 0;
	const u8 *buf = crl + off;
	const _crl_ext_oid *ext = NULL;
	int critical = 0;
	int ret;

	if ((crl == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL) ||
	    (parsed_oid_list == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1))); */

	remain = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, remain,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &ext_hdr_len, &ext_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += ext_hdr_len;
	off += ext_hdr_len;
	remain -= ext_hdr_len;
	saved_ext_len = ext_hdr_len + ext_data_len;

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1))); */

	/*
	 * Let's parse the OID and then check if we have
	 * an associated handler for that extension.
	 */
	ret = parse_OID(buf, ext_data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1))); */

	ext = find_crl_ext_by_oid(buf, oid_len);
	if (ext == NULL) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1))); */

	/*
	 * Now that we know the OID is one we support, we verify
	 * this is the first time we handle an instance of this
	 * type. Having multiple instances of a given extension
	 * in a certificate is forbidden by both section 4.2 of
	 * RFC5280 and section 8 of X.509, w/ respectively
	 *
	 * - "A certificate MUST NOT include more than one
	 *    instance of a particular extension."
	 * - "For all certificate extensions, CRL extensions,
	 *    and CRL entry extensions defined in this Directory
	 *    Specification, there shall be no more than one
	 *    instance of each extension type in any certificate,
	 *    CRL, or CRL entry, respectively."
	 *
	 * This is done by recording for each extension we
	 * processed the pointer to its vtable and compare
	 * it with current one.
	 */
	ret = check_record_crl_ext_unknown(ext, parsed_oid_list);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += oid_len;
	off += oid_len;
	ext_data_len -= oid_len;

	/*
	 * Now that we got the OID, let's check critical
	 * field value if present. It's a boolean
	 * defaulting to FALSE (in which case, it is absent).
	 * We could parse it as an integer but that
	 * would be a lot of work for three simple bytes.
	 */
	ret = parse_boolean(buf, ext_data_len, &parsed);
	if (ret) {
		/*
		 * parse_boolean() returned an error which means this
		 * was either a boolean with invalid content or
		 * something else. If this was indeed a boolean, we can
		 * just leave. Otherwise, this just measn the critical
		 * flag was missing and the default value (false) applies,
		 * in which case, we can continue parsing.
		 */
		if (ext_data_len && (buf[0] == ASN1_TYPE_BOOLEAN)) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}
	} else {
		/*
		 * We now know it's a valid BOOLEAN, *but* in our
		 * case (DER), the DEFAULT FALSE means we cannot
		 * accept an encoded value of FALSE. Note that we
		 * sanity check the value we expect for the length
		 */
		if (parsed != 3) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

#ifndef TEMPORARY_LAXIST_EXTENSION_CRITICAL_FLAG_BOOLEAN_EXPLICIT_FALSE
		if (buf[2] == 0x00) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}
#endif

		/*
		 * We now know the BOOLEAN is present and has
		 * a value of TRUE. Record that.
		 */
		critical = (buf[2] == 0) ? 0 : 1;

		buf += parsed;
		off += parsed;
		ext_data_len -= parsed;
	}

	/*
	 * We should now be in front of the octet string
	 * containing the extnValue.
	 */
	ret = parse_id_len(buf, ext_data_len,
			   CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	ext_data_len -= hdr_len;

	/* Check nothing remains behind the extnValue */
	if (data_len != ext_data_len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert ((u64)off + (u64)ext_data_len) <= MAX_UINT32; */
	/*@ assert \valid_read(crl + (off .. (off + ext_data_len - 1))); */

	/* Parse the parameters for that extension */
	/*@ assert ext->parse_crl_ext_params \in {
	  parse_crl_ext_AKI,
	  parse_crl_ext_IAN,
	  parse_crl_ext_CRLnum,
	  parse_crl_ext_DeltaCRL_indicator,
	  parse_crl_ext_IDP,
	  parse_crl_ext_CRLDP,
	  parse_crl_ext_FreshestCRL,
	  parse_crl_ext_AIA,
	  parse_crl_ext_expCertsOnCRL,
	  parse_crl_ext_szOID_CRL_NEXT_PUBLISH,
	  parse_crl_ext_szOID_CERTSRV_CA_VERSION,
	  parse_crl_ext_szOID_CRL_SELF_CDP }; @*/
	/*@ calls parse_crl_ext_AKI,
	  parse_crl_ext_IAN,
	  parse_crl_ext_CRLnum,
	  parse_crl_ext_DeltaCRL_indicator,
	  parse_crl_ext_IDP,
	  parse_crl_ext_CRLDP,
	  parse_crl_ext_FreshestCRL,
	  parse_crl_ext_AIA,
	  parse_crl_ext_expCertsOnCRL,
	  parse_crl_ext_szOID_CRL_NEXT_PUBLISH,
	  parse_crl_ext_szOID_CERTSRV_CA_VERSION,
	  parse_crl_ext_szOID_CRL_SELF_CDP ; @*/
	ret = ext->parse_crl_ext_params(ctx, crl, off, ext_data_len, critical);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	*eaten = saved_ext_len;
	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(eaten, ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_crl_Extensions(crl_parsing_ctx *ctx,
				     const u8 *crl, u32 off, u32 len,
				     u32 *eaten)
{
	u32 data_len = 0, hdr_len = 0, remain = 0;
	const u8 *buf = crl + off;
	u32 saved_len = 0;
	const _crl_ext_oid *parsed_crl_ext_oid_list[MAX_EXT_NUM_PER_CRL];

	int ret;
	u16 i;

	if ((crl == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Extensions in X.509 CRL is an EXPLICITLY tagged sequence.
	 */
	ret = parse_explicit_id_len(buf, len, 0,
				    CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				    &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	remain = data_len;
	buf += hdr_len;
	off += hdr_len;
	/*@ assert \valid_read(buf + (0 .. (remain - 1))); */

	saved_len = hdr_len + data_len;
	/*@ assert saved_len <= len; */
	/*@ assert data_len <= saved_len; */

	/*
	 * If present, it must contain at least one extension, as specified in
	 * section 5.1.2.7 of RFC 5280: "If present, this field is a sequence
	 * of one or more CRL extensions.
	 */
	if (data_len == 0) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Initialize list of already seen extensions */
	/*@ loop unroll MAX_EXT_NUM_PER_CRL;
	  @ loop assigns i, parsed_crl_ext_oid_list[0 .. (MAX_EXT_NUM_PER_CRL - 1)];
	  @ loop invariant (i < MAX_EXT_NUM_PER_CRL) ==> \valid(&parsed_crl_ext_oid_list[i]);
	  @ loop variant (MAX_EXT_NUM_PER_CRL - i);
	  @*/
	for (i = 0; i < MAX_EXT_NUM_PER_CRL; i++) {
		parsed_crl_ext_oid_list[i] = NULL;
	}
	/*@ assert \initialized(parsed_crl_ext_oid_list + (0 .. (MAX_EXT_NUM_PER_CRL - 1))); */

	/* Now, let's work on each extension in the sequence */
	/*@
	  @ loop assigns off, ret, buf, remain, parsed_crl_ext_oid_list[0 .. (MAX_EXT_NUM_PER_CRL - 1)], *ctx;
	  @ loop invariant (remain != 0) ==> \valid_read(crl + (off .. (off + remain - 1)));
	  @ loop invariant (remain != 0) ==> ((u64)off + (u64)remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @*/
	while (remain) {
		u32 ext_len = 0;

		ret = parse_x509_crl_Extension(ctx, crl, off, remain,
					       parsed_crl_ext_oid_list,
					       &ext_len);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		remain -= ext_len;
		buf += ext_len;
		off += ext_len;
	}

	/*
	 * RFC 5280 has "When CRLs are issued, the CRLs MUST be version 2 CRLs,
	 * include the date by which the next CRL will be issued in the
	 * nextUpdate field (Section 5.1.2.5), include the CRL number extension
	 * (Section 5.2.3), and include the authority key identifier extension
	 * (Section 5.2.1)." If the CRL misses the AKI and CRL number extensions
	 * then it is invalid ;-)
	 */
#ifndef TEMPORARY_LAXIST_ALLOW_MISSING_AKI_OR_CRLNUM
	if (!(ctx->has_crlnumber && ctx->has_aki)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
#endif

	/*@ assert 1 <= saved_len <= len; */
	*eaten = saved_len;

	ret = 0;

out:
	return ret;
}


/*****************************************************************************
 * Code for parsing tbsCertList
 *****************************************************************************/

/*
 * Unlike Certificate Version field which is EXPLICIT, CRL one is not. It is
 * a simple integer.
 *
 *       version                 Version OPTIONAL,
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(version);
  @ requires \separated(eaten, cert+(..), version);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (version == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(version);
  @
  @ assigns *eaten, *version;
  @*/
static int parse_x509_crl_Version(const u8 *cert, u32 off, u32 len, u8 *version, u32 *eaten)
{
	const u8 *buf = cert + off;
	u32 data_len = 0;
	u32 hdr_len = 0;
	int ret;

	if ((cert == NULL) || (version == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */
	ret = parse_integer(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
			    &hdr_len, &data_len);
	if (ret) {
		ret = X509_PARSER_ERROR_VERSION_ABSENT;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += hdr_len;

	/* Integer value is less than 3: data_len must be 1. */
	if (data_len != 1) {
		ret = X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	*version = buf[0];
	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (alg != NULL) ==> \valid(alg);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(crl+(..),alg,ctx,eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \valid_read(*alg);
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_oid_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_oid_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->sig_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->hash_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_len));
  @ ensures (\result == 0) ==> ctx->tbs_sig_alg_start == off;
  @ ensures (\result == 0) ==> \exists integer x; 0 <= x < num_known_sig_algs && *alg == known_sig_algs[x];
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @
  @ assigns *alg, *eaten, *ctx;
  @*/
static int parse_x509_tbsCertList_sig_AlgorithmIdentifier(crl_parsing_ctx *ctx,
							  const u8 *crl, u32 off, u32 len,
							  const _sig_alg **alg,
							  u32 *eaten)
{
	const _sig_alg *talg = NULL;
	const u8 *buf = crl + off;
	u32 saved_off = off;
	u32 parsed = 0;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 param_len;
	u32 oid_len = 0;
	int ret;

	if ((ctx == NULL) || (crl == NULL) || (len == 0)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;}

	parsed = hdr_len + data_len;
	/*@ assert (1 < parsed <= len); */

	buf += hdr_len;
	off += hdr_len;

	/* The first thing we should find in the sequence is an OID */
	ret = parse_OID(buf, data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Let's now see if that OID is one associated w/ an alg we support */
	talg = find_sig_alg_by_oid(buf, oid_len);
	if (talg == NULL) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(talg); */
	/*@ assert \exists integer i ; 0 <= i < num_known_sig_algs && talg == known_sig_algs[i]; */
	/*
	 * Record position of spki alg oid. Also keep track of
	 * the signature mechanism alg identifier and possibly
	 * the associated hash identifier if it was explicit in
	 * the mechanism. Otherwise, we will temporarily inherit
	 * from HASH_ALG_UNKNOWN and possibly get the hash during
	 * the parsing of alg oid sig parameters just below.
	 */
	ctx->tbs_sig_alg_oid_start = off;
	ctx->tbs_sig_alg_oid_len = oid_len;
	ctx->sig_alg = talg->sig_id;
	ctx->hash_alg = talg->hash_id;

	buf += oid_len;
	off += oid_len;
	param_len = data_len - oid_len;

	/*@ assert talg->parse_algoid_sig_params \in {
		  parse_algoid_sig_params_ecdsa_with,
		  parse_algoid_sig_params_ecdsa_with_specified,
		  parse_algoid_sig_params_sm2,
		  parse_algoid_sig_params_eddsa,
		  parse_algoid_sig_params_rsa,
		  parse_algoid_sig_params_rsassa_pss,
		  parse_algoid_sig_params_none,
		  parse_algoid_sig_params_bign_with_hspec }; @*/
	/*@ calls parse_algoid_sig_params_ecdsa_with,
		  parse_algoid_sig_params_ecdsa_with_specified,
		  parse_algoid_sig_params_sm2,
		  parse_algoid_sig_params_eddsa,
		  parse_algoid_sig_params_rsa,
		  parse_algoid_sig_params_rsassa_pss,
		  parse_algoid_sig_params_none,
		  parse_algoid_sig_params_bign_with_hspec; @*/
	ret = talg->parse_algoid_sig_params(&ctx->sig_alg_params,
					    &ctx->hash_alg, crl, off, param_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \exists integer i ; 0 <= i < num_known_sig_algs && talg == known_sig_algs[i]; */
	*alg = talg;
	*eaten = parsed;
	ctx->tbs_sig_alg_start = saved_off;
	ctx->tbs_sig_alg_len = parsed;

	ret = 0;

out:
	return ret;
}

/*
 * Revoked Certificates as defined in section 5.1.2.6 of RFC 5280.
 * The field is optional, i.e. "When there are no revoked certificates,
 * the revoked certificates list MUST be absent.".
 *
 * If one wonders how the disambiguation between absent revokedCertificates
 * and absent extension is performed: the first is a usual sequence, the
 * second is explicitly tagged.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_crl_revokedCertificates(crl_parsing_ctx *ctx,
					      const u8 *crl, u32 off, u32 len,
					      u32 *eaten)
{
	u32 remain = 0, hdr_len = 0, data_len = 0, parsed = 0, cur_off = 0;
	const u8 *buf = crl + off;
	int ret;

	if ((ctx == NULL) || (crl == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */
	/*@ assert \valid_read(crl + (off .. (off + len - 1))); */

	/*
	 * Let's first check we are dealing with a valid sequence. Note that
	 * the field is OPTIONAL, i.e. it must be absent if sequence is empty:
	 * "When there are no revoked certificates, the revoked certificates
	 * list MUST be absent". For that reason, not finding a sequence here
	 * is ok.
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ctx->has_revoked_certs = 0;
		*eaten = 0;
		ret = 0;
		goto out;
	}

	remain = data_len;
	cur_off = off + hdr_len;

	/*@ assert ((u64)cur_off + (u64)remain) <= MAX_UINT32; */
	/*@ assert \valid_read(crl + (cur_off .. (cur_off + remain - 1))); */


#ifndef TEMPORARY_LAXIST_ALLOW_REVOKED_CERTS_LIST_EMPTY
	if (data_len == 0) {
		/*
		 * We do not accept sequences with no data, because
		 * the whole sequence is optional, i.e. it must be
		 * absent when empty.
		 */
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
#endif

	/*@
	  @ loop assigns ret, parsed, *ctx, remain, cur_off;
	  @ loop invariant (remain != 0) ==>
		 \valid_read(crl + (cur_off .. (cur_off + remain - 1)));
	  @ loop invariant (remain != 0) ==>
		 ((u64)cur_off + (u64)remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_x509_crl_revokedCertificate(ctx, crl, cur_off,
							remain,
							&parsed);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		remain -= parsed;
		cur_off += parsed;
	}

	ctx->has_revoked_certs = data_len != 0;
	*eaten = data_len + hdr_len;
	ret = 0;

out:
	return ret;
}

/*
 *
 *    TBSCertList  ::=  SEQUENCE  {
 *         version                 Version OPTIONAL,
 *                                      -- if present, MUST be v2
 *         signature               AlgorithmIdentifier,
 *         issuer                  Name,
 *         thisUpdate              Time,
 *         nextUpdate              Time OPTIONAL,
 *         revokedCertificates     SEQUENCE OF SEQUENCE  {
 *              userCertificate         CertificateSerialNumber,
 *              revocationDate          Time,
 *              crlEntryExtensions      Extensions OPTIONAL
 *                                       -- if present, version MUST be v2
 *                                   }  OPTIONAL,
 *         crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                       -- if present, version MUST be v2
 *                                   }
 *
 * On success, the function returns the size of the TBSCertList
 * structure in 'eaten' parameter. It also provides in 'sig_alg'
 * a pointer to the signature algorithm found in the signature field.
 * This one is provided to be able to check later against the signature
 * algorithm found in the signatureAlgorithm field of the certificate.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(sig_alg, eaten, crl+(..), ctx);
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (sig_alg == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->sig_alg));
  @ ensures (\result == 0) ==> ctx->tbs_sig_alg_start < off + *eaten;
  @
  @ assigns *eaten, *ctx, *sig_alg;
  @*/
static int parse_x509_TBSCertList(crl_parsing_ctx *ctx,
			     const u8 *crl, u32 off, u32 len,
			     const _sig_alg **sig_alg, u32 *eaten)
{
	u32 tbs_data_len = 0;
	u32 tbs_hdr_len = 0;
	u32 tbs_crl_len = 0;
	u32 remain = 0;
	u32 parsed = 0;
	u32 cur_off = off;
	const u8 *buf = crl + cur_off;
	const _sig_alg *alg = NULL;
	int ret, empty_issuer = 1;
	u32 tu_len = 0, nu_len = 0;
	u16 nu_year = 0, tu_year = 0;
	u8 nu_month = 0, nu_day = 0, nu_hour = 0, nu_min = 0, nu_sec = 0;
	u8 tu_month = 0, tu_day = 0, tu_hour = 0, tu_min = 0, tu_sec = 0;
	u64 thisUpdate, nextUpdate;
	u8 t_type = 0;

	if ((ctx == NULL) || (crl == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Let's first check we are dealing with a valid sequence containing
	 * all the elements of the TBSCertList.
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &tbs_hdr_len, &tbs_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	tbs_crl_len = tbs_hdr_len + tbs_data_len;
	buf += tbs_hdr_len;
	cur_off += tbs_hdr_len;
	remain = tbs_data_len;

	/*@ assert \valid_read(buf + (0 .. remain - 1)); */

	/*
	 * Now, we can start and parse all the elements in the sequence
	 * one by one.
	 */

	/*
	 * version: field is optional in which case it is 0x00, i.e. v1.
	 * if present it must be 0x01, i.e. v2. Unlike Version in
	 * certificate, the version field in the CRL is not 'explicit'.
	 * A simle integer is expected.
	 */
	ret = parse_x509_crl_Version(crl, cur_off, remain,
				     &ctx->version, &parsed);
	if (ret) {
		/* missing, use v1 */
		ctx->version = 0x00;
	} else {
		/* present, check this is v2 */
		if (ctx->version != 0x01) {
			ret = -X509_FILE_LINE_NUM_ERR;
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		buf += parsed;
		cur_off += parsed;
		remain -= parsed;
	}

	/* signature */
	ret = parse_x509_tbsCertList_sig_AlgorithmIdentifier(ctx, crl, cur_off,
							     remain, &alg,
							     &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
	/*@ assert \initialized(&(ctx->tbs_sig_alg_start)); */
	/*@ assert ctx->tbs_sig_alg_start == cur_off; */
	/*@ assert ctx->tbs_sig_alg_start < off + tbs_crl_len; */
	/*@ assert \initialized(&(ctx->tbs_sig_alg_len)); */
	/*@ assert \initialized(&(ctx->sig_alg)); */

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* issuer */
	ret = parse_x509_Name(buf, remain, &parsed, &empty_issuer);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
	ctx->issuer_start = cur_off;
	ctx->issuer_len = parsed;

	/*
	 * As described in section 5.1.2.3 of RFC 5280, "The issuer field MUST
	 * contain a non-empty X.500 distinguished name (DN)".
	 */
	/*@ assert (empty_issuer == 0) || (empty_issuer == 1); */
	if (empty_issuer) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* thisUpdate */
	ret = parse_Time(buf, remain, &t_type, &tu_len, &tu_year, &tu_month,
			 &tu_day, &tu_hour, &tu_min, &tu_sec);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Check valid time type was used for year value */
	ret = verify_correct_time_use(t_type, tu_year);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	remain -= tu_len;
	cur_off += tu_len;
	buf += tu_len;

	/*
	 * To export time to context we do not bother converting to unix
	 * but encode all the components of thisUpdate on an u64 in the
	 * following way. Same for nextUpdate. This makes resulting
	 * thisUpdate and nextUpdate values comparable.
	 */

	/*@ assert tu_year <= 9999; */
	/*@ assert tu_month <= 12; */
	/*@ assert tu_day <= 31; */
	/*@ assert tu_hour <= 23; */
	/*@ assert tu_min <= 59; */
	/*@ assert tu_sec <= 59; */
	thisUpdate = time_components_to_comparable_u64(tu_year, tu_month, tu_day,
							tu_hour, tu_min, tu_sec);

	/* nextUpdate */
	ret = parse_Time(buf, remain, &t_type, &nu_len, &nu_year, &nu_month,
			 &nu_day, &nu_hour, &nu_min, &nu_sec);
	if (!ret) {
		/* Check valid time type was used for year value */
		ret = verify_correct_time_use(t_type, nu_year);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		remain -= nu_len;
		cur_off += nu_len;
		buf += nu_len;
	} else {
#ifdef TEMPORARY_LAXIST_ALLOW_MISSING_CRL_NEXT_UPDATE
		/*
		 * In that case, we will define the nextUpdate components to
		 * the largest admisssible values, i.e. encode the "infinity",
		 * i.e. 23h59:59 31/12/9999
		 */
		nu_year = 9999;
		nu_month = 12;
		nu_day = 31;
		nu_hour = 23;
		nu_min = 59;
		nu_sec = 59;
#else
		/*
		 * nextUpdate field is optional in ASN.1 definition but RFC5280
		 * explicitly states both at end of section 5. introduction and
		 * in section 5.1.2 that conforming CRL issuers are required /
		 * MUST include nextUpdate field.
		 */
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
#endif
	}

	/*@ assert nu_year <= 9999; */
	/*@ assert nu_month <= 12; */
	/*@ assert nu_day <= 31; */
	/*@ assert nu_hour <= 23; */
	/*@ assert nu_min <= 59; */
	/*@ assert nu_sec <= 59; */
	nextUpdate = time_components_to_comparable_u64(nu_year, nu_month, nu_day,
						       nu_hour, nu_min, nu_sec);

	if (thisUpdate >= nextUpdate) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert (remain > 0) ==> \valid_read(crl + (cur_off .. (cur_off + remain - 1))); */
	/*
	 * We should now be in front of revokedCertificates sequence, if any.
	 * Note that the field is OPTIONAL, i.e. it must be absent
	 * if sequence is empty: "When there are no revoked certificates,
	 * the revoked certificates list MUST be absent".
	 */
	if (remain) {
		ret = parse_x509_crl_revokedCertificates(ctx, crl, cur_off, remain,
							 &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		cur_off += parsed;
		remain -= parsed;
		/*@ assert (remain > 0) ==> \valid_read(crl + (cur_off .. (cur_off + remain - 1))); */
	}

	/* crlExtensions is only acceptable for v2 crl */
	if ((ctx->version != 0x01) && remain) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert ((u64)cur_off + (u64)remain) <= MAX_UINT32; */
	/*@ assert (remain > 0) ==> \valid_read(crl + (cur_off .. (cur_off + remain - 1))); */

	/* Parse CRL extensions, if any */
	if (remain) {
		ret = parse_x509_crl_Extensions(ctx, crl, cur_off, remain,
						&parsed);
		if (ret) {
			ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
			goto out;
		}

		buf += parsed;
		cur_off += parsed;
		remain -= parsed;
	}

	/*@ assert ctx->tbs_sig_alg_start < off + tbs_crl_len; */

	if (remain != 0) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert ctx->tbs_sig_alg_start < off + tbs_crl_len; */
	/*@ assert 1 < tbs_crl_len <= len; */
	*eaten = tbs_crl_len;
	/*@ assert ctx->tbs_sig_alg_start < off + *eaten; */
	*sig_alg = alg;

	ret = 0;

out:
	return ret;
}


/*****************************************************************************
 * Code for parsing signatureAlgorithm
 *****************************************************************************/

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (0 .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \initialized(&(ctx->tbs_sig_alg_start));
  @ requires \initialized(&(ctx->tbs_sig_alg_len));
  @ requires ctx->tbs_sig_alg_start <= off;
  @ requires \separated(eaten, crl+(..), ctx);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    ctx->sig_alg_start,
	    ctx->sig_alg_len;
  @*/
static int parse_x509_crl_signatureAlgorithm(crl_parsing_ctx *ctx,
					    const u8 *crl, u32 off, u32 len,
					    u32 *eaten)
{
	u32 prev_len;
	int ret;

	if ((crl == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	prev_len = ctx->tbs_sig_alg_len;
	if (prev_len > len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * Section 5.1.1.2 of RFC 5280 has the following regarding
	 * signatureAlgorithm field: "This field MUST contain the same algorithm
	 * identifier as the signature field in the sequence tbsCertList
	 * (Section 5.1.2.2). This is what we verify here.
	 */
	ret = bufs_differ(crl + ctx->tbs_sig_alg_start, crl + off, prev_len);
	if (ret) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}
	ctx->sig_alg_start = off;
	ctx->sig_alg_len = prev_len;

	*eaten = prev_len;

	ret = 0;

out:
	return ret;
}


/*****************************************************************************
 * Code for parsing signatureValue
 *****************************************************************************/

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (off .. (off + len - 1)));
  @ requires (sig_alg != \null) ==> \valid_read(sig_alg) && \valid_function(sig_alg->parse_sig);
  @ requires (\initialized(&ctx->sig_alg));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(ctx, crl+(..), sig_alg, eaten);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (sig_alg == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_crl_signatureValue(crl_parsing_ctx *ctx,
					const u8 *crl, u32 off, u32 len,
					const _sig_alg *sig_alg, u32 *eaten)
{
	u32 saved_off = off;
	int ret;

	if ((ctx == NULL) || (crl == NULL) || (len == 0) ||
	    (sig_alg == NULL) || (eaten == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	if (sig_alg->parse_sig == NULL) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert sig_alg->parse_sig \in {
		  parse_sig_ed448,
		  parse_sig_ed25519,
		  parse_sig_ecdsa,
		  parse_sig_sm2,
		  parse_sig_dsa,
		  parse_sig_rsa_pkcs1_v15,
		  parse_sig_rsa_ssa_pss,
		  parse_sig_rsa_9796_2_pad,
		  parse_sig_rsa_belgian,
		  parse_sig_gost94,
		  parse_sig_gost2001,
		  parse_sig_gost2012_512,
		  parse_sig_gost2012_256,
		  parse_sig_bign,
		  parse_sig_monkey }; @*/
	/*@ calls parse_sig_ed448,
		  parse_sig_ed25519,
		  parse_sig_ecdsa,
		  parse_sig_sm2,
		  parse_sig_dsa,
		  parse_sig_rsa_pkcs1_v15,
		  parse_sig_rsa_ssa_pss,
		  parse_sig_rsa_9796_2_pad,
		  parse_sig_rsa_belgian,
		  parse_sig_gost94,
		  parse_sig_gost2001,
		  parse_sig_gost2012_512,
		  parse_sig_gost2012_256,
		  parse_sig_bign,
		  parse_sig_monkey; @*/
	ret = sig_alg->parse_sig(&(ctx->sig_alg_params), crl, off, len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ctx->sig_start = saved_off;
	ctx->sig_len = *eaten;
	ret = 0;

out:
	return ret;
}


/*****************************************************************************
 * parse_x509_crl()
 *****************************************************************************/

/*@
  @ assigns \nothing;
  @*/
static crl_parsing_ctx get_zeroized_crl_ctx_val(void)
{
	crl_parsing_ctx zeroized_ctx = { 0 };

	return zeroized_ctx;
}

/*
 * RFC 5280, section 5.1 has the following X509 v2 CRL syntax:
 *
 *    CertificateList  ::=  SEQUENCE  {
 *        tbsCertList          TBSCertList,
 *        signatureAlgorithm   AlgorithmIdentifier,
 *        signatureValue       BIT STRING  }
 *
 * DER encoding is used.
 */
/*@
  @ requires ((len > 0) && (crl != \null)) ==> \valid_read(crl + (0 .. (len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, crl+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == 0) ==> \result < 0;
  @ ensures (crl == \null) ==> \result < 0;
  @
  @ assigns *ctx;
  @*/
int parse_x509_crl(crl_parsing_ctx *ctx, const u8 *crl, u32 len)
{
	u32 seq_data_len = 0;
	u32 eaten = 0;
	u32 off = 0;
	const _sig_alg *sig_alg = NULL;
	int ret;

	if ((crl == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	*ctx = get_zeroized_crl_ctx_val();

	/*
	 * Parse beginning of buffer to verify it's a sequence and get
	 * the length of the data it contains.
	 */
	ret = parse_id_len(crl, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &eaten, &seq_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	len -= eaten;
	off += eaten;
	/*@ assert ((u64)off + (u64)len) <= MAX_UINT32; */

	/*
	 * We do expect advertised length to match what now remains in buffer
	 * after the sequence header we just parsed.
	 */
	if (seq_data_len != len) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Parse first element of the sequence: tbsCertList */
	ret = parse_x509_TBSCertList(ctx, crl, off, len, &sig_alg, &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*
	 * XXX as specified in 5.2.1, Conforming CRL issuers MUST use the key
	 * identifier method. This should be enforced here. The thing is that
	 * CRL AKI is an extension and will not be present in old CRL that do
	 * not supported extensions. See what should be done on that aspect.
	 */

	/*@ assert \initialized(&(ctx->sig_alg)); */
	/*@ assert ctx->tbs_sig_alg_start < off + eaten; */

	ctx->tbs_start = off;
	ctx->tbs_len = eaten;

	len -= eaten;
	off += eaten;

	/*@ assert ctx->tbs_sig_alg_start <= off; */

	/* Parse second element of the sequence: signatureAlgorithm */
	ret = parse_x509_crl_signatureAlgorithm(ctx, crl, off, len, &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/*@ assert \initialized(&(ctx->sig_alg)); */

	len -= eaten;
	off += eaten;

	/* Parse second element of the sequence: signatureValue */
	ret = parse_x509_crl_signatureValue(ctx, crl, off, len, sig_alg, &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	/* Check there is nothing left behind */
	if (len != eaten) {
		ret = -X509_FILE_LINE_NUM_ERR;
		ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
		goto out;
	}

	ret = 0;

out:
	return ret;
}


