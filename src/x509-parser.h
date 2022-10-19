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

#include "x509-cert-parser.h"
#include "x509-crl-parser.h"

/*
 * This wrappers around parse_x509_cert() and parse_x509_crl() do not expect the
 * buffer to exactly contain a DER-encoded certificate, but to start with one.
 * It returns the length of the first sequence found in the buffer, no matter
 * if the certificate or CRL (this sequence) is valid or not. It only requires
 * the buffer to start with a sequence.
 *
 * Behavior based on return value:
 *
 *   1 : - buffer does not start with a valid sequence, so 'eaten' has not
 *         been updated with useful info
 *       - parsing has not been performed
 *       - ctx has not been updated
 *
 *   0 : - 'eaten' contains the length of parsed
 *       - Cert/CRL parsing went OK
 *       - ctx is usable and contains parsing info
 *
 * < 0 : - 'eaten' contains the length of parsed
 *       - Cert/CRL parsing went wrong and return value contains parsing
 *         error value
 *       - ctx is usable and contains parsing info
 *
 */
int parse_x509_cert_relaxed(cert_parsing_ctx *ctx, const u8 *buf, u32 len, u32 *eaten);
int parse_x509_crl_relaxed(crl_parsing_ctx *ctx, const u8 *buf, u32 len, u32 *eaten);

#endif /* __X509_PARSER_H__ */
