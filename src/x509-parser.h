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
