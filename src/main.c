/*
 *  Copyright (C) 2022 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "x509-parser.h"

#define X509_FILE_NUM 1 /* See x509-utils.h for rationale */

static void usage(char *argv0)
{
	printf("Usage: %s file.der\n", argv0);
}

int main(int argc, char *argv[])
{
	char *path = argv[1];
	cert_parsing_ctx cert_ctx;
	crl_parsing_ctx crl_ctx;
	struct stat st;
	off_t fsize, offset, remain;
	u32 eaten, to_be_parsed;
	u8 *buf, *ptr;;
	int ret;
	int fd;
	int num_x509_files;
	int num_certs_v3_ok;
	int num_crl_ok;

	if (argc != 2) {
		usage(argv[0]);
		ret = -1;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		printf("Unable to open input file %s\n", path);
		ret = -1;
		goto out;
	}

	/*
	 * Get size of the file. Note: fstat and mmap uses off_t and size_t
	 * types which can be 32-bits (additionally, off_t is a signed int).
	 * As specified in man pages, we use -D_FILE_OFFSET_BITS=64 to have
	 * those on 64 bits.
	 */
	ret = fstat(fd, &st);
	if (ret) {
		printf("fstat() on file %s falied with err %d\n", path, ret);
		ret = -1;
		goto out;
	}
	fsize = st.st_size;

	/* mmap the file */
	ptr = mmap(0, fsize, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		printf("mmap() failed with errno=%d\n", errno);
		ret = -1;
		goto out;
	}

	/* Initialize stat values */
	num_x509_files = 0;
	num_certs_v3_ok = 0;
	num_crl_ok = 0;

	remain = fsize;
	buf = ptr;
	offset = 0;
	while (remain) {
		/*
		 * File may be larger than 4GB but parser expects u32
		 * and has limits on size for individual elements to be
		 * parsed.
		 */
		to_be_parsed = ASN1_MAX_BUFFER_SIZE;
		if (to_be_parsed > remain) {
			to_be_parsed = remain;
		}
		eaten = 0;

		/* First try and parse buffer as a certificate */

		memset(&cert_ctx, 0, sizeof(cert_ctx));
		ret = parse_x509_cert_relaxed(&cert_ctx, buf, to_be_parsed, &eaten);
#ifdef ERROR_TRACE_ENABLE
		printf("- CERT %06d off %llu eaten %lu file %s\n", -ret, offset, eaten, path);
#endif

		switch (ret) {
		case 0:
			// printf("offset %llu %d\n", offset, eaten);
			num_x509_files += 1;
			num_certs_v3_ok += 1;
			break;

		case 1:
			printf("Invalid sequence element #%d at offset %ld\n",
				num_x509_files, offset);
			ret = -1;
			goto out;
			break;

		case X509_PARSER_ERROR_VERSION_NOT_3:
		case X509_PARSER_ERROR_VERSION_ABSENT:
		case X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH:
			num_x509_files += 1;
			break;

		default:
			num_x509_files += 1;
			break;
		}

		/*
		 * if this is not even a valid sequence or the certificate was
		 * considered valid, we do not need to bother parsing it as
		 * a CRL.
		 */
		if ((ret != 1) && (ret != 0)) {
			memset(&crl_ctx, 0, sizeof(crl_ctx));
			ret = parse_x509_crl_relaxed(&crl_ctx, buf, to_be_parsed, &eaten);
#ifdef ERROR_TRACE_ENABLE
			printf("- CRL %06d off %llu eaten %lu file %s\n", -ret, offset, eaten, path);
#endif

			switch (ret) {
			case 0:
				// printf("offset %llu %d\n", offset, eaten);
				num_crl_ok += 1;
				break;

			default:
				break;
			}

		}

		offset += eaten;
		buf += eaten;
		remain -= eaten;
	}

	ret = munmap(ptr, fsize);
	close(fd);

	printf("Valid X.509v3 Certs: %d/%d (%.2f%%)\n",
		num_certs_v3_ok, num_x509_files, ((float)(100*num_certs_v3_ok) / ((float)num_x509_files)));
	printf("Valid X.509 CRL    : %d/%d (%.2f%%)\n",
		num_crl_ok, num_x509_files, ((float)(100*num_crl_ok) / ((float)num_x509_files)));

out:
	return ret;
}
