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
#include "x509-parser.h"

static void usage(char *argv0)
{
	printf("Usage: %s file.der\n", argv0);
}

int main(int argc, char *argv[])
{
	char *path = argv[1];
	cert_parsing_ctx ctx;
	struct stat st;
	off_t fsize, offset, remain;
	u32 eaten, to_be_parsed;
	u8 *buf, *ptr;;
	int ret;
	int fd;
	int num_v3_certs, num_v3_certs_ok, num_not_v3;

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

	/* Initialize stat values */
	num_not_v3 = 0;
	num_v3_certs = 0;
	num_v3_certs_ok = 0;

	remain = fsize;
	buf = ptr;
	offset = 0;
	while (remain) {
		memset(&ctx, 0, sizeof(ctx));

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

		/* We limit our calls to parser to  */
		ret = parse_x509_cert_relaxed(&ctx, buf, to_be_parsed, &eaten);

#ifdef ERROR_TRACE_ENABLE
		printf("- %05d off %llu eaten %lu file %s\n", -ret, offset, eaten, path);
#endif
		switch (ret) {
		case 0:
			// printf("offset %llu %d\n", offset, eaten);
			num_v3_certs_ok += 1;
			num_v3_certs += 1;
			break;

		case 1:
			printf("Invalid sequence for cert #%d at offset %ld\n",
				num_v3_certs + num_not_v3, offset);
			ret = -1;
			goto out;
			break;

		case X509_PARSER_ERROR_VERSION_NOT_3:
		case X509_PARSER_ERROR_VERSION_ABSENT:
		case X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH:
			num_not_v3 += 1;
			break;

		default:
			num_v3_certs += 1;
			break;
		}

		offset += eaten;
		buf += eaten;
		remain -= eaten;
	}

	ret = munmap(ptr, fsize);
	close(fd);

	printf("%d/%d (%.2f%%) valid X.509v3 certificate(s) (and %d non-v3 certs)\n",
		num_v3_certs_ok, num_v3_certs,
		((float)(100*num_v3_certs_ok) / ((float)num_v3_certs)),
		num_not_v3);

out:
	return ret;
}
