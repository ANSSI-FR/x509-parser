/*
 *  Copyright (C) 2019 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "x509-parser.h"
#include <unistd.h>

static void usage(char *argv0)
{
	printf("Usage: %s file.der\n", argv0);
}

int main(int argc, char *argv[])
{
	u8 buf[ASN1_MAX_BUFFER_SIZE];
	off_t pos, offset = 0;
	char *path = argv[1];
	u16 rem, copied, eaten;
	int ret, eof = 0;
	int fd, num_v3_certs, num_v3_certs_ok, num_not_v3;
	int more;

	if (argc != 2) {
		usage(argv[0]);
		ret = -1;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		printf("Unable to open input file %s\n", path);
		return -1;
	}

	num_not_v3 = 0;
	num_v3_certs = 0;
	num_v3_certs_ok = 0;
	more = 1;
	while (more) {
		pos = lseek(fd, offset, SEEK_SET);
		if (pos == (off_t)-1) {
			printf("lseek failed %s\n", path);
			ret = -1;
			goto out;
		}
		rem = ASN1_MAX_BUFFER_SIZE;
		copied = 0;
		while (rem) {
			ret = (int)read(fd, buf + copied, rem);
			if (ret <= 0) {
				if (copied == 0) {
					eof = 1;
				}
				break;
			} else {
				rem -= (u16)ret;
				copied += (u16)ret;
			}
		}

		if (eof) {
			break;
		}

		eaten = 0;
		ret = parse_x509_cert_relaxed(buf, copied, &eaten);
#ifdef ERROR_TRACE_ENABLE
		printf("- %05d %ld %d %s\n", -ret, offset, eaten, path);
#endif
		switch (ret) {
		case 0:
			num_v3_certs_ok += 1;
			num_v3_certs += 1;
			offset += eaten;
			more = 1;
			break;

		case 1:
			printf("Invalid sequence for cert #%d at offset %d\n",
				num_v3_certs + num_not_v3, offset);
			more = 0;
			break;

		case X509_PARSER_ERROR_VERSION_NOT_3:
		case X509_PARSER_ERROR_VERSION_ABSENT:
		case X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH:
			num_not_v3 += 1;
			offset += eaten;
			more = 1;
			break;

		default:
			num_v3_certs += 1;
			offset += eaten;
			more = 1;
			break;
		}
	}
	close(fd);

	ret = 0;

	printf("%d/%d (%.2f%%) valid X.509v3 certificate(s) (and %d non-v3 certs)\n",
		num_v3_certs_ok, num_v3_certs,
		((float)(100*num_v3_certs_ok) / ((float)num_v3_certs)),
		num_not_v3);

out:
	return ret;
}
