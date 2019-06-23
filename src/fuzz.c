#include "x509-parser.h"

int LLVMFuzzerTestOneInput(const u8 *buf, size_t len) {
	parse_x509_cert(buf, len);
	return 0;
}

