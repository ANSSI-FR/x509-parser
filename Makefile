.SUFFIXES:

#####################################################################
# Project compilation
#####################################################################

BUILD_DIR=./build
CORPUS_DIR=./corpus
EXEC = $(BUILD_DIR)/x509-parser

JOBS:=$(shell nproc)

include common.mk

all: $(LIBS) $(EXEC)

$(CORPUS_DIR):
	@mkdir -p $@

$(BUILD_DIR):
	@mkdir -p $@

fuzz-asan: $(CORPUS_DIR) $(BUILD_DIR)/x509-fuzz-asan
	./$(BUILD_DIR)/x509-fuzz-asan -max_len=65535 -jobs=$(JOBS) $(CORPUS_DIR)

fuzz-ubsan: $(CORPUS_DIR) $(BUILD_DIR)/x509-fuzz-ubsan
	./$(BUILD_DIR)/x509-fuzz-ubsan -max_len=65535 -jobs=$(JOBS) $(CORPUS_DIR)

fuzz-msan: $(CORPUS_DIR) $(BUILD_DIR)/x509-fuzz-msan
	./$(BUILD_DIR)/x509-fuzz-msan -max_len=65535 -jobs=$(JOBS) $(CORPUS_DIR)

$(BUILD_DIR)/x509-parser: src/main.c $(BUILD_DIR)/x509-parser.o
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $^ -o $@

$(BUILD_DIR)/x509-fuzz-asan: $(BUILD_DIR) src/fuzz.c src/x509-parser.c
	clang -g -O1 -fsanitize=fuzzer,address src/fuzz.c src/x509-parser.c -o $@

$(BUILD_DIR)/x509-fuzz-ubsan: $(BUILD_DIR) src/fuzz.c src/x509-parser.c
	clang -g -O1 -fsanitize=fuzzer,signed-integer-overflow src/fuzz.c src/x509-parser.c -o $@

$(BUILD_DIR)/x509-fuzz-msan: $(BUILD_DIR) src/fuzz.c src/x509-parser.c
	clang -g -O1 -fsanitize=fuzzer,memory src/fuzz.c src/x509-parser.c -o $@

$(BUILD_DIR)/x509-parser.o: $(BUILD_DIR) src/x509-parser.c src/x509-parser.h
	$(CC) $(LIB_CFLAGS) -c src/x509-parser.c -o $@

clean:
	@rm -fr $(LIBS) $(EXEC) build *.log
	@find -name '*.o' -exec rm -f '{}' \;
	@find -name '*~'  -exec rm -f '{}' \;

#####################################################################
# Frama-C
#####################################################################

SESSION:=frama-c-rte-val-wp.session
TIMEOUT:=15

# "-val-warn-undefined-pointer-comparison none" is to deal with the
# checks (\pointer_comparable( - ,  - )) otherwise added by EVA before
# our tests of pointers against NULL. Those are not understood by WP.
# This is not an issue but should be revisited later. --arno
#
# See https://bts.frama-c.com/view.php?id=2206

frama-c:
	frama-c-gui src/x509-parser.c -machdep x86_64 \
	            -warn-left-shift-negative \
	            -warn-right-shift-negative \
	            -warn-signed-downcast \
	            -warn-signed-overflow \
	            -warn-unsigned-downcast \
	            -warn-unsigned-overflow \
		    -rte \
		    -eva \
		    -wp-dynamic \
		    -eva-slevel 1 \
		    -slevel-function="_extract_complex_tag:100, \
				      _parse_arc:100, \
				      parse_UTCTime:100, \
				      find_dn_by_oid:100, \
				      find_curve_by_oid:100, \
				      find_alg_by_oid:200, \
				      find_ext_by_oid:200, \
				      parse_AccessDescription:400, \
				      parse_x509_Extension:400, \
				      parse_x509_subjectPublicKeyInfo:300, \
				      parse_x509_Extensions:400, \
				      bufs_differ:200, \
				      parse_x509_tbsCertificate:400, \
				      parse_x509_AlgorithmIdentifier:200" \
		    -eva-warn-undefined-pointer-comparison none \
		    -then \
		    -wp \
		    -wp-dynamic \
		    -wp-par $(JOBS) \
		    -wp-steps 100000 -wp-depth 100000 -pp-annot \
		    -wp-split -wp-literals \
		    -wp-timeout $(TIMEOUT) -save $(SESSION)

frama-c-gui:
	frama-c-gui -load $(SESSION)

.PHONY: all clean fuzz-asan fuzz-ubsan fuzz-msan frama-c-gui frama-c
