.SUFFIXES:

#####################################################################
# Project compilation
#####################################################################

BUILD_DIR=./build
EXEC = $(BUILD_DIR)/x509-parser

include common.mk

all: $(LIBS) $(EXEC)

$(BUILD_DIR)/x509-parser: src/main.c build/x509-parser.o
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $^ -o $@

build/x509-parser.o: src/x509-parser.c src/x509-parser.h
	@mkdir -p  $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

clean:
	@rm -f $(LIBS) $(EXEC)
	@find -name '*.o' -exec rm -f '{}' \;
	@find -name '*~'  -exec rm -f '{}' \;

#####################################################################
# Frama-C
#####################################################################

SESSION:=frama-c-rte-val-wp.session
JOBS:=$(shell nproc)
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

.PHONY: all clean frama-c-gui frama-c
