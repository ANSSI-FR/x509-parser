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

build/x509-parser.o: src/x509-parser.c src/x509-parser.h src/x509-parser-internal-decl.h
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
NPROC:=$(shell nproc)
JOBS:=$(shell echo $$(( $(NPROC) * 2 )))
TIMEOUT:=15

# "-val-warn-undefined-pointer-comparison none" is to deal with the
# checks (\pointer_comparable( - ,  - )) otherwise added by EVA before
# our tests of pointers against NULL. Those are not understood by WP.
# This is not an issue but should be revisited later. --arno
#
# See https://bts.frama-c.com/view.php?id=2206

frama-c:
	frama-c src/x509-parser.c -machdep x86_64  -pp-annot \
		    -warn-left-shift-negative \
		    -warn-right-shift-negative \
		    -warn-signed-downcast \
		    -warn-signed-overflow \
		    -warn-unsigned-downcast \
		    -warn-unsigned-overflow \
		    -eva \
		    -wp-dynamic -eva-slevel 1\
		    -eva-warn-undefined-pointer-comparison none\
		    -then -wp -wp-steps 100000\
		    -wp-dynamic \
		    -wp-no-init-const \
		    -wp-par $(JOBS) \
		    -wp-timeout $(TIMEOUT) -save $(SESSION) 

frama-c-gui:
	frama-c-gui -load $(SESSION)

#####################################################################
# IKOS
#####################################################################

IKOS_DATABASE:=ikos.db

ikos:
	ikos src/x509-parser.c -D__IKOS__ -o $(IKOS_DATABASE)

ikos-gui:
	ikos-view $(IKOS_DATABASE)

.PHONY: all clean frama-c-gui frama-c ikos ikos-gui
