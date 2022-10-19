.SUFFIXES:

#####################################################################
# Project compilation
#####################################################################

BUILD_DIR ?= ./build
OBJS_DIR ?= ./
EXEC = $(BUILD_DIR)/x509-parser
LIBS = $(BUILD_DIR)/x509-parser.a $(BUILD_DIR)/x509-parser.so
OBJS = $(OBJS_DIR)/x509-parser.o \
       $(OBJS_DIR)/x509-cert-parser.o $(OBJS_DIR)/x509-crl-parser.o \
       $(OBJS_DIR)/x509-common.o $(OBJS_DIR)/x509-utils.o
HEADERS = $(wildcard src/*.h)

include common.mk


.PHONY: clean all

all: $(OBJS) $(EXEC) $(LIBS)

clean:
	@rm -f $(OBJS) $(EXEC) $(LIBS)
	@find -name '*~'  -exec rm -f '{}' \;


# Main binary
$(BUILD_DIR)/x509-parser: src/main.c $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) -D_FILE_OFFSET_BITS=64 $^ -o $@


# libs (static and dynamic)
$(BUILD_DIR)/x509-parser.a: $(OBJS)
	$(AR) $(AR_FLAGS) $@ $^
	$(RANLIB) $(RANLIB_FLAGS) $@

$(BUILD_DIR)/x509-parser.so: $(OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_DYN_LDFLAGS) $^ -o $@


# objects
$(OBJS_DIR)/x509-parser.o: src/x509-parser.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(OBJS_DIR)/x509-crl-parser.o: src/x509-crl-parser.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(OBJS_DIR)/x509-cert-parser.o: src/x509-cert-parser.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(OBJS_DIR)/x509-common.o: src/x509-common.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(OBJS_DIR)/x509-utils.o: src/x509-utils.c src/x509-utils.h
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) -c $< -o $@


#####################################################################
# Frama-C
#####################################################################

SESSION:=frama-c-rte-eva-then-wp.session
JOBS:=$(shell nproc)
TIMEOUT:=30

# "-val-warn-undefined-pointer-comparison none" is to deal with the
# checks (\pointer_comparable( - ,  - )) otherwise added by EVA before
# our tests of pointers against NULL. Those are not understood by WP.
# This is not an issue but should be revisited later. --arno
#
# See https://bts.frama-c.com/view.php?id=2206

frama-c:
	frama-c src/x509-utils.c src/x509-common.c \
		src/x509-crl-parser.c \
		src/x509-cert-parser.c \
		src/x509-parser.c \
		-machdep x86_64  -pp-annot \
		-warn-left-shift-negative \
		-warn-right-shift-negative \
		-warn-signed-downcast \
		-warn-signed-overflow \
		-warn-unsigned-downcast \
		-warn-unsigned-overflow \
		-rte \
		-then \
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
