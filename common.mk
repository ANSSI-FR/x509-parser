FPIC_CFLAG=-fPIC
FPIE_CFLAG=-fPIE
FPIE_LDFLAGS=-pie -Wl,-z,relro,-z,now
STACK_PROT_FLAG=-fstack-protector-strong

ifeq ($(CC),clang)
# When compiler is *explicitly* set to clang, use its -Weverything option by
# default but disable the sepcific options we cannot support:
#
#   -Wno-reserved-id-macro: our header files use __XXX___ protection macros.
#   -Wno-unreachable-code-break: goto/return in 'default' of a switch before
#                                a break
WARNING_CFLAGS = -Weverything -Werror \
		 -Wno-reserved-id-macro \
		 -Wno-unreachable-code-break \
		 -Wno-covered-switch-default \
		 -Wno-padded
else
WARNING_CFLAGS = -W -Werror -Wextra -Wall -Wunreachable-code
endif

# If the user has overridden the CFLAGS or LDFLAGS, let's detect it
# and adapt our compilation process
ifdef CFLAGS
USER_DEFINED_CFLAGS = $(CFLAGS)
endif
ifdef LDFLAGS
USER_DEFINED_LDFLAGS = $(LDFLAGS)
endif

CFLAGS ?= $(WARNING_CFLAGS) -pedantic -fno-builtin -std=c99 \
	  -D_FORTIFY_SOURCE=2 $(STACK_PROT_FLAG) -O3
LDFLAGS ?=

# Default AR and RANLIB if not overriden by user
AR ?= ar
RANLIB ?= ranlib

# Our debug flags
DEBUG_CFLAGS = -DDEBUG -O -g
# Code coverage options for gcov: -fprofile-arcs -ftest-coverage

# Default all and clean target that will be expanded
# later in the Makefile
all:
clean:

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: clean all

# Let's now define the two kinds of CFLAGS we will use for building our
# library (LIB_CFLAGS) and binaries (BIN_CFLAGS) objects.
# If the user has not overriden the CFLAGS, we add the usual gcc/clang
# flags to produce binaries compatible with hardening technologies.
ifndef USER_DEFINED_CFLAGS
BIN_CFLAGS  ?= $(CFLAGS) $(FPIE_CFLAG)
LIB_CFLAGS  ?= $(CFLAGS) $(FPIC_CFLAG) -ffreestanding
else
BIN_CFLAGS  ?= $(USER_DEFINED_CFLAGS)
LIB_CFLAGS  ?= $(USER_DEFINED_CFLAGS)
endif

ifndef USER_DEFINED_LDFLAGS
BIN_LDFLAGS ?= $(LDFLAGS) $(FPIE_LDFLAGS)
else
BIN_LDFLAGS ?= $(LDFLAGS)
endif
