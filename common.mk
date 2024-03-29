FPIC_CFLAG=-fPIC
FPIE_CFLAG=-fPIE
FPIE_LDFLAGS=-pie -Wl,-z,relro,-z,now
STACK_PROT_FLAG=-fstack-protector-strong

CLANG :=  $(shell $(CROSS_COMPILE)$(CC) -v 2>&1 | grep clang)

ifneq ($(CLANG),)
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

# Clang version >= 13? Adapt
CLANG_VERSION_GTE_13 := $(shell echo `$(CROSS_COMPILE)$(CC) -dumpversion | cut -f1-2 -d.` \>= 13.0 | sed -e 's/\./*100+/g' | bc)
  ifeq ($(CLANG_VERSION_GTE_13), 1)
  # We have to do this because the '_' prefix seems now reserved to builtins
  CFLAGS += -Wno-reserved-identifier
  endif

ifeq ($(PEDANTIC),1)
CFLAGS += -Werror -Walloca -Wcast-qual -Wconversion -Wformat=2           \
	  -Wformat-security -Wnull-dereference -Wstack-protector -Wvla   \
	  -Warray-bounds -Warray-bounds-pointer-arithmetic -Wassign-enum \
	  -Wbad-function-cast -Wconditional-uninitialized -Wconversion   \
	  -Wfloat-equal -Wformat-type-confusion -Widiomatic-parentheses  \
	  -Wimplicit-fallthrough -Wloop-analysis -Wpointer-arith         \
	  -Wshift-sign-overflow -Wshorten-64-to-32                       \
	  -Wtautological-constant-in-range-compare                       \
	  -Wunreachable-code-aggressive -Wthread-safety                  \
	  -Wthread-safety-beta -Wcomma
endif

else # gcc

WARNING_CFLAGS = -W -Werror -Wextra -Wall -Wunreachable-code
ifeq ($(PEDANTIC),1)
CFLAGS += -Wpedantic -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2      \
	  -Wformat-security -Wnull-dereference -Wstack-protector -Wtrampolines \
	  -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3             \
	  -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion    \
	  -Wlogical-op -Wduplicated-cond                                       \
	  -Wduplicated-branches -Wformat-signedness -Wshadow                   \
	  -Wstrict-overflow=2 -Wundef -Wstrict-prototypes -Wswitch-default     \
	  -Wcast-align=strict -Wjump-misses-init
endif

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

LIB_DYN_LDFLAGS ?= -shared -Wl,-z,relro,-z,now

# Default AR and associated flags if not overriden by user
AR ?= ar
AR_FLAGS ?= rcs

# Default RANLIB and associated flags if not overriden by user
RANLIB ?= ranlib
RANLIB_FLAGS ?=

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
