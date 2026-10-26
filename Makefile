# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
#
# tcxflow - Lightweight eBPF-based IPFIX flow accounting for Linux
#
#   make                  build ./tcxflow
#   make dev              strict build of tcxflow and the tests: every warning is an error
#   make test             unit tests (no root needed)
#   sudo make test-bpf    BPF program tests via BPF_PROG_TEST_RUN (root)
#   sudo make test-e2e    end-to-end test in network namespaces (root, nfdump, iperf3)
#   sudo make test-all    all three
#   make indent           format the sources with clang-format
#   make check-indent     fail if a source is not formatted
#   make lint             static analysis with clang-tidy (checks in .clang-tidy) and shellcheck
#   make check            check-indent, lint, make dev and the unit tests
#   make docs             Doxygen documentation in docs/html
#   make dist             source tarball ../tcxflow-VERSION.tar.gz of the committed HEAD
#   sudo make install     binary, systemd unit and example configuration
#   sudo make uninstall   remove the binary and the systemd unit
#   make clean            remove everything the build created
#
# Needs a C23 compiler (GCC >= 14 or Clang >= 19), Clang >= 19 for the BPF program, libbpf >= 1.5
# and bpftool (the oldest supported distribution, Debian 13, has exactly these).
#
# Variables: DEV_WARNINGS=1 (what `make dev` sets), SANITIZE=address (ASan + UBSan),
# CFLAGS, CPPFLAGS, LDFLAGS (the packager's; tcxflow adds its own flags separately),
# PREFIX, SBINDIR, UNITDIR, SYSCONFDIR, DESTDIR, CC, CLANG, BPFTOOL, PKG_CONFIG, CLANG_FORMAT,
# CLANG_TIDY, SHELLCHECK, NJOBS.

# The release version without the "v" of its tag (vX.Y.Z), as tarballs and packages use it; that
# of HEAD, which dist packs, not of an uncommitted edit.
VERSION = $(shell git show HEAD:src/util.h | sed -n 's/^\#define TCXFLOW_VERSION "v\([^"]*\)".*/\1/p')

PREFIX     ?= /usr/local
SBINDIR    ?= $(PREFIX)/sbin
UNITDIR    ?= $(PREFIX)/lib/systemd/system
SYSCONFDIR ?= /etc

PKG_CONFIG   ?= pkg-config
CLANG        ?= clang
# In /usr/sbin, which is not in the PATH of ordinary users on Debian.
BPFTOOL      ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG_FORMAT ?= clang-format
CLANG_TIDY   ?= clang-tidy
SHELLCHECK   ?= shellcheck
NJOBS        ?= $(shell nproc 2>/dev/null || echo 1)

# ------------------------------------------------------------
# Compiler flags
# ------------------------------------------------------------
# CFLAGS, CPPFLAGS and LDFLAGS are the packager's (environment or command line, e.g.
# make CFLAGS="$RPM_OPT_FLAGS"); what tcxflow itself needs is kept separately in TCX_*.
CFLAGS        ?= -O2 -g
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
TCX_CFLAGS     = -std=gnu23 -Wall -Wextra
# build/ holds the BPF skeleton that bpftool generates: a system directory to the compiler, so
# that the warnings of generated code do not fail the strict build.
TCX_CPPFLAGS   = -D_GNU_SOURCE -Isrc -isystem build $(LIBBPF_CFLAGS) \
                 -DCONFIG_DEFAULT_PATH=\"$(SYSCONFDIR)/tcxflow/tcxflow.conf\"
LDLIBS         = $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || echo -lbpf)

# BPF: the bpf target has no system include directories; those of the host, as clang reports
# them, include Debian's multiarch directory with the asm/ headers (as libbpf-bootstrap does).
# Instruction set v4 needs Linux 6.6, which tcx needs anyway.
BPF_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
                  sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
BPF_CFLAGS    = -std=gnu23 -O2 -g -Wall -target bpf -mcpu=v4 -Isrc $(LIBBPF_CFLAGS) $(BPF_INCLUDES)

CC_IS_CLANG := $(shell $(CC) -dM -E -x c /dev/null 2>/dev/null | grep -q __clang__ && echo 1)

# Strict build (`make dev`, or DEV_WARNINGS=1 on any target): lenient by default, so a newer
# compiler never breaks a distribution build. GCC additionally runs its static analyzer.
DEV_WARNINGS ?= 0
ifeq ($(DEV_WARNINGS),1)
COMMON_WARN = -Werror -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wpointer-arith \
              -Wundef -Wvla -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes \
              -Wmissing-declarations -Wimplicit-fallthrough -Wunused-macros -Wredundant-decls
WARN_FLAGS  = $(COMMON_WARN) -pedantic-errors -Wformat=2 -Wnull-dereference -Wold-style-definition \
              -Wnested-externs -Wbad-function-cast -Wdouble-promotion -Wfloat-equal -Wswitch-enum -Walloca \
              -Wmissing-variable-declarations \
              -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection
ifeq ($(CC_IS_CLANG),1)
# libbpf's LIBBPF_OPTS() is a statement expression, which Clang flags even from a system header.
WARN_FLAGS += -Wcast-align -Wcomma -Wassign-enum -Wunreachable-code-aggressive -Wshorten-64-to-32 \
              -Wno-gnu-statement-expression-from-macro-expansion
else
WARN_FLAGS += -Wcast-align=strict -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wjump-misses-init \
              -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-signedness -Wstringop-overflow=4 \
              -Warray-bounds=2 -Wtrampolines -Wstack-usage=65536 -Walloc-size -Wcalloc-transposed-args -fanalyzer
endif
BPF_CFLAGS += $(COMMON_WARN)
endif

# Sanitizers: `make SANITIZE=address` (AddressSanitizer + UndefinedBehaviorSanitizer)
SANITIZE ?=
ifeq ($(SANITIZE),address)
SAN_CFLAGS  = -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
SAN_LDFLAGS = -fsanitize=address,undefined
else ifneq ($(SANITIZE),)
$(error SANITIZE must be address or empty)
endif

# ------------------------------------------------------------
# Sources / targets
# ------------------------------------------------------------
SRCS      = src/main.c src/daemon.c src/config.c src/collector.c src/control.c \
            src/ipfix.c src/cache.c src/meter.c src/util.c src/vlan.c src/iface.c
HEADERS   = $(wildcard src/*.h)
OBJS      = $(SRCS:src/%.c=build/%.o)
BPF_OBJ   = build/tcxflow.bpf.o
SKEL      = build/tcxflow.skel.h

# Compiler and linker command lines of all userspace objects and programs.
COMPILE = $(CC) $(TCX_CPPFLAGS) $(CPPFLAGS) $(TCX_CFLAGS) $(CFLAGS) $(SAN_CFLAGS) $(WARN_FLAGS)
LINK    = $(CC) $(TCX_CFLAGS) $(CFLAGS) $(SAN_CFLAGS) $(WARN_FLAGS) $(LDFLAGS) $(SAN_LDFLAGS)

UNIT_OBJS = build/config.o build/collector.o build/control.o build/ipfix.o build/cache.o build/util.o build/vlan.o \
            build/iface.o
BPF_TEST_OBJS = build/meter.o build/util.o

.PHONY: all dev test test-bpf test-e2e test-all indent check-indent lint check docs dist install uninstall clean FORCE

# A recipe that fails (bpftool writing the skeleton to stdout) leaves no half-written target behind.
.DELETE_ON_ERROR:

all: tcxflow

dev:
	@$(MAKE) --no-print-directory DEV_WARNINGS=1 tcxflow build/test_unit build/test_bpf build/test_bpf_native

build:
	@mkdir -p build

# Every object depends on the flags it was built with: switching between `make`, `make dev`
# and SANITIZE=address rebuilds everything, instead of linking objects built with other flags.
BUILD_FLAGS = $(COMPILE) / $(LINK) $(LDLIBS) / $(CLANG) $(BPF_CFLAGS) / $(BPFTOOL)

# Compared by the shell: minimal container images have no cmp.
build/.flags: FORCE | build
	@echo '$(BUILD_FLAGS)' > $@.new; \
	if [ "$$(cat $@.new)" = "$$(cat $@ 2>/dev/null)" ]; then rm -f $@.new; else mv -f $@.new $@; fi

tcxflow: $(OBJS)
	$(LINK) $(OBJS) -o $@ $(LDLIBS)

build/%.o: src/%.c build/.flags | build
	$(COMPILE) -MMD -MP -c $< -o $@

# bpftool's static linker drops the DWARF debug information and keeps BTF, which CO-RE and the
# verifier's line info need: half the size for the copy embedded in tcxflow.
$(BPF_OBJ): src/tcxflow.bpf.c src/flow.h build/.flags | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o build/tcxflow.tmp.bpf.o
	$(BPFTOOL) gen object $@ build/tcxflow.tmp.bpf.o

# The skeleton embeds the BPF object and names its programs and maps: meter.c refers to them by
# member, so a renamed map fails the build, not the start of the daemon.
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name tcxflow_bpf > $@

build/meter.o: $(SKEL)

-include $(OBJS:.o=.d)

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------
build/test_unit: tests/test_unit.c tests/test.h $(UNIT_OBJS) $(HEADERS) build/.flags
	$(LINK) $(TCX_CPPFLAGS) $(CPPFLAGS) $< $(UNIT_OBJS) -o $@

build/test_bpf: tests/test_bpf.c tests/test.h $(BPF_TEST_OBJS) $(HEADERS) build/.flags
	$(LINK) $(TCX_CPPFLAGS) $(CPPFLAGS) $< $(BPF_TEST_OBJS) -o $@ $(LDLIBS)

# The BPF program as ordinary C: tests/native comes first, so its bpf/bpf_helpers.h replaces
# libbpf's. The BPF-only pragma and attribute mean nothing here, and the maps libbpf needs as
# global definitions are just that.
NATIVE_FLAGS = -Itests/native $(TCX_CPPFLAGS) $(CPPFLAGS) -Wno-unknown-pragmas -Wno-attributes \
               -Wno-missing-variable-declarations
build/test_bpf_native: tests/test_bpf_native.c tests/test.h src/tcxflow.bpf.c tests/native/bpf/bpf_helpers.h \
                       $(HEADERS) build/.flags
	$(LINK) $(NATIVE_FLAGS) $< -o $@

test: build/test_unit build/test_bpf_native
	build/test_unit
	build/test_bpf_native

test-bpf: build/test_bpf
	build/test_bpf

test-e2e: tcxflow
	tests/e2e.sh

test-all: test test-bpf test-e2e

# ------------------------------------------------------------
# Formatting and static analysis
# ------------------------------------------------------------
FORMAT_SRCS = $(wildcard src/*.c src/*.h tests/*.c tests/*.h)

indent:
	@if command -v $(CLANG_FORMAT) >/dev/null 2>&1; then \
		$(CLANG_FORMAT) -i $(FORMAT_SRCS); \
		echo "Code formatted with clang-format"; \
	else \
		echo "clang-format not found, skipping formatting"; \
	fi

check-indent:
	@$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_SRCS) && echo "Formatting OK"

# One stamp per source: touching a file re-lints just that file, -j$(NJOBS) runs clang-tidy in parallel.
LINT_SRCS   = $(SRCS) tests/test_unit.c tests/test_bpf.c
LINT_STAMPS = $(LINT_SRCS:%.c=.lint/%.stamp) .lint/src/tcxflow.bpf.stamp .lint/tests/test_bpf_native.stamp

lint:
	@if ! command -v $(CLANG_TIDY) >/dev/null 2>&1; then \
		echo "clang-tidy not found"; \
		exit 0; \
	fi; \
	echo "Running clang-tidy analysis (NJOBS=$(NJOBS))..."; \
	$(MAKE) --no-print-directory -s -j$(NJOBS) $(LINT_STAMPS)
	@if command -v $(SHELLCHECK) >/dev/null 2>&1; then \
		$(SHELLCHECK) tests/*.sh && echo "shellcheck OK"; \
	else \
		echo "shellcheck not found, skipping tests/*.sh"; \
	fi

.lint/%.stamp: %.c $(HEADERS) tests/test.h .clang-tidy Makefile
	@mkdir -p $(dir $@)
	@$(CLANG_TIDY) $< --quiet -- $(TCX_CPPFLAGS) $(CPPFLAGS) -std=gnu23
	@touch $@

# On the error path of bpftool's skeleton code, the analyzer takes libbpf (a system header) for not
# freeing what it is handed and reports a leak: that one check is off for meter.c, which uses it.
.lint/src/meter.stamp: src/meter.c $(SKEL) $(HEADERS) .clang-tidy Makefile
	@mkdir -p $(dir $@)
	@$(CLANG_TIDY) $< --quiet --checks=-clang-analyzer-unix.Malloc -- $(TCX_CPPFLAGS) $(CPPFLAGS) -std=gnu23
	@touch $@

# BPF maps and programs need external linkage for libbpf, and the kernel UAPI headers
# have no include-what-you-use mapping: those two checks are off for the BPF program.
.lint/src/tcxflow.bpf.stamp: src/tcxflow.bpf.c src/flow.h .clang-tidy Makefile
	@mkdir -p $(dir $@)
	@$(CLANG_TIDY) $< --quiet --checks=-misc-use-internal-linkage,-misc-include-cleaner -- $(BPF_CFLAGS)
	@touch $@

# The same for the BPF program compiled into its native test.
.lint/tests/test_bpf_native.stamp: tests/test_bpf_native.c tests/native/bpf/bpf_helpers.h src/tcxflow.bpf.c \
                                   $(HEADERS) tests/test.h .clang-tidy Makefile
	@mkdir -p $(dir $@)
	@$(CLANG_TIDY) $< --quiet --checks=-misc-use-internal-linkage,-misc-include-cleaner -- \
		-Itests/native $(TCX_CPPFLAGS) $(CPPFLAGS) -std=gnu23 -Wno-unknown-pragmas -Wno-unknown-attributes
	@touch $@

check: check-indent lint
	@$(MAKE) --no-print-directory dev
	@$(MAKE) --no-print-directory DEV_WARNINGS=1 test

# ------------------------------------------------------------
# Documentation, packaging, installation
# ------------------------------------------------------------
docs:
	@command -v doxygen >/dev/null 2>&1 || { echo "doxygen not found"; exit 1; }
	@doxygen && echo "Doxygen documentation written to docs/html/index.html"

# The committed tree only: no build output, no local files .gitignore hides (rpmbuild -ta takes it as is).
dist:
	@git archive --prefix=tcxflow-$(VERSION)/ -o ../tcxflow-$(VERSION).tar.gz HEAD
	@echo "Distribution package created as ../tcxflow-$(VERSION).tar.gz"

install: tcxflow
	install -D -m 0755 tcxflow $(DESTDIR)$(SBINDIR)/tcxflow
	install -D -m 0644 tcxflow.service $(DESTDIR)$(UNITDIR)/tcxflow.service
	sed -i -e 's|/usr/local/sbin/tcxflow|$(SBINDIR)/tcxflow|' \
		-e 's|/etc/tcxflow/tcxflow.conf|$(SYSCONFDIR)/tcxflow/tcxflow.conf|' $(DESTDIR)$(UNITDIR)/tcxflow.service
	test -e $(DESTDIR)$(SYSCONFDIR)/tcxflow/tcxflow.conf || \
		install -D -m 0644 tcxflow.conf $(DESTDIR)$(SYSCONFDIR)/tcxflow/tcxflow.conf

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/tcxflow $(DESTDIR)$(UNITDIR)/tcxflow.service

clean:
	@-rm -rf build .lint docs tcxflow stage
