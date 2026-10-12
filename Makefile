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
#   make dist             source tarball ../tcxflow-VERSION.tar.gz
#   sudo make install     binary, systemd unit and example configuration
#   sudo make uninstall   remove the binary and the systemd unit
#   make clean            remove everything the build created
#
# Variables: DEV_WARNINGS=1 (what `make dev` sets), SANITIZE=address (ASan + UBSan),
# CFLAGS, CPPFLAGS, LDFLAGS (the packager's; tcxflow adds its own flags separately),
# PREFIX, SBINDIR, UNITDIR, SYSCONFDIR, DESTDIR, CC, CLANG, PKG_CONFIG, CLANG_FORMAT, CLANG_TIDY,
# SHELLCHECK, NJOBS.

# The release version without the "v" of its tag (vX.Y.Z), as tarballs and packages use it.
VERSION = $(shell sed -n 's/^\#define TCXFLOW_VERSION "v\([^"]*\)".*/\1/p' src/util.h)

PREFIX     ?= /usr/local
SBINDIR    ?= $(PREFIX)/sbin
UNITDIR    ?= $(PREFIX)/lib/systemd/system
SYSCONFDIR ?= /etc

PKG_CONFIG   ?= pkg-config
CLANG        ?= clang
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
TCX_CFLAGS     = -std=gnu17 -Wall -Wextra
TCX_CPPFLAGS   = -D_GNU_SOURCE -Isrc $(LIBBPF_CFLAGS) -DCONFIG_DEFAULT_PATH=\"$(SYSCONFDIR)/tcxflow/tcxflow.conf\"
LDLIBS         = $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || echo -lbpf)

# BPF: Debian keeps the asm/ headers in a multiarch directory, Fedora and AlmaLinux do not.
MULTIARCH  := $(shell $(CC) -print-multiarch 2>/dev/null)
BPF_CFLAGS  = -O2 -g -Wall -target bpf -mcpu=v3 -Isrc $(LIBBPF_CFLAGS) $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH))

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
              -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection
ifeq ($(CC_IS_CLANG),1)
WARN_FLAGS += -Wcast-align -Wcomma -Wassign-enum -Wunreachable-code-aggressive -Wshorten-64-to-32
else
WARN_FLAGS += -Wcast-align=strict -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wjump-misses-init \
              -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-signedness -Wstringop-overflow=4 \
              -Warray-bounds=2 -Wtrampolines -Wstack-usage=65536 -fanalyzer
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
            src/ipfix.c src/cache.c src/meter.c src/util.c src/vlan.c
HEADERS   = $(wildcard src/*.h)
OBJS      = $(SRCS:src/%.c=build/%.o)
BPF_OBJ   = build/tcxflow.bpf.o
EMBED_OBJ = build/bpfobj.o

# Compiler and linker command lines of all userspace objects and programs.
COMPILE = $(CC) $(TCX_CPPFLAGS) $(CPPFLAGS) $(TCX_CFLAGS) $(CFLAGS) $(SAN_CFLAGS) $(WARN_FLAGS)
LINK    = $(CC) $(TCX_CFLAGS) $(CFLAGS) $(SAN_CFLAGS) $(WARN_FLAGS) $(LDFLAGS) $(SAN_LDFLAGS)

UNIT_OBJS = build/config.o build/collector.o build/control.o build/ipfix.o build/cache.o build/util.o build/vlan.o
BPF_TEST_OBJS = build/meter.o build/util.o $(EMBED_OBJ)

.PHONY: all dev test test-bpf test-e2e test-all indent check-indent lint check docs dist install uninstall clean FORCE

all: tcxflow

dev:
	@$(MAKE) --no-print-directory DEV_WARNINGS=1 tcxflow build/test_unit build/test_bpf

build:
	@mkdir -p build

# Every object depends on the flags it was built with: switching between `make`, `make dev`
# and SANITIZE=address rebuilds everything, instead of linking objects built with other flags.
BUILD_FLAGS = $(COMPILE) / $(LINK) $(LDLIBS) / $(CLANG) $(BPF_CFLAGS)

build/.flags: FORCE | build
	@echo '$(BUILD_FLAGS)' > $@.new; if cmp -s $@.new $@; then rm -f $@.new; else mv -f $@.new $@; fi

tcxflow: $(OBJS) $(EMBED_OBJ)
	$(LINK) $(OBJS) $(EMBED_OBJ) -o $@ $(LDLIBS)

build/%.o: src/%.c build/.flags | build
	$(COMPILE) -MMD -MP -c $< -o $@

$(BPF_OBJ): src/tcxflow.bpf.c src/flow.h build/.flags | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(EMBED_OBJ): src/bpfobj.c src/bpfobj.h $(BPF_OBJ) build/.flags | build
	$(COMPILE) -DBPF_OBJ='"$(BPF_OBJ)"' -c $< -o $@

-include $(OBJS:.o=.d)

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------
build/test_unit: tests/test_unit.c tests/test.h $(UNIT_OBJS) $(HEADERS) build/.flags
	$(LINK) $(TCX_CPPFLAGS) $(CPPFLAGS) $< $(UNIT_OBJS) -o $@

build/test_bpf: tests/test_bpf.c tests/test.h $(BPF_TEST_OBJS) $(HEADERS) build/.flags
	$(LINK) $(TCX_CPPFLAGS) $(CPPFLAGS) $< $(BPF_TEST_OBJS) -o $@ $(LDLIBS)

test: build/test_unit
	build/test_unit

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
LINT_STAMPS = $(LINT_SRCS:%.c=.lint/%.stamp) .lint/src/tcxflow.bpf.stamp

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
	@$(CLANG_TIDY) $< --quiet -- $(TCX_CPPFLAGS) $(CPPFLAGS) -std=gnu17
	@touch $@

# BPF maps and programs need external linkage for libbpf, and the kernel UAPI headers
# have no include-what-you-use mapping: those two checks are off for the BPF program.
.lint/src/tcxflow.bpf.stamp: src/tcxflow.bpf.c src/flow.h .clang-tidy Makefile
	@mkdir -p $(dir $@)
	@$(CLANG_TIDY) $< --quiet --checks=-misc-use-internal-linkage,-misc-include-cleaner -- $(BPF_CFLAGS)
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

dist: clean
	@-rm -f ../tcxflow-$(VERSION).tar.gz
	@cd .. && tar czf tcxflow-$(VERSION).tar.gz \
		--transform='s|^$(notdir $(CURDIR))|tcxflow-$(VERSION)|' \
		--exclude=.git --exclude='*.tar.gz' $(notdir $(CURDIR))
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
