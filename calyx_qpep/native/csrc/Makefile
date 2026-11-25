# OpenQPEP Official Release 1.2.8 (v1.2.8) — Native C99 / SIMD SDK Makefile
# Builds shared libopenqpep (.so/.dylib/.dll), static libopenqpep.a, and pkg-config openqpep.pc
# with strict ISO C99 conformance (-Wall -Wextra -Werror -Wpedantic -fvisibility=hidden).

VERSION := 1.2.8
ABI_MAJOR := 1

CC ?= cc
AR ?= ar
RANLIB ?= ranlib
INSTALL ?= install
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

BASE_CFLAGS := -O3 -std=c99 -fPIC -fvisibility=hidden -Iinclude \
	-Wall -Wextra -Werror -Wpedantic -Wstrict-prototypes -Wmissing-prototypes

ifeq ($(PORTABLE),1)
  SIMD_FLAGS :=
else ifeq ($(UNAME_M),x86_64)
  SIMD_FLAGS := -mavx2 -ftree-vectorize
else ifeq ($(UNAME_M),aarch64)
  SIMD_FLAGS := -march=armv8-a -ftree-vectorize
else ifeq ($(UNAME_M),arm64)
  SIMD_FLAGS := -march=armv8-a -ftree-vectorize
else
  SIMD_FLAGS :=
endif

CFLAGS := $(BASE_CFLAGS) $(SIMD_FLAGS)

ifeq ($(UNAME_S),Darwin)
  LIBEXT := dylib
  SHARED_LDFLAGS := -dynamiclib -Wl,-install_name,@rpath/libopenqpep.$(ABI_MAJOR).dylib
else ifneq (,$(findstring MINGW,$(UNAME_S))$(findstring MSYS,$(UNAME_S))$(findstring CYGWIN,$(UNAME_S)))
  LIBEXT := dll
  SHARED_LDFLAGS := -shared
else
  LIBEXT := so
  SHARED_LDFLAGS := -shared -Wl,-soname,libopenqpep.so.$(ABI_MAJOR)
endif

SRCS := ntt_3329.c ntt_8380417.c cbd.c pentad_accel.c keccak_f1600.c poly_ring_c.c plain_lwe_c.c goppa_c.c rank_uov_c.c wire_c.c qhs_c.c
HEADER := include/openqpep.h

BUILD_DIR := build
SHARED_OBJS := $(patsubst %.c,$(BUILD_DIR)/shared/%.o,$(SRCS))
STATIC_OBJS := $(patsubst %.c,$(BUILD_DIR)/static/%.o,$(SRCS))

SHARED_TARGET := ../libopenqpep.$(LIBEXT)
STATIC_TARGET := ../libopenqpep.a
PKGCONFIG_TARGET := ../openqpep.pc

all: shared static pkgconfig

shared: $(SHARED_TARGET)

static: $(STATIC_TARGET)

pkgconfig: $(PKGCONFIG_TARGET)

$(BUILD_DIR)/shared/%.o: %.c $(HEADER)
	@mkdir -p $(BUILD_DIR)/shared
	$(CC) $(CFLAGS) -DOPENQPEP_BUILDING_DLL -c -o $@ $<

$(BUILD_DIR)/static/%.o: %.c $(HEADER)
	@mkdir -p $(BUILD_DIR)/static
	$(CC) $(CFLAGS) -DOPENQPEP_STATIC -c -o $@ $<

$(SHARED_TARGET): $(SHARED_OBJS)
	$(CC) $(SHARED_LDFLAGS) -o $@ $(SHARED_OBJS)
ifeq ($(LIBEXT),so)
	ln -sf libopenqpep.so ../libopenqpep.so.$(ABI_MAJOR)
endif

$(STATIC_TARGET): $(STATIC_OBJS)
	$(AR) rcs $@ $(STATIC_OBJS)
	$(RANLIB) $@

$(PKGCONFIG_TARGET): openqpep.pc.in
	sed \
		-e 's|@PREFIX@|$(PREFIX)|g' \
		-e 's|@LIBDIR@|$(LIBDIR)|g' \
		-e 's|@INCLUDEDIR@|$(INCLUDEDIR)|g' \
		-e 's|@VERSION@|$(VERSION)|g' \
		$< > $@

install: all
	$(INSTALL) -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(PKGCONFIGDIR)
	$(INSTALL) -m 0755 $(SHARED_TARGET) $(DESTDIR)$(LIBDIR)/libopenqpep.$(LIBEXT)
ifeq ($(LIBEXT),so)
	ln -sf libopenqpep.so $(DESTDIR)$(LIBDIR)/libopenqpep.so.$(ABI_MAJOR)
endif
	$(INSTALL) -m 0644 $(STATIC_TARGET) $(DESTDIR)$(LIBDIR)/libopenqpep.a
	$(INSTALL) -m 0644 $(HEADER) $(DESTDIR)$(INCLUDEDIR)/openqpep.h
	$(INSTALL) -m 0644 $(PKGCONFIG_TARGET) $(DESTDIR)$(PKGCONFIGDIR)/openqpep.pc

TEST_BIN_STATIC := $(BUILD_DIR)/test_openqpep_c
TEST_BIN_SHARED := $(BUILD_DIR)/test_openqpep_c_shared
TEST_BIN_SAN    := $(BUILD_DIR)/test_openqpep_c_san
TEST_BIN_SAN_PT := $(BUILD_DIR)/test_openqpep_c_san_portable

SAN_FLAGS := -O1 -g -fno-omit-frame-pointer -std=c99 -Iinclude \
	-Wall -Wextra -Werror -Wpedantic -Wstrict-prototypes -Wmissing-prototypes \
	-fsanitize=address,undefined -fno-sanitize-recover=all -DOPENQPEP_STATIC

test: all
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -DOPENQPEP_STATIC test_openqpep_c.c $(STATIC_TARGET) -o $(TEST_BIN_STATIC)
	./$(TEST_BIN_STATIC)
	$(CC) $(CFLAGS) test_openqpep_c.c -L.. -lopenqpep -Wl,-rpath,'$$ORIGIN/../..' -o $(TEST_BIN_SHARED)
	LD_LIBRARY_PATH=..:$$LD_LIBRARY_PATH ./$(TEST_BIN_SHARED)

test-san:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SAN_FLAGS) $(SIMD_FLAGS) test_openqpep_c.c $(SRCS) -o $(TEST_BIN_SAN)
	./$(TEST_BIN_SAN)

test-san-portable:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SAN_FLAGS) test_openqpep_c.c $(SRCS) -o $(TEST_BIN_SAN_PT)
	./$(TEST_BIN_SAN_PT)

clean:
	rm -rf $(BUILD_DIR) ../libopenqpep.so ../libopenqpep.so.* ../libopenqpep.dylib ../libopenqpep.dll ../libopenqpep.a ../openqpep.pc

.PHONY: all shared static pkgconfig install test test-san test-san-portable clean
