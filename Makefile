# AuthentiELF build and test entry points.
#
#   make test                                  lint + unit tests + native e2e
#   make e2e E2E_TARGETS="native aarch64"      end-to-end matrix (test/e2e.sh)
#   make e2e E2E_TARGETS=all STRICT=1          every target; missing tools fail
#   make deps E2E_TARGETS=all                  install toolchains + qemu (Ubuntu 24.04, sudo)
#   make fuzz FUZZTIME=60s
#   make dist VERSION=v1.2.3                   release archives in build/dist (scripts/dist.sh)

GO          ?= go
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_DIR   ?= build
CLI         := $(BUILD_DIR)/authentielf
FUZZTIME    ?= 30s
STRICT      ?= 0
SUDO        ?= sudo
E2E_TARGETS ?= native

ALL_TARGETS := native aarch64 armhf i686 riscv64 s390x ppc64 mips
ifeq ($(E2E_TARGETS),all)
  override E2E_TARGETS := $(ALL_TARGETS)
endif

# Ubuntu 24.04 packages per e2e target.
PKGS_common  := openssl python3 binutils
PKGS_native  := gcc libc6-dev
PKGS_aarch64 := gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user
PKGS_armhf   := gcc-arm-linux-gnueabihf libc6-dev-armhf-cross qemu-user
PKGS_i686    := gcc-i686-linux-gnu libc6-dev-i386-cross qemu-user
PKGS_riscv64 := gcc-riscv64-linux-gnu libc6-dev-riscv64-cross qemu-user
PKGS_s390x   := gcc-s390x-linux-gnu libc6-dev-s390x-cross qemu-user
PKGS_ppc64   := gcc-powerpc64-linux-gnu libc6-dev-ppc64-cross qemu-user
PKGS_mips    := gcc-mips-linux-gnu libc6-dev-mips-cross qemu-user
DEPS := $(sort $(PKGS_common) $(foreach t,$(E2E_TARGETS),$(PKGS_$(t))))

.PHONY: all build test lint unit e2e fuzz dist deps clean

all: build

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(CLI) ./cmd/authentielf

dist:
	GO=$(GO) scripts/dist.sh $(VERSION) $(abspath $(BUILD_DIR))/dist

lint:
	@out=$$(find . -path ./$(BUILD_DIR) -prune -o -name '*.go' -print | xargs gofmt -l); \
		if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

unit:
	$(GO) test -count=1 ./...

e2e: build
	AUTHENTIELF=$(CLI) OUT=$(abspath $(BUILD_DIR))/e2e STRICT=$(STRICT) test/e2e.sh $(E2E_TARGETS)

test: lint unit e2e

# Minimization is capped: by default each new input is minimized for up to
# 60s without visible progress, which would eat a short fuzzing budget.
fuzz:
	$(GO) test -run '^$$' -fuzz FuzzVerify -fuzztime $(FUZZTIME) -fuzzminimizetime 5s .

deps:
	$(SUDO) apt-get update
	$(SUDO) env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(DEPS)

clean:
	$(GO) clean -testcache
	@test -n "$(BUILD_DIR)" && test "$(BUILD_DIR)" != / && rm -rf -- "$(BUILD_DIR)"
