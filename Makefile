# Makefile - front door for building and testing systemd-utils-rs
#
# 20261115 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261116 - Link libudev.so.1 in the release build; libudev32 target - Claude - scottfk
# 20261116 - reference: also the C test-udev-rule-runner - Claude - scottfk
#
#   make              release build (target/release/, and
#                     target/release/libudev/libudev.so.1)
#   make libudev32    the x86 libudev.so.1 (target/i686-unknown-linux-gnu/release/libudev/)
#   make reference    build the C reference at tools/REFERENCE_TAG into ../systemd
#   make check        build the reference if needed, then run every test
#                     (the differential suites)
#   make clippy       cargo clippy --all-targets -D warnings
#   make fmt          cargo fmt

CARGO     ?= cargo
REFERENCE ?= ../systemd

.PHONY: all build libudev32 reference check test clippy fmt clean

all: build

build:
	$(CARGO) build --release
	CARGO=$(CARGO) tools/link-libudev.sh --release

libudev32:
	CARGO=$(CARGO) tools/link-libudev.sh --release --target i686-unknown-linux-gnu

reference:
	@if [ ! -x $(REFERENCE)/build/systemd-sysctl ]; then tools/build-reference.sh $(REFERENCE); fi
	@if [ ! -x $(REFERENCE)/build/test-udev-rule-runner ]; then tools/build-rule-runner.sh $(REFERENCE); fi

check: reference
	SYSTEMD_REFERENCE=$(abspath $(REFERENCE)) $(CARGO) test

test: check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

clean:
	$(CARGO) clean
