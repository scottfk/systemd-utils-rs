# Makefile - front door for building and testing systemd-utils-rs
#
# 20261115 - Created by Claude (claude.ai, Anthropic) - scottfk
#
#   make              release build (target/release/)
#   make reference    build the C reference at tools/REFERENCE_TAG into ../systemd
#   make check        build the reference if needed, then run every test
#                     (the differential suites)
#   make clippy       cargo clippy --all-targets -D warnings
#   make fmt          cargo fmt

CARGO     ?= cargo
REFERENCE ?= ../systemd

.PHONY: all build reference check test clippy fmt clean

all: build

build:
	$(CARGO) build --release

reference:
	@if [ ! -x $(REFERENCE)/build/systemd-sysctl ]; then tools/build-reference.sh $(REFERENCE); fi

check: reference
	SYSTEMD_REFERENCE=$(abspath $(REFERENCE)) $(CARGO) test

test: check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

clean:
	$(CARGO) clean
