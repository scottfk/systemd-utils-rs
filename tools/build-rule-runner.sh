#!/bin/bash
# build-rule-runner.sh - link upstream's test-udev-rule-runner in the C reference build
#
# 20261116 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: tools/build-rule-runner.sh [REFERENCE_DIR]   (default ../systemd)
#
# The reference is configured with -Dtests=false, so the runner's link
# fails for want of test_setup_logging() (libsystemd-tests).  This links
# the runner meson already compiled, with tests/test-setup-logging.c (a
# copy of upstream's function) standing in for that library, as
# REFERENCE_DIR/build/test-udev-rule-runner.

set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
ref=$(cd "${1:-$here/../systemd}" && pwd)
b=$ref/build

ninja -C "$b" test-udev-rule-runner.p/src_udev_test-udev-rule-runner.c.o udevadm >/dev/null
cc -c -O2 -fPIC -o "$b/test-udev-rule-runner.p/test-setup-logging.o" "$here/tests/test-setup-logging.c"
cmd=$(ninja -C "$b" -t commands test-udev-rule-runner | tail -n 1)
case $cmd in
    "cc "*"-o test-udev-rule-runner "*) ;;
    *) echo "unexpected link command: $cmd" >&2; exit 1 ;;
esac
(cd "$b" && eval "$cmd test-udev-rule-runner.p/test-setup-logging.o")
echo "$b/test-udev-rule-runner"
