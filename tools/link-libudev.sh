#!/bin/bash
# link-libudev.sh - link libudev.so.1 from the libudev crate's static library
#
# 20261116 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: tools/link-libudev.sh [--target TRIPLE] [--release] [OUTDIR]
#
# Builds the libudev crate (cargo build -p libudev) for TRIPLE (default:
# the host; i686-unknown-linux-gnu for the x86 ABI), then links
# OUTDIR/libudev.so.1.7.15 from it, with the symlinks libudev.so.1 and
# libudev.so, the way upstream's meson does: soname libudev.so.1,
# upstream's version script (crates/libudev/libudev.sym, so every symbol
# carries its LIBUDEV_nnn version) and libgcc linked statically, so the
# library needs nothing but libc (and the dynamic loader, for libgcc's
# unwinder).  rustc can't do this itself: it gives a cdylib its own version
# script, which drops the symbol versions.
#
# OUTDIR defaults to target/[TRIPLE/]{debug,release}/libudev.
#
# CC (default cc), CARGO (default cargo) and LDFLAGS are honored.

set -euo pipefail

top=$(cd "$(dirname "$0")/.." && pwd)
target=
profile=debug
outdir=
while [ $# -gt 0 ]; do
    case $1 in
        --target) target=$2; shift 2 ;;
        --target=*) target=${1#--target=}; shift ;;
        --release) profile=release; shift ;;
        -*) echo "link-libudev.sh: unknown option $1" >&2; exit 2 ;;
        *) outdir=$1; shift ;;
    esac
done

cargo_args=(build -p libudev)
[ "$profile" = release ] && cargo_args+=(--release)
tdir=$top/target
if [ -n "$target" ]; then
    cargo_args+=(--target "$target")
    tdir=$tdir/$target
fi
tdir=$tdir/$profile
"${CARGO:-cargo}" "${cargo_args[@]}" --manifest-path "$top/Cargo.toml"

m=()
case $target in
    i686-*|i586-*) m=(-m32) ;;
esac

outdir=${outdir:-$tdir/libudev}
mkdir -p "$outdir"
# shellcheck disable=SC2086 # LDFLAGS is a list of words
"${CC:-cc}" "${m[@]}" -shared -o "$outdir/libudev.so.1.7.15.tmp" \
    -Wl,--whole-archive "$tdir/libudev.a" -Wl,--no-whole-archive \
    -Wl,--gc-sections -Wl,--as-needed \
    -Wl,--version-script="$top/crates/libudev/libudev.sym" \
    -Wl,-soname,libudev.so.1 -Wl,-z,relro -Wl,-z,now \
    -static-libgcc ${LDFLAGS:-} -lc
mv -f "$outdir/libudev.so.1.7.15.tmp" "$outdir/libudev.so.1.7.15"
ln -sfn libudev.so.1.7.15 "$outdir/libudev.so.1"
ln -sfn libudev.so.1 "$outdir/libudev.so"
echo "$outdir/libudev.so.1.7.15"
