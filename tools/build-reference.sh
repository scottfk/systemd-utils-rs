#!/bin/bash
# build-reference.sh - build upstream C systemd-utils at the pinned tag, for the differential tests
#
# 20261115 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: tools/build-reference.sh [DIR]
#
# DIR defaults to ../systemd (next to this checkout), which is where the
# tests will look (override with SYSTEMD_REFERENCE=/path/to/systemd).
# Builds the way Gentoo's sys-apps/systemd-utils-262 does with hydra's
# USE="acl kmod sysctl tmpfiles udev" (-boot -kernel-install -selinux
# -split-usr -sysusers -test -ukify) and abi_x86_32:
#
#   DIR/build    the native (x86_64) build: every program and libudev
#   DIR/build32  the x86 build: libudev.so.1 only, as multilib does it
#
# Same meson options, buildtype=plain, and CFLAGS/LDFLAGS default to
# hydra's make.conf values. Two deliberate differences, neither of which
# changes a compiled file: man pages are off (they need the docbook
# stylesheets and take minutes), and nothing is installed.
# Gentoo applies no patches to 262 on glibc.

set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-$here/../systemd}
tag=$(cat "$here/tools/REFERENCE_TAG")
url=https://github.com/systemd/systemd.git

: "${CFLAGS:=-O3 -pipe -march=native}"
: "${LDFLAGS:=-Wl,-O1 -Wl,--as-needed -Wl,-z,pack-relative-relocs}"
export CFLAGS LDFLAGS

if [[ ! -d $dir/.git ]]; then
	git clone --branch "$tag" --single-branch "$url" "$dir"
fi
cd "$dir"
if [[ $(git describe --tags --exact-match 2>/dev/null || true) != "$tag" ]]; then
	git fetch --tags origin
	git checkout -q "$tag"
fi

# The options every ABI gets: the ebuild's multilib_src_configure, with
# meson.eclass's own (prefix, libdir, b_pch, werror, buildtype).
common=(
	--prefix=/usr --sysconfdir=/etc --localstatedir=/var
	--wrap-mode=nodownload -Db_pch=false -Dwerror=false -Dbuildtype=plain
	--auto-features=disabled
	-Ddocdir=share/doc/systemd-utils-262
	-Dmode=release -Dlibc=glibc
	-Dsplit-bin=false -Dtests=false -Dhwdb=true

	-Dadm-group=false -Danalyze=false -Dbacklight=false -Dbinfmt=false
	-Dcreate-log-dirs=false -Dcoredump=false -Ddns-over-tls=false
	-Denvironment-d=false -Dhibernate=false -Dhostnamed=false -Didn=false
	-Dima=false -Dinitrd=false -Dipe=false -Dfirstboot=false -Dldconfig=false
	-Dlocaled=false -Dlogind=false -Dmachined=false -Dmountfsd=false
	-Dnetworkd=false -Dnsresourced=false -Dnss-myhostname=false
	-Dnss-systemd=false -Doomd=false -Dportabled=false -Dpstore=false
	-Dquotacheck=false -Drandomseed=false -Dresolve=false -Drfkill=false
	-Dsmack=false -Dstoragetm=false -Dsysext=false -Dsysinstall=false
	-Dtimedated=false -Dtimesyncd=false -Dtpm=false -Durlify=false
	-Duserdb=false -Dutmp=false -Dvconsole=false -Dwheel-group=false
	-Dxdg-autostart=false

	-Dbashcompletiondir=no -Ddbus-interfaces-dir=no -Drpmmacrosdir=no
	-Dshellprofiledir=no -Dsshconfdir=no -Dsshdconfdir=no
	-Dsshdprivsepdir=no -Dzshcompletiondir=no
)

if [[ ! -f build/build.ninja ]]; then
	meson setup build "${common[@]}" --libdir=lib64 \
		-Dbootloader=disabled -Dkernel-install=false -Dman=disabled \
		-Dselinux=disabled -Dsysusers=false -Dtmpfiles=true \
		-Dblkid=enabled -Dlibmount=enabled -Dukify=disabled \
		-Dacl=enabled -Dkmod=enabled
fi
meson compile -C build

# The x86 ABI, as meson-multilib builds it: a cross file for gcc -m32, the
# native-only features off, and only the libudev targets compiled.
if [[ ! -f build32/build.ninja ]]; then
	cross=$dir/build32.cross
	cat > "$cross" <<-EOF
	[binaries]
	c = ['gcc', '-m32']
	cpp = ['g++', '-m32']
	pkg-config = 'pkg-config'

	[properties]
	pkg_config_libdir = '/usr/lib/pkgconfig:/usr/share/pkgconfig'

	[host_machine]
	system = 'linux'
	cpu_family = 'x86'
	cpu = 'i686'
	endian = 'little'
	EOF
	meson setup build32 "${common[@]}" --libdir=lib --cross-file "$cross" \
		-Dbootloader=disabled -Dkernel-install=false -Dman=disabled \
		-Dselinux=disabled -Dsysusers=false -Dtmpfiles=false \
		-Dblkid=disabled -Dlibmount=disabled -Dukify=disabled \
		-Dacl=disabled -Dkmod=disabled
fi
meson compile -C build32 libudev src/libudev/libudev.pc

echo "reference: $(pwd) (udevadm $(build/udevadm --version); x86 $(file -bL build32/libudev.so.1 | cut -d, -f1-2))"
