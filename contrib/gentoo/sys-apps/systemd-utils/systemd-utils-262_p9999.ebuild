# Copyright 2022-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2
# 20261120 - Created by Claude (claude.ai, Anthropic) - scottfk

# sys-apps/systemd-utils 262 with every program and library replaced by
# systemd-utils-rs's (a strict-compatibility Rust port, built live from
# git): udevadm (and udevd), systemd-hwdb, systemd-tmpfiles,
# systemd-sysctl, the eight /usr/lib/udev helpers and libudev.so.1 for each
# ABI.  Upstream's v262, configured and installed exactly as
# sys-apps/systemd-utils-262 does it, supplies everything else: rules, hwdb
# sources, man pages, the .link file, headers and pkg-config files.
# libsystemd-shared is not installed: only the C programs linked it.
# systemd-utils-rs ports v262 only; pin it with a package.mask of
# >sys-apps/systemd-utils-262_p9999.  To go back to C:
# emerge -1 =sys-apps/systemd-utils-262 (or -K from a binary package).

EAPI=8

PYTHON_COMPAT=( python3_{11..14} )
QA_PKGCONFIG_VERSION=$(ver_cut 1)

# Avoid QA warnings about these eclasses
TMPFILES_OPTIONAL=1
UDEV_OPTIONAL=1

SYSTEMD_PV="262"
# systemd-utils-rs's Cargo.lock: update together.
CRATES="libc@0.2.191"
RUST_MIN_VER="1.88.0"
# libudev is built for every ABI: Rust needs the matching targets.
RUST_MULTILIB=1

inherit cargo flag-o-matic git-r3 linux-info meson-multilib
inherit python-any-r1 shell-completion toolchain-funcs udev

DESCRIPTION="Utilities split out from systemd for OpenRC users (systemd-utils-rs programs)"
HOMEPAGE="https://github.com/scottfk/systemd-utils-rs https://systemd.io/"

MY_P="systemd-${SYSTEMD_PV}"
EGIT_REPO_URI="https://github.com/scottfk/systemd-utils-rs.git"
SRC_URI="
	https://github.com/systemd/systemd/archive/refs/tags/v${SYSTEMD_PV}.tar.gz -> ${MY_P}.tar.gz
	${CARGO_CRATE_URIS}
"
S="${WORKDIR}/${MY_P}"
# The systemd-utils-rs checkout.
RS="${WORKDIR}/systemd-utils-rs"
EGIT_CHECKOUT_DIR="${RS}"

LICENSE="GPL-2 LGPL-2.1 MIT public-domain"
# Dependent crate licenses
LICENSE+=" || ( Apache-2.0 MIT )"
SLOT="0"
# systemd-utils-rs ports the udev, tmpfiles and sysctl parts, built with
# ACLs and kmod and without SELinux or split-usr (its feature string and
# paths are fixed), so those flags are too.  boot, kernel-install, sysusers
# and ukify are not ported.
IUSE="+sysctl +tmpfiles +udev"
REQUIRED_USE="|| ( tmpfiles sysctl udev )"
# The differential tests need upstream's C build and user namespaces.
RESTRICT="test"

COMMON_DEPEND="
	tmpfiles? ( sys-apps/acl )
	udev? (
		>=sys-apps/util-linux-2.37
		sys-apps/acl
		>=sys-apps/kmod-15
	)
"
DEPEND="${COMMON_DEPEND}
	>=sys-kernel/linux-headers-3.11
"
RDEPEND="${COMMON_DEPEND}
	tmpfiles? ( !<sys-apps/systemd-tmpfiles-250 )
	udev? (
		acct-group/audio
		acct-group/cdrom
		acct-group/dialout
		acct-group/disk
		acct-group/floppy
		acct-group/input
		acct-group/kmem
		acct-group/kvm
		acct-group/lp
		acct-group/render
		acct-group/sgx
		acct-group/tape
		acct-group/tty
		acct-group/usb
		acct-group/video
		!sys-apps/gentoo-systemd-integration
		!<sys-fs/udev-250
		!sys-fs/eudev
	)
	!sys-apps/systemd
"
PDEPEND="
	udev? ( >=sys-fs/udev-init-scripts-34 )
"
BDEPEND="
	app-text/docbook-xml-dtd:4.2
	app-text/docbook-xml-dtd:4.5
	app-text/docbook-xsl-stylesheets
	dev-libs/libxslt
	dev-util/gperf
	>=sys-apps/coreutils-8.16
	sys-devel/gettext
	virtual/pkgconfig
	$(python_gen_any_dep 'dev-python/jinja2[${PYTHON_USEDEP}]')
"

python_check_deps() {
	python_has_version "dev-python/jinja2[${PYTHON_USEDEP}]"
}

CONFIG_CHECK="~BLK_DEV_BSG ~DEVTMPFS ~!IDE ~INOTIFY_USER ~!SYSFS_DEPRECATED
	~!SYSFS_DEPRECATED_V2 ~SIGNALFD ~EPOLL ~FHANDLE ~NET ~UNIX"

pkg_setup() {
	if [[ ${MERGE_TYPE} != buildonly ]] && use udev; then
		linux-info_pkg_setup
	fi
	rust_pkg_setup
	python-any-r1_pkg_setup
}

src_unpack() {
	cargo_src_unpack
	git-r3_src_unpack
}

src_prepare() {
	default
}

src_configure() {
	# Our toolchain sets F_S=2 by default w/ >= -O2, so we need
	# to unset F_S first, then explicitly set 2, to negate any default
	# and anything set by the user if they're choosing 3 (or if they've
	# modified GCC to set 3).
	#
	# malloc_usable_size doesn't play well with _F_S=3:
	#  https://github.com/systemd/systemd/issues/41459 (bug #971773)
	if tc-is-clang && tc-enables-fortify-source ; then
		# We can't unconditionally do this b/c we fortify needs
		# some level of optimisation.
		filter-flags -D_FORTIFY_SOURCE=3
		append-cppflags -U_FORTIFY_SOURCE -D_GENTOO_NO_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	fi

	meson-multilib_src_configure

	pushd "${RS}" >/dev/null || die
	cargo_src_configure
	popd >/dev/null || die
}

multilib_src_configure() {
	# As sys-apps/systemd-utils-262 with USE="acl kmod -boot
	# -kernel-install -selinux -split-usr -sysusers -test -ukify".
	local emesonargs=(
		--auto-features=disabled
		--localstatedir="${EPREFIX}/var"
		-Ddocdir="share/doc/${PF}"

		# default is developer, bug 918671
		-Dmode=release
		-Dlibc=$(usex elibc_musl musl glibc)

		-Dbootloader=disabled
		-Dkernel-install=false
		$(meson_native_enabled man)
		-Dselinux=disabled
		-Dsplit-bin=false
		-Dsysusers=false
		-Dtests=false
		$(meson_native_use_bool tmpfiles)
		$(meson_native_use_feature udev blkid)
		$(meson_native_use_feature udev libmount)
		$(meson_use udev hwdb)
		-Dukify=disabled

		-Dadm-group=false
		-Danalyze=false
		-Dbacklight=false
		-Dbinfmt=false
		-Dcreate-log-dirs=false
		-Dcoredump=false
		-Ddns-over-tls=false
		-Denvironment-d=false
		-Dhibernate=false
		-Dhostnamed=false
		-Didn=false
		-Dima=false
		-Dinitrd=false
		-Dipe=false
		-Dfirstboot=false
		-Dldconfig=false
		-Dlocaled=false
		-Dlogind=false
		-Dmachined=false
		-Dmountfsd=false
		-Dnetworkd=false
		-Dnsresourced=false
		-Dnss-myhostname=false
		-Dnss-systemd=false
		-Doomd=false
		-Dportabled=false
		-Dpstore=false
		-Dquotacheck=false
		-Drandomseed=false
		-Dresolve=false
		-Drfkill=false
		-Dsmack=false
		-Dstoragetm=false
		-Dsysext=false
		-Dsysinstall=false
		-Dtimedated=false
		-Dtimesyncd=false
		-Dtpm=false
		-Durlify=false
		-Duserdb=false
		-Dutmp=false
		-Dvconsole=false
		-Dwheel-group=false
		-Dxdg-autostart=false

		-Dbashcompletiondir=no
		-Ddbus-interfaces-dir=no
		-Drpmmacrosdir=no
		-Dshellprofiledir=no
		-Dsshconfdir=no
		-Dsshdconfdir=no
		-Dsshdprivsepdir=no
		-Dzshcompletiondir=no
	)

	if use tmpfiles || use udev; then
		emesonargs+=( $(meson_native_enabled acl) )
	fi

	if use udev; then
		emesonargs+=( $(meson_native_enabled kmod) )
	fi

	meson_src_configure
}

src_compile() {
	multilib-minimal_src_compile
}

multilib_src_compile() {
	# C as Gentoo builds it: its programs are replaced at install.
	if multilib_is_native_abi; then
		meson_src_compile
	elif use udev; then
		meson_src_compile libudev src/libudev/libudev.pc
	fi

	pushd "${RS}" >/dev/null || die
	if multilib_is_native_abi; then
		cargo_src_compile --workspace --bins
	fi
	if use udev; then
		# libudev.so.1 with upstream's version script, for this ABI.
		local target=()
		multilib_is_native_abi || target=( --target "$(rust_abi)" )
		cargo_env env CARGO="${CARGO:-cargo}" CC="$(tc-getCC)" \
			tools/link-libudev.sh $(usex debug "" --release) "${target[@]}" "${RS}/libudev-${ABI}" || die
	fi
	popd >/dev/null || die
}

src_test() {
	:
}

installx() {
	local dir f
	for f in "$@"; do
		dir="${f%/*}"
		dir="/${dir#/}"
		dodir "${dir}"
		mv -v "${ed}"/${f#/} "${ED}${dir}/" || die
	done
}

# rs_replace <Rust program> <installed path>: put systemd-utils-rs's
# program where meson installed C's.
rs_replace() {
	local src="${RS}/$(cargo_target_dir)/$1" dst="${ED}$2"
	[[ -f ${dst} && ! -L ${dst} ]] || die "C's ${2} is not where it should be"
	install -m 0755 "${src}" "${dst}" || die
}

multilib_src_install() {
	local d="${WORKDIR}/install"
	local ed="${d}${EPREFIX}"

	if use udev; then
		meson_install --tags libudev
		insinto "/usr/$(get_libdir)/pkgconfig"
		doins src/libudev/libudev.pc
		# The library itself: meson's symlinks stay.
		local lib="/usr/$(get_libdir)/libudev.so.1.7.15"
		[[ -f ${ED}${lib} ]] || die "C's ${lib} is not where it should be"
		install -m 0755 "${RS}/libudev-${ABI}/libudev.so.1.7.15" "${ED}${lib}" || die
	fi

	multilib_is_native_abi || return

	meson_install --destdir "${d}"

	# libsystemd-shared is not installed: nothing else links it.
	installx usr/share/locale

	if use sysctl; then
		installx usr/lib/sysctl.d
		installx usr/lib/systemd/systemd-sysctl
		installx usr/share/man/man5/sysctl.d.5
		installx usr/share/man/man8/systemd-sysctl.8
		mv -v "${ed}"/usr/share/man/man8/systemd-sysctl.service.8 \
			"${ED}"/usr/share/man/man8/systemd-sysctl.8 || die
		rs_replace systemd-sysctl /usr/lib/systemd/systemd-sysctl
	fi

	if use tmpfiles; then
		installx usr/bin/systemd-tmpfiles
		installx usr/lib/tmpfiles.d/{etc,home,static-nodes-permissions,var}.conf
		installx usr/share/man/{man5/tmpfiles.d.5,man8/systemd-tmpfiles.8}
		rs_replace systemd-tmpfiles /usr/bin/systemd-tmpfiles
	fi

	if use udev; then
		installx etc/udev
		installx usr/bin/systemd-hwdb
		installx usr/bin/udevadm
		installx usr/lib/systemd/systemd-udevd
		installx usr/lib/systemd/network/99-default.link
		installx usr/lib/udev
		if ! use sysctl; then
			rm "${ED}"/usr/lib/udev/rules.d/99-systemd.rules || die
		fi
		installx usr/share/pkgconfig/udev.pc
		installx usr/share/man/man5/{iocost.conf,systemd.link,udev.conf}.5
		installx usr/share/man/man7/{hwdb,udev}.7
		installx usr/share/man/man8/{systemd-hwdb,udevadm}.8
		mv -v "${ed}"/usr/share/man/man8/systemd-udevd.service.8 \
			"${ED}"/usr/share/man/man8/systemd-udevd.8 || die
		installx usr/share/man/man3/libudev.3 "usr/share/man/man3/udev_*"

		# udevd is a symlink to udevadm, as with C.
		[[ -L ${ED}/usr/lib/systemd/systemd-udevd ]] || die "systemd-udevd is not a symlink"
		rs_replace udevadm /usr/bin/udevadm
		rs_replace systemd-hwdb /usr/bin/systemd-hwdb
		local h
		for h in ata_id cdrom_id dmi_memory_id fido_id iocost mtd_probe scsi_id v4l_id; do
			rs_replace ${h} /usr/lib/udev/${h}
		done
	fi
}

src_install() {
	multilib-minimal_src_install
}

multilib_src_install_all() {
	einstalldocs
	docinto systemd-utils-rs
	dodoc "${RS}"/{README,QUIRKS}.md

	if use tmpfiles; then
		dozshcomp shell-completion/zsh/_systemd-tmpfiles
		insinto /usr/lib/tmpfiles.d
		doins "${FILESDIR}"/{legacy,tmp}.conf
		doinitd "${FILESDIR}"/systemd-tmpfiles-setup
		doinitd "${FILESDIR}"/systemd-tmpfiles-setup-dev
		exeinto /etc/cron.daily
		doexe "${FILESDIR}"/systemd-tmpfiles-clean
	fi

	if use udev; then
		doheader src/libudev/libudev.h
		dobashcomp shell-completion/bash/udevadm
		dozshcomp shell-completion/zsh/_udevadm
		# Avoid udev_dorules to avoid picking up stale udevdir from pkg-config
		insinto /usr/lib/udev/rules.d
		doins "${FILESDIR}"/40-gentoo.rules
	fi

	# Nothing of C's may be left: every installed ELF file is Rust's (rustc's
	# std paths are in each of them, in none of C's).
	local f left=()
	while IFS= read -r -d '' f; do
		[[ $(head -c 4 "${f}") == $'\x7fELF' ]] || continue
		grep -qa '/rustc/' "${f}" || left+=( "${f#${ED}}" )
	done < <(find "${ED}" -type f -print0)
	[[ ${#left[@]} -eq 0 ]] || die "C files not replaced by systemd-utils-rs: ${left[*]}"
}

add_service() {
	local initd=$1
	local runlevel=$2

	ebegin "Adding '${initd}' service to the '${runlevel}' runlevel"
	mkdir -p "${EROOT}/etc/runlevels/${runlevel}" &&
	ln -snf "${EPREFIX}/etc/init.d/${initd}" "${EROOT}/etc/runlevels/${runlevel}/${initd}"
	eend $?
}

pkg_postinst() {
	if [[ -z ${REPLACING_VERSIONS} ]]; then
		add_service systemd-tmpfiles-setup-dev sysinit
		add_service systemd-tmpfiles-setup boot
	fi
	if use udev; then
		udev_hwdb_update
		udev_reload
	fi

	elog "udevadm, udevd, systemd-hwdb, systemd-tmpfiles, systemd-sysctl, the udev"
	elog "helpers and libudev are now systemd-utils-rs's.  Its known differences"
	elog "from C are in ${EROOT}/usr/share/doc/${PF}/systemd-utils-rs/QUIRKS.md*."
	elog "udevd keeps running the old program until it is restarted (or reboot)."
	elog "To go back, emerge the C release: emerge -1 =sys-apps/systemd-utils-${SYSTEMD_PV}"
}
