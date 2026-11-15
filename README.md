# systemd-utils-rs

A drop-in port/reimplementation of Gentoo's systemd-utils (udev, libudev, hwdb, tmpfiles and sysctl) in rust. Currently just something fun for me to tinker with in Claude.

## Goals

- **Drop-in compatible with systemd-utils 262** (Gentoo's `sys-apps/systemd-utils`,
  the pieces of systemd that OpenRC systems use), built with USE="acl kmod sysctl
  tmpfiles udev" and `abi_x86_32`:
  - the same programs, options, messages and exit statuses;
  - the same configuration syntax (rules, `.hwdb`, `.link`, `tmpfiles.d`,
    `sysctl.d`, `udev.conf`) and the same on-disk formats (`hwdb.bin`, the
    `/run/udev` database, tags and links);
  - the same devices named, linked, owned and moved at the same events, the same
    uevents broadcast to libudev listeners;
  - the `libudev.so.1` C ABI, symbol versions included, for both x86_64 and x86.

  Upstream quirks are reproduced on purpose and listed in [QUIRKS.md](QUIRKS.md).
  Improvements come later, as deliberate changes.
- **Linux only, OpenRC systems only.** No systemd unit, D-Bus or PID 1 integration
  beyond what systemd-utils itself has.
- **Small and boring:** `libc` as the only crate dependency. Like upstream, nothing
  but libc is linked: libacl, libblkid, libkmod and libmount are `dlopen()`ed when
  they're needed. No async, and `unsafe` confined to `sys` modules (plus the
  `extern "C"` surface of libudev).

## Status

Phase 1 is done: `systemd-sysctl` is ported, along with the shared code the
later phases build on (see the layout below). 330 differential cases match the
C build.

The reference is upstream's tag `v262` (its sources are the same as the release
tarball's), built as Gentoo builds it ([tools/build-reference.sh](tools/build-reference.sh)):

- Gentoo applies no patches to 262 on glibc;
- the ebuild's meson options, `buildtype=plain`, and hydra's CFLAGS/LDFLAGS;
- `../systemd/build` is the x86_64 build, and `../systemd/build32` the x86 build of
  `libudev.so.1` only, as the multilib eclass does it.

The build matches the installed package: the same `--version` feature string, the
same 12 programs, the same exported libudev symbols on both ABIs (92 functions in
6 version nodes, `LIBUDEV_183` to `LIBUDEV_247`) and the same linked libraries.

## Layout

| Path | What |
|---|---|
| `crates/shared` | ports of the `src/basic`, `src/shared` and `src/libsystemd` code the programs use, one module per C file: logging (`log.c`), the 262 option parser and `--help` tables (`options.c`, `verbs.c`, `format-table.c`), `--introspect-cli` JSON (`sd-json.c`), the pager, conf-files and `--cat-config`, `chase.c`, `fileio.c`, path and string helpers.  All `unsafe` is in `sys.rs`. |
| `crates/sysctl` | `systemd-sysctl` (`src/sysctl/sysctl.c`) |
| `tests/common` | the differential harness, shared by every crate's tests |
| `tests/shim` | the LD_PRELOAD clock |
| `tools` | the reference build |

### Known differences

Things the port does differently from C on purpose, because matching them
isn't possible or isn't worth it:

- `SYSTEMD_LOG_LOCATION=1` and the journal's `CODE_FILE=`/`CODE_LINE=`
  name the Rust source, not the C source.
- `detect_container()` isn't ported. In a container, PID 1 and programs
  started with `$SYSTEMD_EXEC_PID` read the kernel command line from
  `/proc/cmdline` rather than from PID 1's argv.
- `sd_pid_get_owner_uid()` (used for the pager's secure mode) only looks for
  a `user-UID.slice` in the process's own cgroup. Without systemd, both find
  no owner.
- `$NOTIFY_SOCKET` doesn't support AF_VSOCK addresses.

## What gets ported

About 44,000 lines of C are specific to these programs. A good part of systemd's
`src/basic`, `src/shared` and `src/libsystemd` (sd-event, sd-netlink, sd-varlink,
the config parsers) is reached from them too. That makes it by far the biggest of the
ports, which is why the roadmap is in small steps.

| Program | Upstream | What it is |
|---|---|---|
| `/usr/lib/systemd/systemd-sysctl` | `src/sysctl` | applies `sysctl.d` (the `sysctl` boot service) |
| `/usr/bin/systemd-tmpfiles` | `src/tmpfiles` | `tmpfiles.d` (`systemd-tmpfiles-setup{,-dev}`, cron.daily clean) |
| `/usr/bin/systemd-hwdb` | `src/hwdb`, `src/shared/hwdb-util.c` | compiles `hwdb.d` into `hwdb.bin` |
| `/usr/lib64/libudev.so.1`, `/usr/lib/libudev.so.1` | `src/libudev`, `sd-device`, `sd-hwdb` | the public C library |
| `/usr/bin/udevadm`, `/usr/lib/systemd/systemd-udevd` | `src/udev` | the daemon (one binary; udevd is a symlink) and its control tool |
| `/usr/lib/udev/{ata,scsi,cdrom,v4l,fido,dmi_memory}_id`, `mtd_probe`, `iocost` | `src/udev/*/` | helpers that rules run |

Data files (rules, hwdb sources, `.link`, `tmpfiles.d`, `sysctl.d`) and Gentoo's
init scripts are installed unchanged.

## Testing

`make check` builds the C reference into `../systemd` if it isn't there,
then runs the test suites (so far, phase 1's differential cases):

1. **Differential tests.** Each case runs the C program and the port on copies of the
   same tree, and compares the exit status, stdout, stderr, what was logged, and every
   file left behind (contents, owners, modes, ACLs, attributes, times).
   - As in [cronie-rs](https://github.com/scottfk/cronie-rs) and
     [logrotate-rs](https://github.com/scottfk/logrotate-rs), each run is in a private
     user and mount namespace with real users mapped from your subordinate ids, and an
     LD_PRELOAD clock (log timestamps now, file ages for `tmpfiles --clean` later).
   - The sandbox mirrors the real paths: the case's `/etc/sysctl.d`, `/run`,
     `/usr/lib/sysctl.d`, `/usr/local/lib` and a fake `/proc/sys` (plain files) are
     bound over the real ones, so messages name the paths a user would see.
   - `/dev/log`, `/dev/kmsg` and the journal socket are captured, so every log target
     is compared; cases can also run on a pty (colors, the pager) or as another user.
   - `SYSTEMD_DIFF_SHOW=1 cargo test -- --nocapture` prints each case's outcome.
   - udev cases run on a fake sysfs (as upstream's own udev tests do) with a private
     `/run/udev` and `/dev`, through `udevadm test`, `udevadm info` and the libudev API
     (a small C probe linked against each `libudev.so.1`).
   - The daemon is driven with synthetic uevents in a network namespace, and what it
     does (nodes, links, database, the uevents it rebroadcasts) is compared.
2. **Upstream's own tests** where they can run against a different binary (the
   `udev-test.pl` rules suite, the tmpfiles shell tests, `test-libudev`).
3. **A VM** (the same VirtualBox testbed as the other ports) for everything that needs
   real hardware, real root, or the real boot: udevd at sysinit, `udevadm trigger` and
   `settle`, the `*_id` helpers on real disks and CD drives, interface renaming,
   kernel modules, and comparing `/dev` and `/run/udev` after C and Rust boots.

## Roadmap

1. **sysctl:** `systemd-sysctl`, along with the shared groundwork: logging, the
   `conf-files` search paths and drop-ins, the `--cat-config` pager output and
   option parsing.
2. **tmpfiles:** every line type and modifier, `--create`/`--clean`/`--remove`/
   `--purge`, `--boot`, `--prefix`/`--exclude-prefix`, `--root`, specifiers, ACLs
   (libacl via `dlopen`), file attributes, and the age-based clean.
3. **hwdb:** the `.hwdb` parser and the `hwdb.bin` writer (`systemd-hwdb` and
   `udevadm hwdb`), and sd-hwdb lookups; the compiled database must be byte-identical.
4. **libudev:** sd-device and sd-device-monitor, the enumerator, the udev database
   reader, and the `libudev.so.1` C ABI for both ABIs, with its version script.
5. **The rules engine:** `udev-rules.c`, formatting and substitutions, `udevadm test`,
   `info`, `verify` and `cat`, node and link handling, the database writer.
6. **udevd:** the manager and workers, the netlink monitor, inotify watches, the
   control socket and varlink, and `udevadm trigger`, `settle`, `control`, `monitor`,
   `wait`, `lock`; boot-tested in the VM.
7. **Builtins and helpers:** `blkid`, `btrfs`, `hwdb`, `input_id`, `keyboard`, `kmod`,
   `net_id`, `net_setup_link` (`.link` files), `path_id`, `uaccess`, `usb_id` and the
   rest, plus the eight helper programs in `/usr/lib/udev`.
8. **Packaging:** a Gentoo ebuild (a `sys-apps/systemd-utils` drop-in), with a VM
   rehearsal and a rollback through a binary package of the C build.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

The same licenses as upstream systemd, file by file. Upstream's sources are
LGPL-2.1-or-later unless they say otherwise, and some of `src/udev` is
GPL-2.0-or-later. So, as upstream explains in its
[LICENSES/README.md](LICENSES/README.md):

- `libudev.so.1`, `systemd-tmpfiles`, `systemd-sysctl` and `systemd-hwdb` are
  **LGPL-2.1-or-later** ([LICENSE.LGPL2.1](LICENSE.LGPL2.1));
- `udevadm`/`systemd-udevd` and the udev helpers are **GPL-2.0-or-later**
  ([LICENSE.GPL2](LICENSE.GPL2)).

Each ported file carries the SPDX identifier of the upstream file it ports. The
`LICENSE.*` files and `LICENSES/` are copied from upstream unchanged.
