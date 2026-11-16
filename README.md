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

Phases 1 to 5 are done: `systemd-sysctl`, `systemd-tmpfiles`,
`systemd-hwdb` and `libudev.so.1` (both ABIs) are ported, along with the
shared code the later phases build on (see the layout below). 330 sysctl,
893 tmpfiles and 187 hwdb differential cases match the C build, and
compiling the installed `hwdb.d` gives a `hwdb.bin` byte-identical to the C
build's (and to the one installed). libudev exports the same 92 versioned
symbols as C on x86_64 and x86; 102 probe cases match C on each ABI (every
device on the machine, a made-up sysfs and udev database full of edge
cases, the monitor fed crafted netlink messages, hwdb lookups, and the
debug log), and `lsblk`, `findmnt`, `lsusb` and `libinput` print the same
with either library.

Phase 5 ports `udevadm` and the rules engine: `udevadm info`, `test`,
`verify`, `cat` and `hwdb`, and the event with what udevd does to it
(database, tag index, node permissions and symlinks, `RUN`).  525
differential cases match C, among them all of upstream's `test-udev.py`
rule sets that don't need builtins, `verify` and `cat` on the installed
rules, and upstream's rule runner in the destructive mode.  The builtins
(`IMPORT{builtin}`, phase 7) are still to come.

Phase 6 (in progress) ports `systemd-udevd` and `udevadm control`,
`settle`, `monitor`, `trigger`, `wait` and `lock`, on an event loop and a
Varlink implementation in the shared crate.  The daemon runs against C's in
user and network namespaces, fed real kernel uevents of netkit devices: the
logs of the manager and each worker, `/run/udev` and the clients' output
match C, through queueing and blocking, workers that fail, time out or get
killed, `udevadm control` settings, reloads, signals and interface renames;
and each Rust client matches C's against a C udevd.  The boot test in the
VM is still to do.

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
| `crates/shared` | ports of the `src/basic`, `src/shared` and `src/libsystemd` code the programs use, one module per C file: logging (`log.c`), the 262 option parser and `--help` tables (`options.c`, `verbs.c`, `format-table.c`), `--introspect-cli` JSON (`sd-json.c`), the pager, conf-files and `--cat-config`, `chase.c`, `fileio.c`, path and string helpers; for tmpfiles also specifiers, `sd-path`, ACLs (`acl-util.c`, libacl `dlopen()`ed), xattrs, `chattr`, btrfs subvolumes and qgroups, `rm-rf.c`, `copy.c`, capabilities and credentials.  All `unsafe` is in `sys.rs` (and the libacl calls in `sys_acl.rs`). |
| `crates/sysctl` | `systemd-sysctl` (`src/sysctl/sysctl.c`) |
| `crates/tmpfiles` | `systemd-tmpfiles` (`src/tmpfiles/tmpfiles.c`, `offline-passwd.c`) |
| `crates/hwdb` | `systemd-hwdb` (`src/hwdb/hwdb.c`); the compiler and sd-hwdb are `shared::hwdb` (`hwdb-util.c`, `sd-hwdb.c`, `strbuf.c`), for udevadm and libudev later |
| `crates/udevadm` | `udevadm` (`src/udev/udevadm*.c`): `info`, `test`, `verify`, `cat` and the deprecated `hwdb`; `control`, `settle`, `monitor`, `trigger`, `wait` and `lock`; `test-builtin` (phase 7) has its option table (for `--help` and `--introspect-cli`) but fails "not ported yet".  Invoked as `systemd-udevd`, it is the daemon (`src/udevd/`).  The engine (`src/udev/udev-*.c`) is the library: the rules parser and the matching and assignment of every key, the `%`/`$` substitutions, `PROGRAM`/`IMPORT{program}`/`RUN` execution, the event (with the destructive steps udevd takes: the database and tag index, attribute and sysctl writes, device node permissions and the `/dev` symlink stacks), `OPTIONS="dump"`.  The builtins are a table only (phase 7).  `src/bin/test-udev-rule-runner.rs` is upstream's rule runner, for the tests. |
| `crates/libudev` | `libudev.so.1` (`src/libudev`): the C ABI over `shared::sd_device` (`sd-device.c`, `device-private.c`, `device-util.c`), `shared::device_enumerator`, `shared::device_monitor` (with its BPF filter) and `shared::device_filter`; the netlink calls are in `shared::sys_net`, the RTM_GETLINK lookup in `shared::netlink`.  Built as a static library and linked by `tools/link-libudev.sh` with upstream's version script. |
| `tests/common` | the differential harness, shared by every crate's tests |
| `tests/shim` | the LD_PRELOAD clock |
| `tools` | the reference build, and the libudev link step |

### Known differences

Things the port does differently from C on purpose, because matching them
isn't possible or isn't worth it:

- `SYSTEMD_LOG_LOCATION=1` and the journal's `CODE_FILE=`/`CODE_LINE=`
  name the Rust source, not the C source.
- `sd_pid_get_owner_uid()` (used for the pager's secure mode) only looks for
  a `user-UID.slice` in the process's own cgroup. Without systemd, both find
  no owner.
- `$NOTIFY_SOCKET` doesn't support AF_VSOCK addresses.
- `systemd-tmpfiles --image=` isn't supported: it fails with "Operating on
  disk image '…' is not supported." (after the same argument checks as C), and
  `--image-policy=` is accepted without being parsed. Use `--root=` on a
  mounted image instead.
- tmpfiles handles the items below a path (for `--remove`, `--clean` and
  `--purge`) in the order they were read. C keeps them in a hash set whose order
  changes from run to run, so this is one of the orders C uses.
- tmpfiles' `C` lines copy with `copy.c`'s behavior for what tmpfiles asks for
  (merging, hard links, `user.*` xattrs, owners, modes and times), not all of
  `copy.c`; and `inode_same_at()` compares `fstat()` results where C compares
  file handles, which gives the same answers.
- libudev: C keeps tags, devlinks, sysattr names and child devices in hash
  sets whose order changes from run to run (and with it the order of the
  words in `TAGS=`, `CURRENT_TAGS=` and `DEVLINKS=`); the port keeps them
  sorted, which is one of the orders C uses. The lists libudev hands out are
  sorted by name either way.
- libudev: `udev_list_entry_get_by_name()` with a NULL name crashes in C (it
  hashes the NULL); the port returns NULL.
- libudev.so.1 is bigger (656 KB stripped, against 421 KB) and, besides
  libc, needs the dynamic loader (`ld-linux-x86-64.so.2`/`ld-linux.so.2`),
  for the unwinder of the statically linked libgcc. rustc can't link a
  library with symbol versions, so `tools/link-libudev.sh` links it from the
  static library with `cc`.
- udevadm: C keeps the attributes and sysctls an event writes (shown by
  `udevadm test` and `OPTIONS="dump"`) in hash maps whose order changes
  from run to run; the port lists them in the order they were written.  For
  the same reason, the trace lines of `SYMLINK==` and `TAG==` (one per
  link or tag tried until one matches) come in sorted order.
- udevadm: without systemd there is nothing to ask about a unit's
  `SysFSPath=`, so `udevadm info dev-sda.device` takes the device from the
  unit name, as C does when it can't connect (C would ask systemd over
  D-Bus if it ran).  Likewise, users and groups are looked up in NSS (and
  the intrinsic `root` and `nobody`, numeric ids, and the foreign range):
  there are no userdb services to ask, and JSON user records in `userdb/`
  directories are not read.
- udevadm: callouts (`PROGRAM="ata_id ..."`) are not looked for in a build
  directory first (C does that when it runs from its meson build tree);
  `$ATA_ID_PATH` and friends are honored.
- udevadm: `SECLABEL{selinux}` and `SECLABEL{smack}` are accepted and
  logged as set, as in C built without SELinux and SMACK.
- udevadm: interface names are always sanitized as the naming schemes with
  `NAMING_REPLACE_STRICTLY` (all of them since v247) do; `net.naming_scheme=`
  is ignored until `net_id` is ported (phase 7).
- udevd: there is no service manager file descriptor store, so the inotify
  fd, the `udevadm control` settings and queued events are not pushed to
  one on exit (C only does with `$NOTIFY_SOCKET`); fds passed in
  `$LISTEN_FDS` are taken as in C.
- udevd: events are dropped from the queue as soon as they are processed
  (C keeps them while later events reference them as blockers; the
  blocker search starts at the same place), and workers are picked for
  events in the order they were spawned (C iterates a hash map).
- udevd: without libblkid, the partition table of a whole disk whose node
  was closed after writing is reread with `BLKRRPART` (C's path without
  libblkid); C with libblkid adds, resizes and removes GPT partitions one
  by one.  This comes with the `blkid` builtin (phase 7).
- The event loop fires timers at their time (sd-event coalesces them within
  their accuracy), and the Varlink server answers each method before the
  handler returns (no deferred replies, "more" or "upgrade" calls, and
  `GetInterfaceDescription` answers `MethodNotImplemented`).
- `udevadm lock --backing=` on btrfs, whose files have no block device
  number, fails with "Block device required" (C asks btrfs).
- sd-hwdb reads `hwdb.bin` into memory where C maps it; and a lookup whose
  pattern is longer than `LINE_MAX` (2048 bytes, far beyond any real hwdb
  entry) stops matching where C's buffer arithmetic would go wrong.

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
then runs the test suites (so far, the differential cases of phases 1 to 6):

1. **Differential tests.** Each case runs the C program and the port on copies of the
   same tree, and compares the exit status, stdout, stderr, what was logged, and every
   file left behind (contents, owners, modes, ACLs, attributes, times).
   - As in [cronie-rs](https://github.com/scottfk/cronie-rs) and
     [logrotate-rs](https://github.com/scottfk/logrotate-rs), each run is in a private
     user and mount namespace with real users mapped from your subordinate ids, and an
     LD_PRELOAD clock (log timestamps, and the file ages for `tmpfiles --clean`).
   - The sandbox mirrors the real paths: the case's `/etc/sysctl.d`, `/run`,
     `/usr/lib/sysctl.d`, `/usr/local/lib` and a fake `/proc/sys` (plain files) are
     bound over the real ones, so messages name the paths a user would see.
   - `/dev/log`, `/dev/kmsg` and the journal socket are captured, so every log target
     is compared; cases can also run on a pty (colors, the pager) or as another user.
   - tmpfiles cases run on a root of the sandbox's own (a tmpfs `/` with the system
     directories bound in), because the real `/` belongs to a user the sandbox can't
     map, and `CHASE_SAFE` refuses that transition. They also compare xattrs, ACLs,
     file capabilities, `lsattr` flags, link counts and timestamps, and hydra's btrfs
     root means `v`, `q` and `Q` lines make real subvolumes.
   - Binary files (such as `hwdb.bin`) are compared by size and SHA-256. A case can
     also run a shell script in which the program's name runs the implementation
     under test, e.g. `systemd-hwdb update && systemd-hwdb query …`, so each
     build reads what it wrote.
   - `SYSTEMD_DIFF_SHOW=1 cargo test -- --nocapture` prints each case's outcome.
   - libudev cases run `tests/probe.c`, a small C program that makes libudev calls
     from its command line and prints every result (and errno), built four times:
     against each `libudev.so.1` (by rpath), for x86_64 and x86. They read the real
     sysfs and `/run/udev`, or a made-up sysfs and udev database bound over them
     (`SYSTEMD_DEVICE_VERIFY_SYSFS=0` lets sd-device accept it); monitor cases run
     in a network namespace of their own, where the probe can broadcast crafted
     uevents. Real programs (`lsblk`, `lsusb`, ...) run against each library through
     `LD_LIBRARY_PATH`, and the exported symbols and versions are compared.
   - udevadm cases run on upstream's fake sysfs (`test/sys-script.py`, bound
     over `/sys`) with a private `/run` and rules trees: all of upstream's
     `test-udev.py` rule sets (except the two that need builtins) through
     `udevadm test`, with and without `-v`, extracted by
     `tools/udev-test-rules.py`; rules files with every check of `verify`;
     `info` on a made-up database.  The destructive event mode udevd uses
     runs through upstream's `test-udev-rule-runner`
     (`tools/build-rule-runner.sh` links it in the reference build) and its
     port, on devices without device nodes (the sandbox can't make those),
     comparing the database, tag index, written attributes and what the
     `RUN` programs did.  Output that varies even between two C runs is
     normalized: hash-ordered sets (devlinks, tags, written attributes),
     `USEC_INITIALIZED` of devices without a database entry, the CPU's APIC
     id; and until phase 7, the builtins' init and exit logging.
   - udevd runs in a user and network namespace of its own, with sysfs
     remounted for it and an empty `/run`; netkit devices created there (and
     writes to their `uevent` files) give real kernel uevents
     (`crates/udevadm/tests/diff_udevd.rs`).  The debug log is split by
     process (`SYSTEMD_LOG_TID=1`) and compared per process, with pids,
     seqnums and fd numbers normalized; the client output and `/run/udev`
     are compared too.  The clients run once each against a C udevd.
2. **Upstream's own tests** where they can run against a different binary (the
   `udev-test.pl` rules suite, the tmpfiles shell tests, `test-libudev`).
3. **A VM** (the same VirtualBox testbed as the other ports) for everything that needs
   real hardware, real root, or the real boot: udevd at sysinit, `udevadm trigger` and
   `settle`, the `*_id` helpers on real disks and CD drives, interface renaming,
   kernel modules, and comparing `/dev` and `/run/udev` after C and Rust boots.

## Roadmap

1. **sysctl (done, branch `phase1-sysctl`):** `systemd-sysctl`, along with the shared groundwork: logging, the
   `conf-files` search paths and drop-ins, the `--cat-config` pager output and
   option parsing.
2. **tmpfiles (done, branch `phase2-tmpfiles`):** every line type and modifier, `--create`/`--clean`/`--remove`/
   `--purge`, `--boot`, `--prefix`/`--exclude-prefix`, `--root`, specifiers, ACLs
   (libacl via `dlopen`), file attributes, and the age-based clean.
3. **hwdb (done, branch `phase3-hwdb`):** the `.hwdb` parser and the `hwdb.bin` writer (`systemd-hwdb` and
   `udevadm hwdb`), and sd-hwdb lookups; the compiled database must be byte-identical.
4. **libudev (done, branch `phase4-libudev`):** sd-device and sd-device-monitor, the enumerator, the udev database
   reader, and the `libudev.so.1` C ABI for both ABIs, with its version script.
5. **The rules engine (done, branch `phase5-rules`):** `udev-rules.c`, formatting and substitutions, `udevadm test`,
   `info`, `verify` and `cat`, node and link handling, the database writer.
   Node and link handling still has to be tested in the VM (phase 6).
6. **udevd (in progress, branch `phase6-udevd`):** the manager and workers, the netlink monitor, inotify watches,
   varlink, interface renaming, and `udevadm trigger`, `settle`, `control`, `monitor`,
   `wait`, `lock` (done); boot-tested in the VM (next).
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
