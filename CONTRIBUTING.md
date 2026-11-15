# Contributing

Thanks for stopping by. This is a personal project, a Rust port of the parts of
[systemd](https://github.com/systemd/systemd) that Gentoo ships as `sys-apps/systemd-utils`
(udev, libudev, hwdb, tmpfiles and sysctl), that I tinker with in my spare time, but
contributions are welcome. Here's how things work.

## What this project is

systemd-utils-rs aims to be a **drop-in replacement** for those C programs and for
`libudev.so.1`. Given the same arguments, configuration, sysfs, uevents and clock, it
should produce the same output, exit status, files, device nodes, symlinks, udev database
and rebroadcast uevents, down to the byte, the owner and the mode. Programs linked against
the C libudev should work unchanged against ours. It is not a redesign: if upstream has
an odd edge case, we copy the odd edge case and list it in QUIRKS.md.

The upstream release we track is pinned in `tools/REFERENCE_TAG`, built the way Gentoo
builds it (see the README). Behavior is checked against a build of that tag, not against
the man pages or against what seems sensible.

The layout follows upstream's sources; the README describes it as it grows.

## What's useful to contribute

- **Behavior differences.** If systemd-utils-rs does something different from the C
  build at the pinned tag, that's a bug. Please send the command, the configuration or
  rules, the device involved (`udevadm info --export-db` and the sysfs attributes help),
  and both outcomes. A new differential test case is even better.
- **libudev ABI problems.** A program that behaves differently against our
  `libudev.so.1` than against the C one, on either ABI.
- **Quirk fixes, as separate changes.** Fixing something listed in QUIRKS.md is welcome,
  but as its own PR that says which quirk it fixes. Ideally it gets fixed upstream too.
- **Reference bumps.** Moving `tools/REFERENCE_TAG` to a newer systemd release, plus the
  fixes needed so the tests pass again.
- **Documentation.** Corrections or additions, especially install notes for other
  distros that ship udev and tmpfiles without systemd.

## What doesn't fit

- **"Improvements" that change behavior quietly.** New rule keys, changed defaults and
  nicer messages belong upstream in systemd first. Once they ship in a tagged release,
  we'll match them.
- **New dependencies** without a strong reason. The only crate is `libc`, and I'd like to
  keep it that way. libacl, libblkid, libkmod and libmount are loaded with `dlopen()`, as
  upstream does.
- **`unsafe` outside the `sys` modules and the libudev C ABI.** If you need a new
  syscall, add a safe wrapper there.

## Building and testing

You need Rust 1.88 or newer (edition 2024) with the `i686-unknown-linux-gnu` standard
library (for the x86 `libudev.so.1`), a C compiler with `-m32` support, and 32-bit glibc.
For the tests you also need the tools to build upstream systemd (`git`, `meson`, `ninja`,
`gperf`, Python with jinja2, and the util-linux, kmod and acl headers), unprivileged user
namespaces, and a subordinate id range of at least 65536 for your user in `/etc/subuid`
and `/etc/subgid` (with `newuidmap`/`newgidmap` from shadow).

```sh
tools/build-reference.sh   # build the C reference at the pinned tag into ../systemd
```

```sh
make            # release build in target/release/
make check      # build the reference if needed, then run every test
make clippy     # cargo clippy --all-targets -D warnings
make fmt        # cargo fmt
```

**Before sending a PR, please make sure `make check`, `make clippy` and `make fmt` are
clean.**

### Differential tests

Most testing is done by running the C reference and systemd-utils-rs side by side on
the same input, the way [cronie-rs](https://github.com/scottfk/cronie-rs) and
[logrotate-rs](https://github.com/scottfk/logrotate-rs) do it:

- Each run is in a private user and mount namespace with real users mapped from your
  subordinate ids, and its own copy of the case's tree: a fake sysfs, `/run`, `/dev`
  and `/etc`.
- The clock comes from an LD_PRELOAD shim where times matter.
- The exit status, stdout, stderr, log messages, and every file left behind (contents,
  owner, mode, ACLs, attributes, times) are compared. libudev is compared by running the
  same C probe against each library.

Anything that needs real hardware or real root (udevd during boot, the `*_id` helpers,
renaming interfaces, loading modules) is tested in a VM, never on the host.

When you fix a difference or change behavior, add cases that cover it, including error
paths and odd input. Unit tests are fine for internal helpers, but a differential test is
what shows the behavior matches.

## Code conventions

- **Port, don't paraphrase.** Each function's doc comment names the upstream function it
  ports (e.g. `` `udev_rules_apply_to_event()` ``). Keep the structure close enough to
  the C that someone can read the two side by side.
- **Bytes, not strings.** Rules, sysfs attribute values, device paths, uevent payloads
  and configuration lines are `Vec<u8>`/`&[u8]`, as they are in C. Don't round-trip
  through `String` where non-UTF-8 input could show up.
- **Mark quirks.** Reproduced upstream bugs get a `QUIRK:` comment in the code and a row
  in QUIRKS.md.
- **Every `unsafe` block gets a `// SAFETY:` comment.** The lints enforce this
  (`undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn`).
- **SPDX headers.** Each source file starts with the SPDX identifier of the upstream file
  it ports (`LGPL-2.1-or-later` or `GPL-2.0-or-later`).
- **US-English spelling** in comments, docs and identifiers, except where a name or
  string must match upstream.
- **Script headers.** Shell scripts, C shims and the Makefile have a changelog comment at
  the top, one line per change: `YYYYMMDD - <description> - <author>`. Please add a line
  when you change one.

## How to submit changes

The repo lives at <https://github.com/scottfk/systemd-utils-rs>.

1. Fork the repo and create a branch.
2. Make your change, with tests.
3. In the PR description, explain **what** changed and **why**. For a behavior fix,
   include the input that showed the difference.
4. If you bumped or tested against a different upstream tag, say which one.

There's no CLA. Contributions are accepted under the project's licenses (see the
README), the same as upstream systemd's for the file you're changing.

## Issues

You can open issues for questions, not just bugs. If something about the build or the
reference setup is confusing, ask. I can't promise a fast response, but I do read them.

## Code of conduct

Be straightforward and respectful. That's the whole policy. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
