# Security

systemd-utils-rs is a reimplementation of udev, libudev, hwdb, tmpfiles and sysctl. All
of them run as root early in boot: udevd decides who may open every device node, runs
programs from rules for each uevent, and loads kernel modules; tmpfiles creates, chowns,
chmods and deletes files in directories other users can write to (`/tmp`, `/var/tmp`);
sysctl sets kernel parameters. `libudev.so.1` is loaded into many other programs,
including setuid and privileged ones. Security bugs here matter, even though this is a
hobby project.

## Status and supported versions

systemd-utils-rs is pre-release (0.x). There are no maintained release branches: only
the latest `main` gets fixes.

## What counts as a security issue

These are the kinds of bugs I most want to hear about:

- **Device permissions.** A device node, or a symlink to one, ending up with a wrong
  owner, group, mode, ACL (`uaccess`) or security label, even briefly.
- **Filesystem races and link tricks.** Ways for a user who can write to a directory
  that tmpfiles cleans or creates in, or to `/dev`, to make it follow a symlink or hard
  link, or win a race, so it creates, truncates, chowns, chmods or deletes a file it
  shouldn't.
- **Untrusted input.** Crashes, hangs or memory growth from uevents, sysfs attribute
  values, device names, hardware-provided strings (USB, SCSI, ATA, input and DMI ids),
  the udev database, `hwdb.bin`, or config that a package can install. udevd reads
  uevents from the kernel and from other processes; make sure only the kernel's are
  acted on, as upstream does.
- **Command and name injection.** A device property or attribute that ends up in a
  `PROGRAM`/`RUN` command line, a file name or a symlink name in a way C udev wouldn't
  allow (escaping, `..`, `/`).
- **libudev memory safety.** Unsoundness in the C ABI: use-after-free across ref/unref,
  missing NUL terminators, returning pointers that don't live as long as C's do, or
  thread-safety differences.
- **Memory safety elsewhere.** Unsoundness in the `unsafe` code, or anything reachable
  from safe code that causes undefined behavior.
- **Divergence from upstream that weakens security.** For example, a permission check,
  an `O_NOFOLLOW`, a credential check on a socket, or a sandbox step that the C build
  does and systemd-utils-rs skips.

Upstream behavior that is reproduced on purpose will be listed in QUIRKS.md. Reports
about it are still welcome, especially if the impact is worse than described. It will be
fixed as deliberate changes.

If the same bug is also present in **upstream systemd**, please report it to the
[systemd project](https://github.com/systemd/systemd/security) as well. Upstream's fix
is what systemd-utils-rs will follow.

## How to report

For anything that could be exploited, **please don't put the details in a public issue.**
Email them to me instead:

    scone-void-baggage (at) duck (dot) com

(Replace `(at)` with `@` and `(dot)` with `.`, and remove the spaces.)

If you don't get a reply, open an issue on
<https://github.com/scottfk/systemd-utils-rs/issues> that only says you've sent a
security report, without any details.

For low-risk problems, such as hardening suggestions or issues that need root already
(a malicious rule file in `/etc/udev/rules.d`, for instance), a normal public issue is
fine.

Useful things to include:

- The commit you tested.
- The rules or configuration, the device or files involved (owners and modes), and the
  exact steps.
- What happened, and what the C build does at the pinned tag (`tools/REFERENCE_TAG`).

## What to expect

This is a spare-time project, so I can't promise a response time, but I'll acknowledge
security reports as soon as I can, fix confirmed bugs on `main`, and credit you in the
commit unless you'd rather I didn't.
