# Upstream quirks, kept on purpose

systemd-utils-rs reproduces systemd-utils **262**, as Gentoo builds it, exactly,
including behavior that looks like a bug. Each item here is marked `QUIRK` in the source.
Fixing one is a deliberate, separate change (ideally upstream as well), not something to
slip into the port.

Severity: **high** means it can expose a device or a file to the wrong user, delete or
clobber the wrong file, or leave the system without a working `/dev`; **medium** means
it's surprising and user-visible; **low** means it's cosmetic or hard to hit.

## systemd-sysctl

| Severity | Quirk |
|---|---|
| medium | With `--save=`, the result of saving replaces the result of parsing the files given, so a file that couldn't be read (or another parse error) no longer makes the run fail if saving works. Without `--save=` the same error gives exit status 1. |

## systemd-tmpfiles

| Severity | Quirk |
|---|---|
| low | While cleaning a directory (`dir_cleanup()`), the result is overwritten by every entry's `statx()`, so a failure to remove an earlier entry (logged as a warning) only makes the run fail if it happens on the last entry looked at. |
| low | `btrfs_subvol_get_parent()` (used by `q` and `Q` lines when quotas are on) doesn't advance its search between rounds, so a tree search that returns items but no match would repeat forever. The kernel always returns the backref it looks for, so it doesn't happen in practice. |

## systemd-hwdb

| Severity | Quirk |
|---|---|
| medium | `--strict` doesn't make `update` fail on parse errors (malformed records and properties are only warnings); only a file that can't be read does. |
| low | A `#` anywhere in a line starts a comment, also inside a property value: ` KEY=a#b` sets `KEY=a`. |
| low | `query` is silent about a missing or unreadable database (exit status 1) and about a corrupt one (exit status 0, no properties). |

## libudev (sd-device)

| Severity | Quirk |
|---|---|
| medium | `udev_device_new_from_environment()` splits each `KEY=value` of the environment in place, writing a NUL over the `=` and leaving it there: after the call, those variables are gone from the process environment (`getenv("TZ")` no longer finds `TZ`), and a second call fails ("Not a key-value pair"). |
| low | The udev database reader drops a last line that has no newline, and an empty value (`E:` followed by a newline) takes in the next line as its value. |
| low | The enumerator's rule that a sound card's `controlC` device sorts after its other devices never applies: it looks for the `/` from the start of the devpath instead of after `/sound/card`. |
| low | `udev_monitor_filter_add_match_subsystem_devtype()` adds a filter on every call, the same subsystem and devtype again included (the filters are keyed by pointer), so the BPF program grows each time. |
| low | `udev_device_new_from_devnum()` with a type other than `b` or `c` logs (at debug level) the macro expansion of `IN_SET(type, 'b', 'c')` as the failed assertion's text, since `assert_return()` stringifies its argument after expansion. |

## udevadm and the rules engine

| Severity | Quirk |
|---|---|
| low | The labels and commands an event queues are kept in maps keyed by the strings' addresses, so nothing is ever a duplicate: `RUN+="x"` twice runs `x` twice, and `SECLABEL{selinux}+=` twice keeps both labels (applied in order, the last one wins). |
| low | One invalid key in a rule line drops the whole line, the valid keys before it included. |
| low | When `IMPORT{file}` or `IMPORT{program}` can't parse a line, the debug message shows the line as the parser left it: cut at the `=` and with the key's trailing whitespace removed (`FOO="x'` is logged as `FOO`). |

## The udev helpers

| Severity | Quirk |
|---|---|
| low | `dmi_memory_id` prints a voltage that is a multiple of 100 mV with `%.1g`, one significant digit, so 1.2 V is `MEMORY_DEVICE_0_CONFIGURED_VOLTAGE=1` and 1.5 V is `2` (other voltages use `%g`: 1.35 V is `1.35`). |
| low | `cdrom_id` counts each failed open of a busy (`EBUSY`) drive twice, so it gives up after 11 tries (one to two seconds of waiting) rather than the 20 the loop is written for. |
