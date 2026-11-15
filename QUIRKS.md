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
