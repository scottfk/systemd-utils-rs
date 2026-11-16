// SPDX-License-Identifier: GPL-2.0-or-later
//! Differential tests for systemd-udevd: each scenario runs the C and the
//! Rust daemon in a fresh user, mount and network namespace, with sysfs
//! remounted for that network namespace, an empty tmpfs on /run and no
//! rules but the scenario's own.  Kernel uevents come from netkit devices
//! created in the namespace (`ip link add ... type netkit`) and from
//! writes to their `uevent` files.  The same (C) udevadm is the client in
//! both runs, so only the daemon differs.
//!
//! Compared: the client output, the files under /run/udev, and the
//! daemon's debug log split by process (`SYSTEMD_LOG_TID=1`): the
//! manager's lines, then each worker's, with pids, seqnums, fd numbers and
//! socket names normalized.  Scenarios run the workers one at a time
//! (`-c 1`) or with the exec queue stopped while uevents arrive, so the
//! order of each process's lines is deterministic.
//!
//! Skipped (with a message) when the namespaces or netkit are unavailable.

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use common::{reference_build, repo_dir};

fn c_udevadm() -> PathBuf {
    reference_build().join("udevadm")
}

fn rust_udevadm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_udevadm"))
}

fn work_dir() -> PathBuf {
    let d = repo_dir().join("target/difftest/udevd");
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Sets up the sandbox, then sources the scenario.  $D is the daemon,
/// $U the client.
const PRELUDE: &str = r#"set -u
mount -t tmpfs tmpfs /run
mount -t sysfs sysfs /sys
mkdir -p /run/empty /run/udev/rules.d
mount --bind /run/empty /usr/lib/udev/rules.d
[ -d /etc/udev/rules.d ] && mount --bind /run/empty /etc/udev/rules.d
[ -d /lib/udev/rules.d ] && [ ! -L /lib ] && mount --bind /run/empty /lib/udev/rules.d
[ -e /etc/udev/udev.conf ] && mount --bind /run/empty/../empty /etc/udev/udev.conf 2>/dev/null
ln -s "$D" /run/systemd-udevd
export SYSTEMD_LOG_TID=1 SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC=${SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC:-10}
start() {
    SYSTEMD_LOG_LEVEL=debug /run/systemd-udevd "$@" 2>>/run/d.log &
    echo $! > /run/d.pid
    i=0
    while [ ! -S /run/udev/io.systemd.Udev ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done
}
stop() {
    # Workers that exited must have been reaped.
    echo "zombies=$(ps --ppid "$(cat /run/d.pid)" -o stat= | grep -c '^Z')"
    "$U" control --exit; echo "exit=$?"
    pid=$(cat /run/d.pid)
    wait "$pid"; echo "udevd=$?"
}
settle() { "$U" settle -t 20; echo "settle=$?"; }
info() { "$U" info "$@" | grep -v '^E: USEC_INITIALIZED='; }
link() { ip link add "$1" type netkit peer name "$2"; }
link2() { ip link add "$1" type netkit mode l2 peer name "$2"; }
quiet() { sleep 0.4; }
"#;

const EPILOGUE: &str = r#"
echo "== state"
cd /run/udev && find . -mindepth 1 ! -name 'io.systemd.Udev' | sort
for f in /run/udev/data/*; do [ -f "$f" ] && { echo "-- $f"; grep -v '^I:' "$f"; }; done
echo "== log"
cat /run/d.log
"#;

/// Whether the sandbox works here.
fn available() -> bool {
    static A: OnceLock<bool> = OnceLock::new();
    *A.get_or_init(|| {
        let ok = Command::new("unshare")
            .args(["-Urnm", "--propagation", "private", "sh", "-c"])
            .arg("mount -t sysfs sysfs /sys && ip link add x0 type netkit peer name x1")
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("diff_udevd: no user/net namespaces or no netkit here, skipping");
        }
        ok
    })
}

fn run(daemon: &PathBuf, label: &str, name: &str, script: &str, env: &[(&str, &str)]) -> String {
    let path = work_dir().join(format!("{name}.{label}.sh"));
    std::fs::write(&path, format!("{PRELUDE}\n{script}\n{EPILOGUE}")).unwrap();
    let mut cmd = Command::new("timeout");
    cmd.args(["120", "unshare", "-Urnm", "--propagation", "private", "sh"])
        .arg(&path)
        .env("D", daemon)
        .env("U", c_udevadm())
        .env_remove("SYSTEMD_LOG_LEVEL")
        .env_remove("NOTIFY_SOCKET");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let o = cmd.output().unwrap();
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    s
}

/// Lines that depend on the sandbox rather than the program: the process
/// title (which depends on the environment's size) and the container
/// detection.
fn is_masked(line: &str) -> bool {
    const PREFIXES: &[&str] =
        &["PR_SET_MM_ARG_START failed", "Failed to read $container of PID 1", "Found container virtualization"];
    PREFIXES.iter().any(|p| line.starts_with(p))
}

/// Replaces every decimal number following `marker` with `with`.
fn replace_num(s: &str, marker: &str, with: &dyn Fn(u64) -> String) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(marker) {
        out.push_str(&rest[..i + marker.len()]);
        rest = &rest[i + marker.len()..];
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            continue;
        }
        out.push_str(&with(rest[..n].parse().unwrap()));
        rest = &rest[n..];
    }
    out.push_str(rest);
    out
}

/// Normalizes a run's output: the log is split by process.
fn normalize(raw: &str) -> String {
    let (head, log) = raw.split_once("== log\n").unwrap_or((raw, ""));
    // Seqnums are the kernel's global counter, which other uevents on the
    // host advance too: number them by rank.
    let mut seqnums: Vec<u64> = Vec::new();
    for l in raw.lines() {
        for m in ["SEQNUM=", "seqnum="] {
            let mut rest = l;
            while let Some(i) = rest.find(m) {
                rest = &rest[i + m.len()..];
                let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(v) = n.parse::<u64>() {
                    seqnums.push(v);
                }
            }
        }
    }
    seqnums.sort_unstable();
    seqnums.dedup();
    let mut roles: BTreeMap<u64, String> = BTreeMap::new();
    let mut order: Vec<u64> = Vec::new();
    let mut streams: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut n_workers = 0;
    let mut n_other = 0;
    for l in log.lines() {
        let (pid, text) = match l.strip_prefix('(').and_then(|r| r.split_once(") ")) {
            Some((p, t)) if p.bytes().all(|c| c.is_ascii_digit()) => (p.parse::<u64>().unwrap(), t),
            _ => (0, l),
        };
        if !roles.contains_key(&pid) {
            let role = if roles.is_empty() {
                "manager".to_string()
            } else {
                n_other += 1;
                format!("process{n_other}")
            };
            roles.insert(pid, role);
        }
        if !order.contains(&pid) {
            order.push(pid);
        }
        if let Some(rest) = text.strip_prefix("Successfully forked off '(udev-worker)' as PID ") {
            let p: u64 = rest.trim_end_matches('.').parse().unwrap_or(0);
            n_workers += 1;
            roles.insert(p, format!("worker{n_workers}"));
        }
        if is_masked(text) || text.contains(": PR_SET_MM_ARG_START failed") {
            continue;
        }
        // Whether the client's close shows as POLLHUP before the read that
        // finds it depends on timing, in C as well.
        if text.ends_with(": Got POLLHUP from socket.") {
            continue;
        }
        // Varlink connections are served between events as they come: a
        // separate stream (key pid+1<<63) keeps each order deterministic.
        let varlink =
            text.starts_with("varlink") || text.starts_with("Received io.systemd") || text.starts_with("Serializ");
        let key = if varlink && roles.get(&pid).is_some_and(|r| r == "manager") { pid | 1 << 63 } else { pid };
        if key != pid && !order.contains(&key) {
            order.push(key);
            roles.insert(key, "manager (varlink)".to_string());
        }
        streams.entry(key).or_default().push(text.to_string());
    }
    let mut pid_names: Vec<(u64, String)> = roles.iter().map(|(p, r)| (*p, r.clone())).collect();
    pid_names.sort_by_key(|(p, _)| std::cmp::Reverse(*p));
    let fix = |s: &str| -> String {
        let rank = |v: u64| format!("#{}", seqnums.binary_search(&v).unwrap_or(usize::MAX));
        let mut s = replace_num(s, "SEQNUM=", &rank);
        s = replace_num(&s, "seqnum=", &rank);
        for (p, r) in &pid_names {
            if *p != 0 {
                s = s.replace(&format!("[{p}]"), &format!("[{r}]")).replace(&format!("PID {p}"), &format!("PID {r}"));
            }
        }
        s = replace_num(&s, "as PID ", &|_| "<pid>".into());
        s = replace_num(&s, "' [", &|_| "<pid>".into());
        s = replace_num(&s, "varlink-", &|_| "N".into());
        s = replace_num(&s, "varlink-N-", &|_| "N".into());
        s = replace_num(&s, "'@", &|_| "SOCK".into());
        s
    };
    let mut out = String::new();
    for l in head.lines() {
        out.push_str(&fix(l));
        out.push('\n');
    }
    for pid in &order {
        let Some(lines) = streams.get(pid) else { continue };
        out.push_str(&format!("== {}\n", roles[pid]));
        for l in lines {
            out.push_str(&fix(l));
            out.push('\n');
        }
    }
    out
}

fn check(name: &str, script: &str) {
    check_env(name, script, &[]);
}

fn check_env(name: &str, script: &str, env: &[(&str, &str)]) {
    if !available() {
        return;
    }
    let c = normalize(&run(&c_udevadm(), "c", name, script, env));
    let r = normalize(&run(&rust_udevadm(), "rust", name, script, env));
    let dir = work_dir();
    std::fs::write(dir.join(format!("{name}.c.out")), &c).unwrap();
    std::fs::write(dir.join(format!("{name}.rust.out")), &r).unwrap();
    if c != r {
        let d = Command::new("diff")
            .arg("-u")
            .arg(dir.join(format!("{name}.c.out")))
            .arg(dir.join(format!("{name}.rust.out")))
            .output()
            .unwrap();
        panic!("{name}: C and Rust differ:\n{}", String::from_utf8_lossy(&d.stdout));
    }
}

#[test]
fn basic() {
    check(
        "basic",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM!="net", GOTO="end"
ACTION=="add", ENV{FOO}="bar", TAG+="t1", RUN+="/bin/true"
ACTION=="add", PROGRAM=="/bin/echo hello %k", ENV{PROG}="%c"
ACTION=="add", IMPORT{program}="/bin/echo IMPORTED=1"
ACTION=="change", ENV{CHANGED}="yes"
LABEL="end"
EOF
start -c 1
"$U" control --ping; echo "ping=$?"
"$U" control -s
link d0 d1
quiet
"$U" control -S
settle
echo change > /sys/class/net/d0/uevent
settle
info /sys/class/net/d0
info /sys/class/net/d1
stop
"#,
    );
}

#[test]
fn control() {
    check(
        "control",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM=="net", ENV{GLOBAL}=="?*", ENV{SEEN_GLOBAL}="$env{GLOBAL}"
EOF
start -c 1
"$U" control -l info; echo "l=$?"
"$U" control -l debug -p GLOBAL=one -m 1 --trace=no; echo "m=$?"
link d0 d1
settle
info /sys/class/net/d0
"$U" control -p GLOBAL=; echo "p=$?"
"$U" control --revert; echo "revert=$?"
cat >> /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM=="net", ENV{RELOADED}="1"
EOF
"$U" control -R; echo "reload=$?"
echo change > /sys/class/net/d1/uevent
settle
info /sys/class/net/d1
stop
"#,
    );
}

#[test]
fn failures() {
    check_env(
        "failures",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM!="net", GOTO="end"
KERNEL=="f0", ACTION=="add", RUN+="/bin/false"
KERNEL=="f1", ACTION=="add", PROGRAM=="/bin/sh -c 'kill -9 $PPID'"
KERNEL=="f0", ACTION=="change", RUN+="/bin/sleep 3"
LABEL="end"
EOF
start -c 1 -t 1
"$U" control -s
link f0 f1
quiet
"$U" control -S
settle
echo change > /sys/class/net/f0/uevent
settle
info /sys/class/net/f0
info /sys/class/net/f1
stop
"#,
        &[("SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC", "1")],
    );
}

#[test]
fn signals() {
    check(
        "signals",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM=="net", ENV{A}="1"
EOF
start -c 1
link s0 s1
settle
echo 'SUBSYSTEM=="net", ENV{B}="1"' >> /run/udev/rules.d/50-t.rules
kill -HUP "$(cat /run/d.pid)"
"$U" control --ping; echo "ping=$?"
echo change > /sys/class/net/s0/uevent
settle
info /sys/class/net/s0
kill -TERM "$(cat /run/d.pid)"
wait "$(cat /run/d.pid)"; echo "udevd=$?"
"#,
    );
}

#[test]
fn options() {
    check(
        "options",
        r#"
start -c x -e x -t x -N bogus --timeout-signal=NOPE -D
"$U" control --ping; echo "ping=$?"
stop
"/run/systemd-udevd" --help | head -3
"/run/systemd-udevd" --version | head -1
"#,
    );
}

/// Runs `script` against a C udevd, once with the C and once with the Rust
/// udevadm as $U (the client), and compares what the client printed.
fn check_client(name: &str, script: &str) {
    if !available() {
        return;
    }
    let run_with = |label: &str, client: &PathBuf| -> String {
        let path = work_dir().join(format!("{name}.{label}.sh"));
        std::fs::write(&path, format!("{PRELUDE}\nU=\"$CLIENT\"\n{script}\n")).unwrap();
        let o = Command::new("timeout")
            .args(["120", "unshare", "-Urnm", "--propagation", "private", "sh"])
            .arg(&path)
            .env("D", c_udevadm())
            .env("U", c_udevadm())
            .env("CLIENT", client)
            .env_remove("SYSTEMD_LOG_LEVEL")
            .env_remove("NOTIFY_SOCKET")
            .output()
            .unwrap();
        let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&o.stderr));
        normalize_client(&s)
    };
    let c = run_with("c", &c_udevadm());
    let r = run_with("rust", &rust_udevadm());
    let dir = work_dir();
    std::fs::write(dir.join(format!("{name}.c.out")), &c).unwrap();
    std::fs::write(dir.join(format!("{name}.rust.out")), &r).unwrap();
    if c != r {
        let d = Command::new("diff")
            .arg("-u")
            .arg(dir.join(format!("{name}.c.out")))
            .arg(dir.join(format!("{name}.rust.out")))
            .output()
            .unwrap();
        panic!("{name}: C and Rust differ:\n{}", String::from_utf8_lossy(&d.stdout));
    }
}

/// Masks timestamps, seqnums, uuids and other per-run values of the
/// clients' output.
fn normalize_client(raw: &str) -> String {
    let mut out = String::new();
    for l in raw.lines() {
        // SYSTEMD_LOG_TID=1's "(pid) " prefix.
        let l = match l.strip_prefix('(').and_then(|r| r.split_once(") ")) {
            Some((p, t)) if p.bytes().all(|c| c.is_ascii_digit()) => t,
            _ => l,
        };
        let mut s = l.to_string();
        // "KERNEL[1234.567890] change   /devices/... (net)"
        if let Some(i) = s.find('[')
            && (s.starts_with("UDEV") || s.starts_with("KERNEL"))
            && let Some(j) = s[i..].find(']')
        {
            s.replace_range(i..i + j + 1, "[TIME]");
        }
        for key in ["SEQNUM=", "USEC_INITIALIZED=", "SYNTH_UUID=", "IFINDEX="] {
            if let Some(v) = s.strip_prefix(key) {
                let _ = v;
                s = format!("{key}X");
            }
        }
        // UUIDs printed by trigger --uuid
        let is_uuid = |w: &str| w.len() == 36 && w.chars().filter(|&c| c == '-').count() == 4;
        s = s.split(' ').map(|w| if is_uuid(w) { "UUID" } else { w }).collect::<Vec<_>>().join(" ");
        s = replace_num(&s, "varlink-", &|_| "N".into());
        s = replace_num(&s, "varlink-N-", &|_| "N".into());
        s = replace_num(&s, "as PID ", &|_| "<pid>".into());
        out.push_str(&s);
        out.push('\n');
    }
    out
}

#[test]
fn client_control_settle() {
    check_client(
        "client_control",
        r#"
start -c 1
export SYSTEMD_LOG_LEVEL=debug
"$U" control --ping; echo "ping=$?"
"$U" control -l info -p A=b -m 3 --trace=yes --revert -s -S -R; echo "multi=$?"
"$U" control -p bad; echo "bad=$?"
"$U" settle -t 5; echo "settle=$?"
"$U" settle -E /run/udev/control; echo "settle=$?"
unset SYSTEMD_LOG_LEVEL
"$U" control --exit; echo "exit=$?"
wait "$(cat /run/d.pid)"
"$U" control --ping; echo "ping=$?"
"$U" settle; echo "settle=$?"
"#,
    );
}

#[test]
fn client_monitor() {
    check_client(
        "client_monitor",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM=="net", ENV{MON}="1", TAG+="mon"
EOF
start -c 1
"$U" monitor -k -p > /run/k.out 2>&1 &
k=$!
"$U" monitor -u -s net -t mon > /run/u.out 2>&1 &
u=$!
"$U" monitor -u -s block > /run/b.out 2>&1 &
b=$!
sleep 0.5
link m0 m1
settle
echo change > /sys/class/net/m0/uevent
settle
sleep 0.3
kill $k $u $b; wait $k $u $b
echo "== kernel"; cat /run/k.out
echo "== udev"; cat /run/u.out
echo "== block"; cat /run/b.out
stop
"#,
    );
}

#[test]
fn client_trigger() {
    check_client(
        "client_trigger",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM=="net", ENV{TRIG}="$env{ACTION}"
EOF
start -c 1
link t0 t1
settle
"$U" trigger -n -v -s net; echo "dry=$?"
"$U" trigger -v -s net -y 't*' --settle --uuid | sort; echo "trigger=$?"
"$U" trigger -c add -s net --settle -v; echo "add=$?"
"$U" trigger -c help | head -3
"$U" trigger -c bogus; echo "bogus=$?"
"$U" trigger -t bogus; echo "type=$?"
"$U" trigger --name-match=nope; echo "name=$?"
"$U" trigger -p FOO; echo "prop=$?"
"$U" trigger -n -v -s net --initialized-match; echo "init=$?"
"$U" trigger -n -v -s net -a ifindex=2; echo "attr=$?"
"$U" trigger -n -v -b /sys/class/net/t0 --include-parents | head -3; echo "parent=$?"
"$U" trigger --wait-daemon=2 -n -s net; echo "wait=$?"
info /sys/class/net/t0
stop
"#,
    );
}

#[test]
fn client_wait_lock() {
    check_client(
        "client_wait_lock",
        r#"
start -c 1
link w0 w1
settle
"$U" wait -t 5 /sys/class/net/w0; echo "wait=$?"
"$U" wait -t 1 --initialized=no /sys/class/net/w0 --settle; echo "wait=$?"
"$U" wait --removed -t 1 /sys/class/net/zz; echo "removed=$?"
"$U" wait -t 1 /sys/class/net/nonexist; echo "timeout=$?"
"$U" wait -t 1 /tmp/x; echo "path=$?"
"$U" wait -t 1 /sys/../x; echo "dotdot=$?"
"$U" wait; echo "none=$?"
(sleep 0.5; ip link add w2 type netkit peer name w3) &
"$U" wait -t 10 /sys/class/net/w2; echo "later=$?"
(sleep 0.5; ip link del w2) &
"$U" wait -t 10 --removed /sys/class/net/w2; echo "gone=$?"
"$U" lock; echo "lock=$?"
"$U" lock -p true; echo "lock=$?"
"$U" lock -d /dev/null true; echo "lock=$?"
"$U" lock --print -d /dev/null; echo "lock=$?"
"$U" lock -t x -d /dev/null true; echo "lock=$?"
stop
"#,
    );
}

#[test]
fn rename() {
    check(
        "rename",
        r#"
cat > /run/udev/rules.d/50-t.rules <<'EOF'
SUBSYSTEM!="net", GOTO="end"
ACTION=="add", KERNEL=="r0", NAME="renamed0", ENV{WAS}="r0"
ACTION=="add", KERNEL=="r1", NAME="bad/name"
ACTION=="move", ENV{MOVED}="$env{INTERFACE_OLD}"
LABEL="end"
EOF
start -c 1
"$U" control -s
link r0 r1
quiet
"$U" control -S
settle
ip -br link | awk '{print $1}' | sort
info /sys/class/net/renamed0
info /sys/class/net/r1
stop
"#,
    );
}

#[test]
fn link_files() {
    // .link files on L2 netkit devices: matching, names and alternative
    // names, MAC address policies, rtnetlink settings, udev properties,
    // drop-ins, conditions, and the parser's warnings.
    check(
        "link_files",
        r#"
mount -t tmpfs tmpfs /usr/lib/systemd/network
mkdir -p /run/systemd/network/10-name.link.d
cat > /run/udev/rules.d/80-net.rules <<'EOF'
SUBSYSTEM!="net", GOTO="end"
ACTION=="remove", GOTO="end"
IMPORT{builtin}="net_driver"
IMPORT{builtin}="net_id"
IMPORT{builtin}="net_setup_link"
NAME=="", ENV{ID_NET_NAME}!="", NAME="$env{ID_NET_NAME}"
LABEL="end"
EOF
cat > /run/systemd/network/10-name.link <<'EOF'
[Match]
OriginalName=n0
[Link]
Description=renamed by Name=
Name=named0
AlternativeName=alt-n0 alt-n0 bad/name
MACAddressPolicy=none
MACAddress=02:11:22:33:44:55
MTUBytes=1400
TransmitQueueLength=500
Alias=hello alias
Property=FOO=bar "BAZ=a b" FOO=again DEVPATH=x
ImportProperty=ID_NET_DRIVER
UnsetProperty=ID_NET_NAMING_SCHEME
EOF
cat > /run/systemd/network/10-name.link.d/50-more.conf <<'EOF'
[Link]
TransmitQueueLength=600
EOF
cat > /run/systemd/network/20-persistent.link <<'EOF'
[Match]
OriginalName=p*
Driver=netkit
Property=ID_NET_DRIVER=netkit
[Link]
NamePolicy=keep kernel mac path
AlternativeNamesPolicy=mac path
MACAddressPolicy=persistent
EOF
cat > /run/systemd/network/30-random.link <<'EOF'
[Match]
OriginalName=r0
Type=ether
[Link]
MACAddressPolicy=random
Name=rnd0
EOF
cat > /run/systemd/network/40-nomatch.link <<'EOF'
[Match]
Host=no-such-host
Virtualization=!container
Architecture=no-such-arch
[Link]
Name=never
EOF
cat > /run/systemd/network/50-warnings.link <<'EOF'
Outside=1
[Match]
OriginalName=!x0 bad/name
MACAddress=00:11:22:33:44:55 nonsense 0011.2233.4455
PermanentMACAddress=
Property=NOEQUALS
KernelCommandLine=
[Nosuch]
Key=1
[Link]
NoSuchKey=1
X-Extension=1
Name=way-too-long-interface-name
MTUBytes=1x
BitsPerSecond=10G
Duplex=sideways
AutoNegotiation=maybe
Advertise=10baset-full nosuchmode
Port=tp
MDI=crossover
WakeOnLan=magic nosuch phy
WakeOnLanPassword=00:11:22:33:44
RxChannels=max
TxChannels=0
OtherChannels=x
RxBufferSize=1024
RxCoalesceSec=1s
StatisticsBlockCoalesceSec=0
TxMaxCoalescedFrames=abc
NamePolicy=mac mac kernel nosuch
AlternativeNamesPolicy=kernel path
TransmitQueues=0
ReceiveQueues=16385
GenericSegmentOffloadMaxBytes=64K
GenericSegmentOffloadMaxSegments=lots
UDPSegmentationOffload=yes
ReceiveChecksumOffload=yes
IRQAffinityPolicy=nosuch
IRQAffinity=0-1 3-2 x
IRQAffinityNUMA=local
ReceivePacketSteeringCPUMask=all
SR-IOVVirtualFunctions=2
Alias=caf\xc3\xa9
[SR-IOV]
VirtualFunction=0
VLANId=5000
[SR-IOV]
VirtualFunction=1
Trust=sure
[SR-IOV]
VLANId=3
[SR-IOV]
VirtualFunction=7
[SR-IOV]
VirtualFunction=1
MACSpoofCheck=yes
LinkState=auto
[EnergyEfficientEthernet]
Enable=yes
TxLowPowerIdleSec=1d
LinkMode=nosuch
EOF
: > /run/systemd/network/60-empty.link
cat > /run/systemd/network/70-nomatch-section.link <<'EOF'
[Link]
Name=nope
EOF
start -c 1
"$U" control -s
link2 n0 n1
link2 p0 p1
link2 r0 r1
quiet
"$U" control -S
settle
ip -br link | awk '{print $1}' | sort
ip -d link show named0 | grep -o 'mtu [0-9]*\|qlen [0-9]*\|link/ether [0-9a-f:]*\|altname [a-z0-9-]*\|alias .*' | sort
info /sys/class/net/named0
info /sys/class/net/p0
stop
"#,
    );
}

#[test]
fn empty_rules_reload() {
    check(
        "empty_rules",
        r#"
: > /run/udev/rules.d/10-empty.rules
echo 'SUBSYSTEM=="net", ENV{E}="1"' > /run/udev/rules.d/50-t.rules
start -c 1
link e0 e1
settle
sleep 4.5
echo change > /sys/class/net/e0/uevent
settle
stop
"#,
    );
}
