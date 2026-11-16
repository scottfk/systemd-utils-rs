/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * probe.c - drive libudev from the command line, for the differential tests
 *
 * 20261116 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * Each argument is a command, some of which take the arguments after it;
 * "-" stands for NULL.  Every result is printed, with errno after a
 * failure.  The same program is built twice (and twice more with -m32),
 * once against the C libudev and once against the port (by rpath), and the
 * test harness compares the two runs.
 *
 * The values of TAGS=, CURRENT_TAGS= and DEVLINKS= are printed with their
 * words sorted: C builds them from a hash set, in a different order from
 * run to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "libudev.h"

static struct udev *u;
static struct udev_device *cur;
static struct udev_enumerate *en;
static struct udev_monitor *mon;
static struct udev_hwdb *hw;
static struct udev_queue *q;
static struct udev_list_entry *last;
static int nl_sock = -1;
static char **argp;

static const char *ename(int e) {
        const char *s;

        if (e == 0)
                return "0";
        s = strerrorname_np(e);
        return s ? s : "?";
}

static const char *next_arg(void) {
        const char *a = *argp;

        if (!a) {
                fprintf(stderr, "probe: missing argument\n");
                exit(2);
        }
        argp++;
        return strcmp(a, "-") == 0 ? NULL : a;
}

static void show_str(const char *what, const char *s, int e) {
        if (s)
                printf("%s=%s\n", what, s);
        else
                printf("%s=(null) errno=%s\n", what, ename(e));
}

static int cmp_str(const void *a, const void *b) {
        return strcmp(*(char * const *) a, *(char * const *) b);
}

/* Sort the words of a TAGS=/CURRENT_TAGS=/DEVLINKS= value. */
static void print_sorted_words(const char *v, const char *sep, int wrap) {
        char *copy = strdup(v), *save = NULL, *w;
        char *words[1024];
        size_t n = 0;

        for (w = strtok_r(copy, sep, &save); w && n < 1024; w = strtok_r(NULL, sep, &save))
                words[n++] = w;
        qsort(words, n, sizeof(char *), cmp_str);
        if (wrap)
                fputs(sep, stdout);
        for (size_t i = 0; i < n; i++) {
                if (i > 0)
                        fputs(sep, stdout);
                fputs(words[i], stdout);
        }
        if (wrap && n > 0)
                fputs(sep, stdout);
        free(copy);
}

static void print_value(const char *name, const char *v) {
        if (!v) {
                fputs("(null)", stdout);
                return;
        }
        if (name && (strcmp(name, "TAGS") == 0 || strcmp(name, "CURRENT_TAGS") == 0))
                print_sorted_words(v, ":", 1);
        else if (name && strcmp(name, "DEVLINKS") == 0)
                print_sorted_words(v, " ", 0);
        else
                fputs(v, stdout);
}

static void show_list(const char *what, struct udev_list_entry *e, int values) {
        struct udev_list_entry *i;

        if (!e) {
                printf("%s: (empty)\n", what);
                return;
        }
        last = e;
        printf("%s:\n", what);
        udev_list_entry_foreach(i, e) {
                printf("  %s", udev_list_entry_get_name(i));
                if (values) {
                        fputs("=", stdout);
                        print_value(udev_list_entry_get_name(i), udev_list_entry_get_value(i));
                }
                fputs("\n", stdout);
        }
}

#define SHOW(dev, f)                                                    \
        do {                                                            \
                const char *_s;                                         \
                errno = 0;                                              \
                _s = udev_device_get_##f(dev);                          \
                show_str(#f, _s, errno);                                \
        } while (0)

static void dump(struct udev_device *d, int attrs) {
        unsigned long long v;
        dev_t devnum;
        int r;

        if (!d) {
                printf("device=(null)\n");
                return;
        }
        SHOW(d, syspath);
        SHOW(d, devpath);
        SHOW(d, sysname);
        SHOW(d, sysnum);
        SHOW(d, devnode);
        SHOW(d, subsystem);
        SHOW(d, devtype);
        SHOW(d, driver);
        SHOW(d, action);
        errno = 0;
        devnum = udev_device_get_devnum(d);
        printf("devnum=%u:%u", major(devnum), minor(devnum));
        if (devnum == 0)
                printf(" errno=%s", ename(errno));
        printf("\n");
        printf("seqnum=%llu\n", udev_device_get_seqnum(d));
        errno = 0;
        r = udev_device_get_is_initialized(d);
        printf("is_initialized=%d", r);
        if (r <= 0)
                printf(" errno=%s", ename(errno));
        printf("\n");
        errno = 0;
        v = udev_device_get_usec_since_initialized(d);
        printf("usec_since_initialized=%s", v > 0 ? ">0" : "0");
        if (v == 0)
                printf(" errno=%s", ename(errno));
        printf("\n");
        show_list("properties", udev_device_get_properties_list_entry(d), 1);
        show_list("devlinks", udev_device_get_devlinks_list_entry(d), 0);
        show_list("tags", udev_device_get_tags_list_entry(d), 0);
        show_list("current_tags", udev_device_get_current_tags_list_entry(d), 0);
        if (attrs)
                show_list("sysattrs", udev_device_get_sysattr_list_entry(d), 0);
}

static void new_device(const char *what, struct udev_device *d, int e) {
        /* The previous device is dropped: its parents with it. */
        udev_device_unref(cur);
        cur = d;
        if (d)
                printf("%s: ok\n", what);
        else
                printf("%s: (null) errno=%s\n", what, ename(e));
}

static void enumerate_dump(int attrs) {
        struct udev_list_entry *i, *e;

        errno = 0;
        e = udev_enumerate_get_list_entry(en);
        if (!e) {
                printf("enumerate: (empty) errno=%s\n", ename(errno));
                return;
        }
        last = e;
        udev_list_entry_foreach(i, e) {
                struct udev_device *d;

                printf("== %s\n", udev_list_entry_get_name(i));
                errno = 0;
                d = udev_device_new_from_syspath(u, udev_list_entry_get_name(i));
                if (!d) {
                        printf("(null) errno=%s\n", ename(errno));
                        continue;
                }
                dump(d, attrs);
                udev_device_unref(d);
        }
}

/* systemd's MurmurHash2(), for the monitor's filter hashes. */
static uint32_t murmur2(const char *key) {
        const uint32_t m = 0x5bd1e995;
        int len = strlen(key);
        uint32_t h = 0 ^ len;
        const unsigned char *data = (const unsigned char *) key;

        while (len >= 4) {
                uint32_t k;
                memcpy(&k, data, 4);
                k *= m;
                k ^= k >> 24;
                k *= m;
                h *= m;
                h ^= k;
                data += 4;
                len -= 4;
        }
        switch (len) {
        case 3: h ^= data[2] << 16; /* fall through */
        case 2: h ^= data[1] << 8;  /* fall through */
        case 1: h ^= data[0];
                h *= m;
        }
        h ^= h >> 13;
        h *= m;
        h ^= h >> 15;
        return h;
}

static uint64_t bloom64(const char *s) {
        uint32_t hash = murmur2(s);
        uint64_t bits = 0;

        bits |= UINT64_C(1) << (hash & 63);
        bits |= UINT64_C(1) << ((hash >> 6) & 63);
        bits |= UINT64_C(1) << ((hash >> 12) & 63);
        bits |= UINT64_C(1) << ((hash >> 18) & 63);
        return bits;
}

/* "K=V|K=V|..." to a nulstr, with "\n" in values kept. */
static size_t nulstr(const char *props, char *out, size_t max) {
        size_t n = 0;

        for (const char *p = props; *p && n < max - 1; p++)
                out[n++] = *p == '|' ? '\0' : *p;
        out[n++] = '\0';
        return n;
}

static void nl_open(void) {
        /* A fixed port id, so messages naming the sender are the same in every run. */
        struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_pid = 4242 };

        if (nl_sock >= 0)
                return;
        nl_sock = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
        if (nl_sock < 0 || bind(nl_sock, (struct sockaddr *) &sa, sizeof sa) < 0) {
                printf("nl: socket errno=%s\n", ename(errno));
                exit(3);
        }
}

/* Send to group G, or to the monitor itself ("self"). */
static void nl_send(const char *dest, const void *buf, size_t len) {
        struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
        ssize_t n;

        nl_open();
        if (strcmp(dest, "self") == 0) {
                struct sockaddr_nl me;
                socklen_t l = sizeof me;

                getsockname(udev_monitor_get_fd(mon), (struct sockaddr *) &me, &l);
                sa.nl_pid = me.nl_pid;
        } else
                sa.nl_groups = atoi(dest);
        n = sendto(nl_sock, buf, len, 0, (struct sockaddr *) &sa, sizeof sa);
        if (n < 0)
                printf("nl-send: errno=%s\n", ename(errno));
}

struct hdr {
        char prefix[8];
        unsigned magic, header_size, properties_off, properties_len;
        unsigned subsystem_hash, devtype_hash, bloom_hi, bloom_lo;
};

static void *unref_thread(void *p) {
        udev_device_unref(p);
        return NULL;
}

int main(int argc, char *argv[]) {
        (void) argc;
        argp = argv + 1;
        u = udev_new();

        while (*argp) {
                const char *c = *argp++;

                if (strcmp(c, "log") == 0) {
                        udev_set_log_priority(u, atoi(next_arg()));
                        printf("log: %d\n", udev_get_log_priority(u));
                } else if (strcmp(c, "syspath") == 0) {
                        const char *p = next_arg();
                        errno = 0;
                        struct udev_device *d = udev_device_new_from_syspath(u, p);
                        new_device("syspath", d, errno);
                } else if (strcmp(c, "devnum") == 0) {
                        const char *t = next_arg(), *n = next_arg();
                        unsigned ma = 0, mi = 0;
                        sscanf(n, "%u:%u", &ma, &mi);
                        errno = 0;
                        struct udev_device *d = udev_device_new_from_devnum(u, t ? t[0] : 0, makedev(ma, mi));
                        new_device("devnum", d, errno);
                } else if (strcmp(c, "id") == 0) {
                        const char *p = next_arg();
                        errno = 0;
                        struct udev_device *d = udev_device_new_from_device_id(u, p);
                        new_device("id", d, errno);
                } else if (strcmp(c, "subsys") == 0) {
                        const char *s = next_arg(), *n = next_arg();
                        errno = 0;
                        struct udev_device *d = udev_device_new_from_subsystem_sysname(u, s, n);
                        new_device("subsys", d, errno);
                } else if (strcmp(c, "env") == 0) {
                        errno = 0;
                        struct udev_device *d = udev_device_new_from_environment(u);
                        new_device("env", d, errno);
                } else if (strcmp(c, "putenv") == 0) {
                        putenv(strdup(next_arg()));
                } else if (strcmp(c, "clearenv") == 0) {
                        clearenv();
                } else if (strcmp(c, "dump") == 0) {
                        dump(cur, 0);
                } else if (strcmp(c, "dump-attrs") == 0) {
                        dump(cur, 1);
                } else if (strcmp(c, "parent") == 0) {
                        struct udev_device *p;
                        errno = 0;
                        p = udev_device_get_parent(cur);
                        if (!p) {
                                printf("parent: (null) errno=%s\n", ename(errno));
                                continue;
                        }
                        printf("parent: %s\n", udev_device_get_syspath(p));
                        /* Keep the child alive: it owns the parent. */
                        udev_device_ref(p);
                        new_device("parent", p, 0);
                } else if (strcmp(c, "parents") == 0) {
                        struct udev_device *p = cur;
                        for (;;) {
                                errno = 0;
                                p = udev_device_get_parent(p);
                                if (!p) {
                                        printf("parents: end errno=%s\n", ename(errno));
                                        break;
                                }
                                printf("parents: %s\n", udev_device_get_syspath(p));
                        }
                } else if (strcmp(c, "parent-st") == 0) {
                        const char *s = next_arg(), *t = next_arg();
                        struct udev_device *p;
                        errno = 0;
                        p = udev_device_get_parent_with_subsystem_devtype(cur, s, t);
                        if (p)
                                printf("parent-st: %s\n", udev_device_get_syspath(p));
                        else
                                printf("parent-st: (null) errno=%s\n", ename(errno));
                } else if (strcmp(c, "attr") == 0) {
                        const char *a = next_arg(), *v;
                        errno = 0;
                        v = udev_device_get_sysattr_value(cur, a);
                        printf("attr %s: ", a ? a : "(null)");
                        show_str("value", v, errno);
                } else if (strcmp(c, "setattr") == 0) {
                        const char *a = next_arg(), *v = next_arg();
                        printf("setattr %s: %d\n", a ? a : "(null)", udev_device_set_sysattr_value(cur, a, v));
                } else if (strcmp(c, "prop") == 0) {
                        const char *k = next_arg(), *v;
                        errno = 0;
                        v = udev_device_get_property_value(cur, k);
                        printf("prop %s: ", k ? k : "(null)");
                        if (v) {
                                fputs("value=", stdout);
                                print_value(k, v);
                                fputs("\n", stdout);
                        } else
                                show_str("value", v, errno);
                } else if (strcmp(c, "tag") == 0) {
                        const char *t = next_arg();
                        printf("tag %s: %d\n", t ? t : "(null)", udev_device_has_tag(cur, t));
                } else if (strcmp(c, "ctag") == 0) {
                        const char *t = next_arg();
                        printf("ctag %s: %d\n", t ? t : "(null)", udev_device_has_current_tag(cur, t));
                } else if (strcmp(c, "attrs") == 0) {
                        show_list("sysattrs", udev_device_get_sysattr_list_entry(cur), 0);
                } else if (strcmp(c, "props") == 0) {
                        show_list("properties", udev_device_get_properties_list_entry(cur), 1);
                } else if (strcmp(c, "list-name") == 0) {
                        const char *n = next_arg();
                        struct udev_list_entry *e = udev_list_entry_get_by_name(last, n);
                        printf("list-name %s: ", n ? n : "(null)");
                        if (e) {
                                printf("%s=", udev_list_entry_get_name(e));
                                print_value(udev_list_entry_get_name(e), udev_list_entry_get_value(e));
                                printf("\n");
                        } else
                                printf("(null)\n");
                } else if (strcmp(c, "list-next") == 0) {
                        struct udev_list_entry *e = udev_list_entry_get_next(last);
                        printf("list-next: %s\n", e ? udev_list_entry_get_name(e) : "(null)");
                } else if (strcmp(c, "list-first") == 0) {
                        printf("list-first: %s\n", last ? udev_list_entry_get_name(last) : "(null)");
                } else if (strcmp(c, "null") == 0) {
                        udev_device_unref(cur);
                        cur = NULL;
                } else if (strcmp(c, "enum") == 0) {
                        udev_enumerate_unref(en);
                        en = udev_enumerate_new(u);
                } else if (strcmp(c, "enum-null") == 0) {
                        udev_enumerate_unref(en);
                        en = NULL;
                } else if (strcmp(c, "e-sub") == 0) {
                        printf("e-sub: %d\n", udev_enumerate_add_match_subsystem(en, next_arg()));
                } else if (strcmp(c, "e-nosub") == 0) {
                        printf("e-nosub: %d\n", udev_enumerate_add_nomatch_subsystem(en, next_arg()));
                } else if (strcmp(c, "e-attr") == 0) {
                        const char *a = next_arg(), *v = next_arg();
                        printf("e-attr: %d\n", udev_enumerate_add_match_sysattr(en, a, v));
                } else if (strcmp(c, "e-noattr") == 0) {
                        const char *a = next_arg(), *v = next_arg();
                        printf("e-noattr: %d\n", udev_enumerate_add_nomatch_sysattr(en, a, v));
                } else if (strcmp(c, "e-prop") == 0) {
                        const char *a = next_arg(), *v = next_arg();
                        printf("e-prop: %d\n", udev_enumerate_add_match_property(en, a, v));
                } else if (strcmp(c, "e-tag") == 0) {
                        printf("e-tag: %d\n", udev_enumerate_add_match_tag(en, next_arg()));
                } else if (strcmp(c, "e-parent") == 0) {
                        printf("e-parent: %d\n", udev_enumerate_add_match_parent(en, cur));
                } else if (strcmp(c, "e-init") == 0) {
                        printf("e-init: %d\n", udev_enumerate_add_match_is_initialized(en));
                } else if (strcmp(c, "e-name") == 0) {
                        printf("e-name: %d\n", udev_enumerate_add_match_sysname(en, next_arg()));
                } else if (strcmp(c, "e-path") == 0) {
                        printf("e-path: %d\n", udev_enumerate_add_syspath(en, next_arg()));
                } else if (strcmp(c, "e-scan") == 0) {
                        printf("e-scan: %d\n", udev_enumerate_scan_devices(en));
                } else if (strcmp(c, "e-scansub") == 0) {
                        printf("e-scansub: %d\n", udev_enumerate_scan_subsystems(en));
                } else if (strcmp(c, "e-list") == 0) {
                        struct udev_list_entry *e;
                        errno = 0;
                        e = udev_enumerate_get_list_entry(en);
                        if (!e)
                                printf("e-list: (empty) errno=%s\n", ename(errno));
                        else
                                show_list("e-list", e, 0);
                } else if (strcmp(c, "e-dump") == 0) {
                        enumerate_dump(0);
                } else if (strcmp(c, "e-dump-attrs") == 0) {
                        enumerate_dump(1);
                } else if (strcmp(c, "e-udev") == 0) {
                        errno = 0;
                        printf("e-udev: %s errno=%s\n", udev_enumerate_get_udev(en) == u ? "same" : "other", ename(errno));
                } else if (strcmp(c, "hwdb") == 0) {
                        if (!hw) {
                                errno = 0;
                                hw = udev_hwdb_new(u);
                                if (!hw) {
                                        printf("hwdb: (null) errno=%s\n", ename(errno));
                                        next_arg();
                                        continue;
                                }
                        }
                        const char *m = next_arg();
                        struct udev_list_entry *e;
                        errno = 0;
                        e = udev_hwdb_get_properties_list_entry(hw, m, 0);
                        if (!e)
                                printf("hwdb %s: (empty) errno=%s\n", m ? m : "(null)", ename(errno));
                        else
                                show_list("hwdb", e, 1);
                } else if (strcmp(c, "hwdb-null") == 0) {
                        struct udev_list_entry *e;
                        errno = 0;
                        e = udev_hwdb_get_properties_list_entry(NULL, "x", 0);
                        printf("hwdb-null: %s errno=%s\n", e ? "entry" : "(null)", ename(errno));
                } else if (strcmp(c, "queue") == 0) {
                        if (!q)
                                q = udev_queue_new(u);
                        printf("queue: active=%d empty=%d finished=%d seq-finished=%d kernel=%llu udev=%llu\n",
                               udev_queue_get_udev_is_active(q),
                               udev_queue_get_queue_is_empty(q),
                               udev_queue_get_seqnum_is_finished(q, 1),
                               udev_queue_get_seqnum_sequence_is_finished(q, 1, 2),
                               udev_queue_get_kernel_seqnum(q),
                               udev_queue_get_udev_seqnum(q));
                        errno = 0;
                        printf("queue: queued=%s errno=%s\n",
                               udev_queue_get_queued_list_entry(q) ? "entry" : "(null)", ename(errno));
                        printf("queue: flush-before-fd=%d\n", udev_queue_flush(q));
                        int fd = udev_queue_get_fd(q);
                        printf("queue: fd=%s same=%d flush=%d\n", fd >= 0 ? "ok" : ename(-fd),
                               udev_queue_get_fd(q) == fd, udev_queue_flush(q));
                        errno = 0;
                        printf("queue: udev=%s errno=%s\n", udev_queue_get_udev(q) == u ? "same" : "other", ename(errno));
                } else if (strcmp(c, "encode") == 0) {
                        const char *s = next_arg();
                        int len = atoi(next_arg()), r;
                        char buf[512];
                        memset(buf, 'X', sizeof buf);
                        r = udev_util_encode_string(s, len > 0 ? buf : NULL, len);
                        printf("encode: %d [", r);
                        for (int i = 0; i < len && i < (int) sizeof buf; i++) {
                                if (buf[i] == 0)
                                        printf("\\0");
                                else
                                        putchar(buf[i]);
                        }
                        printf("]\n");
                } else if (strcmp(c, "mon") == 0) {
                        const char *n = next_arg();
                        udev_monitor_unref(mon);
                        errno = 0;
                        mon = udev_monitor_new_from_netlink(u, n);
                        printf("mon %s: %s errno=%s\n", n ? n : "(null)", mon ? "ok" : "(null)", mon ? "0" : ename(errno));
                } else if (strcmp(c, "m-sub") == 0) {
                        const char *s = next_arg(), *d = next_arg();
                        printf("m-sub: %d\n", udev_monitor_filter_add_match_subsystem_devtype(mon, s, d));
                } else if (strcmp(c, "m-tag") == 0) {
                        printf("m-tag: %d\n", udev_monitor_filter_add_match_tag(mon, next_arg()));
                } else if (strcmp(c, "m-update") == 0) {
                        printf("m-update: %d\n", udev_monitor_filter_update(mon));
                } else if (strcmp(c, "m-enable") == 0) {
                        printf("m-enable: %d\n", udev_monitor_enable_receiving(mon));
                } else if (strcmp(c, "m-remove") == 0) {
                        printf("m-remove: %d\n", udev_monitor_filter_remove(mon));
                } else if (strcmp(c, "m-buf") == 0) {
                        printf("m-buf: %d\n", udev_monitor_set_receive_buffer_size(mon, atoi(next_arg())));
                } else if (strcmp(c, "m-fd") == 0) {
                        int fd = udev_monitor_get_fd(mon);
                        printf("m-fd: %s\n", fd >= 0 ? "ok" : ename(-fd));
                } else if (strcmp(c, "m-recv") == 0) {
                        /* Wait (up to the given ms) for something to read, then receive. */
                        struct pollfd p = { .fd = udev_monitor_get_fd(mon), .events = POLLIN };
                        int ms = atoi(next_arg());
                        if (poll(&p, 1, ms) <= 0) {
                                printf("m-recv: timeout\n");
                                continue;
                        }
                        errno = 0;
                        struct udev_device *d = udev_monitor_receive_device(mon);
                        if (!d) {
                                printf("m-recv: (null) errno=%s\n", ename(errno));
                                continue;
                        }
                        printf("m-recv: device\n");
                        new_device("m-recv", d, 0);
                        dump(cur, 0);
                } else if (strcmp(c, "m-recv-now") == 0) {
                        errno = 0;
                        struct udev_device *d = udev_monitor_receive_device(mon);
                        if (!d) {
                                printf("m-recv-now: (null) errno=%s\n", ename(errno));
                                continue;
                        }
                        new_device("m-recv-now", d, 0);
                        dump(cur, 0);
                } else if (strcmp(c, "nl-udev") == 0) {
                        /* nl-udev DEST SUBSYSTEM DEVTYPE TAG PROPS: a udevd broadcast. */
                        const char *dest = next_arg(), *s = next_arg(), *dt = next_arg(), *tag = next_arg();
                        const char *props = next_arg();
                        char buf[8192];
                        struct hdr h = { .prefix = "libudev", .magic = htobe32(0xfeedcafe), .header_size = sizeof h };
                        size_t n = nulstr(props ? props : "", buf + sizeof h, sizeof buf - sizeof h);
                        h.properties_off = sizeof h;
                        h.properties_len = n;
                        if (s)
                                h.subsystem_hash = htobe32(murmur2(s));
                        if (dt)
                                h.devtype_hash = htobe32(murmur2(dt));
                        if (tag) {
                                uint64_t b = bloom64(tag);
                                h.bloom_hi = htobe32(b >> 32);
                                h.bloom_lo = htobe32(b & 0xffffffff);
                        }
                        memcpy(buf, &h, sizeof h);
                        nl_send(dest, buf, sizeof h + n);
                } else if (strcmp(c, "nl-badmagic") == 0) {
                        const char *dest = next_arg();
                        char buf[256] = {};
                        struct hdr h = { .prefix = "libudev", .magic = 0x12345678, .header_size = sizeof h, .properties_off = sizeof h };
                        memcpy(buf, &h, sizeof h);
                        memcpy(buf + sizeof h, "ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=x\0SEQNUM=1", 50);
                        nl_send(dest, buf, sizeof h + 50);
                } else if (strcmp(c, "nl-kernel") == 0) {
                        /* nl-kernel DEST HEADER PROPS: a kernel-style uevent. */
                        const char *dest = next_arg(), *hd = next_arg(), *props = next_arg();
                        char buf[8192];
                        size_t l = strlen(hd ? hd : "");
                        memcpy(buf, hd ? hd : "", l + 1);
                        size_t n = nulstr(props ? props : "", buf + l + 1, sizeof buf - l - 1);
                        nl_send(dest, buf, l + 1 + n);
                } else if (strcmp(c, "nl-raw") == 0) {
                        /* nl-raw DEST TEXT, with "|" for NUL and no terminator added. */
                        const char *dest = next_arg(), *t = next_arg();
                        char buf[8192];
                        size_t n = strlen(t);
                        for (size_t i = 0; i < n; i++)
                                buf[i] = t[i] == '|' ? 0 : t[i];
                        nl_send(dest, buf, n);
                } else if (strcmp(c, "refs") == 0) {
                        struct udev *x = udev_ref(u);
                        printf("refs: ref=%s unref=%s unref=%s\n", x == u ? "same" : "other",
                               udev_unref(u) == u ? "same" : "(null)", udev_ref(NULL) ? "?" : "(null)");
                        udev_set_userdata(u, (void *) 0x1234);
                        printf("refs: userdata=%s\n", udev_get_userdata(u) == (void *) 0x1234 ? "set" : "unset");
                        udev_set_userdata(NULL, NULL);
                        errno = 0;
                        printf("refs: get_userdata(NULL)=%s\n", udev_get_userdata(NULL) ? "?" : "(null)");
                        if (cur) {
                                struct udev_device *d2 = udev_device_ref(cur);
                                printf("refs: device ref=%s unref=%s udev=%s\n", d2 == cur ? "same" : "other",
                                       udev_device_unref(d2) ? "?" : "(null)",
                                       udev_device_get_udev(cur) == u ? "same" : "other");
                        }
                } else if (strcmp(c, "nulls") == 0) {
                        /* Every getter with a NULL object. */
                        errno = 0; show_str("syspath", udev_device_get_syspath(NULL), errno);
                        errno = 0; show_str("devpath", udev_device_get_devpath(NULL), errno);
                        errno = 0; show_str("sysname", udev_device_get_sysname(NULL), errno);
                        errno = 0; show_str("sysnum", udev_device_get_sysnum(NULL), errno);
                        errno = 0; show_str("devnode", udev_device_get_devnode(NULL), errno);
                        errno = 0; show_str("subsystem", udev_device_get_subsystem(NULL), errno);
                        errno = 0; show_str("devtype", udev_device_get_devtype(NULL), errno);
                        errno = 0; show_str("driver", udev_device_get_driver(NULL), errno);
                        errno = 0; show_str("action", udev_device_get_action(NULL), errno);
                        errno = 0; show_str("property", udev_device_get_property_value(NULL, "X"), errno);
                        errno = 0; show_str("property2", udev_device_get_property_value(cur, NULL), errno);
                        errno = 0; show_str("attr", udev_device_get_sysattr_value(NULL, "x"), errno);
                        errno = 0; printf("devnum=%d errno=%s\n", (int) udev_device_get_devnum(NULL), ename(errno));
                        errno = 0; printf("seqnum=%llu errno=%s\n", udev_device_get_seqnum(NULL), ename(errno));
                        errno = 0; printf("usec=%lld errno=%s\n", (long long) udev_device_get_usec_since_initialized(NULL), ename(errno));
                        printf("is_initialized=%d\n", udev_device_get_is_initialized(NULL));
                        printf("has_tag=%d has_current_tag=%d\n", udev_device_has_tag(NULL, "x"), udev_device_has_current_tag(NULL, "x"));
                        printf("setattr=%d\n", udev_device_set_sysattr_value(NULL, "x", "y"));
                        errno = 0; printf("parent=%s errno=%s\n", udev_device_get_parent(NULL) ? "?" : "(null)", ename(errno));
                        errno = 0; printf("parent-st=%s errno=%s\n", udev_device_get_parent_with_subsystem_devtype(NULL, "x", NULL) ? "?" : "(null)", ename(errno));
                        errno = 0; printf("udev=%s errno=%s\n", udev_device_get_udev(NULL) ? "?" : "(null)", ename(errno));
                        errno = 0; printf("lists=%s%s%s%s%s errno=%s\n",
                                          udev_device_get_properties_list_entry(NULL) ? "?" : "-",
                                          udev_device_get_devlinks_list_entry(NULL) ? "?" : "-",
                                          udev_device_get_tags_list_entry(NULL) ? "?" : "-",
                                          udev_device_get_current_tags_list_entry(NULL) ? "?" : "-",
                                          udev_device_get_sysattr_list_entry(NULL) ? "?" : "-", ename(errno));
                        printf("ref=%s unref=%s\n", udev_device_ref(NULL) ? "?" : "(null)", udev_device_unref(NULL) ? "?" : "(null)");
                        printf("enumerate: %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
                               udev_enumerate_add_match_subsystem(NULL, "x"),
                               udev_enumerate_add_nomatch_subsystem(NULL, "x"),
                               udev_enumerate_add_match_sysattr(NULL, "x", NULL),
                               udev_enumerate_add_nomatch_sysattr(NULL, "x", NULL),
                               udev_enumerate_add_match_property(NULL, "x", NULL),
                               udev_enumerate_add_match_tag(NULL, "x"),
                               udev_enumerate_add_match_parent(NULL, NULL),
                               udev_enumerate_add_match_is_initialized(NULL),
                               udev_enumerate_add_match_sysname(NULL, "x"),
                               udev_enumerate_add_syspath(NULL, "x"),
                               udev_enumerate_scan_devices(NULL),
                               udev_enumerate_scan_subsystems(NULL),
                               udev_enumerate_ref(NULL) != NULL);
                        errno = 0; printf("enumerate list=%s errno=%s\n", udev_enumerate_get_list_entry(NULL) ? "?" : "(null)", ename(errno));
                        errno = 0; printf("enumerate udev=%s errno=%s\n", udev_enumerate_get_udev(NULL) ? "?" : "(null)", ename(errno));
                        printf("monitor: %d %d %d %d %d %d %d %d %s %s\n",
                               udev_monitor_filter_update(NULL),
                               udev_monitor_enable_receiving(NULL),
                               udev_monitor_set_receive_buffer_size(NULL, 1),
                               udev_monitor_get_fd(NULL),
                               udev_monitor_filter_add_match_subsystem_devtype(NULL, "x", NULL),
                               udev_monitor_filter_add_match_tag(NULL, "x"),
                               udev_monitor_filter_remove(NULL),
                               udev_monitor_ref(NULL) != NULL,
                               udev_monitor_get_udev(NULL) ? "?" : "(null)",
                               udev_monitor_receive_device(NULL) ? "?" : "(null)");
                        printf("queue: %d %d %s %s\n", udev_queue_get_fd(NULL), udev_queue_flush(NULL),
                               udev_queue_get_udev(NULL) ? "?" : "(null)", udev_queue_ref(NULL) ? "?" : "(null)");
                        printf("hwdb: %s %s\n", udev_hwdb_ref(NULL) ? "?" : "(null)", udev_hwdb_unref(NULL) ? "?" : "(null)");
                        printf("list: %s %s %s %s\n",
                               udev_list_entry_get_next(NULL) ? "?" : "(null)",
                               udev_list_entry_get_by_name(NULL, "x") ? "?" : "(null)",
                               udev_list_entry_get_name(NULL) ? "?" : "(null)",
                               udev_list_entry_get_value(NULL) ? "?" : "(null)");
                } else if (strcmp(c, "thread-unref") == 0) {
                        pthread_t t;
                        struct udev_device *d = cur;
                        cur = NULL;
                        pthread_create(&t, NULL, unref_thread, d);
                        pthread_join(t, NULL);
                        printf("thread-unref: done\n");
                } else {
                        fprintf(stderr, "probe: unknown command %s\n", c);
                        return 2;
                }
        }

        udev_device_unref(cur);
        udev_enumerate_unref(en);
        udev_monitor_unref(mon);
        udev_hwdb_unref(hw);
        udev_queue_unref(q);
        printf("unref: %s\n", udev_unref(u) ? "?" : "(null)");
        return 0;
}
