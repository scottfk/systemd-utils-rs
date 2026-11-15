/*
 * faketime.c - LD_PRELOAD clock for the differential tests
 *
 * 20261111 - Created by Claude (claude.ai, Anthropic) - scottfk
 * 20261111 - Copied from metalog-rs for the cronie-rs tests; $TEST_FAKETIME - Claude - scottfk
 * 20261111 - Virtual sleep() for crond ($TEST_VIRTUAL_SLEEP, $TEST_STOP) - Claude - scottfk
 * 20261111 - Virtual alarm() for anacron - Claude - scottfk
 * 20261115 - Copied from cronie-rs for the logrotate-rs tests - Claude - scottfk
 * 20261115 - Copied from logrotate-rs for the systemd-utils-rs tests - Claude - scottfk
 *
 * If $TEST_FAKETIME names a readable file holding "SECONDS NANOSECONDS",
 * time(), gettimeofday() and clock_gettime(CLOCK_REALTIME) return that
 * instant.  The file is re-read on every call, so a test steps the clock by
 * rewriting it.  Other clocks (CLOCK_MONOTONIC) pass
 * through.  Both the C reference and the Rust port call these through the PLT,
 * so one shim controls both.  errno is preserved: the C code prints
 * it after unrelated calls.
 *
 * With $TEST_VIRTUAL_SLEEP set, sleep() doesn't sleep: it waits until every
 * child of the caller has finished (is a zombie or gone), then moves the
 * fake clock forward by the requested seconds.  So crond runs a day of
 * minutes in moments, and each minute's jobs are done before the next one
 * starts.  If that would reach $TEST_STOP (seconds), the clock stops there
 * and the process gets SIGTERM, for a clean shutdown.  alarm(n) works the
 * same way, then raises SIGALRM at once (anacron waits with alarm() and
 * sigsuspend()).
 *
 * Build: cc -shared -fPIC -O2 -o faketime.so faketime.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fake(struct timespec *ts)
{
    const char *f = getenv("TEST_FAKETIME");
    char buf[64];
    long long s = 0, ns = 0;
    int fd, n, saved = errno, i = 0, neg = 0;

    if (!f || (fd = open(f, O_RDONLY | O_CLOEXEC)) < 0) {
        errno = saved;
        return 0;
    }
    n = (int) read(fd, buf, sizeof buf - 1);
    close(fd);
    errno = saved;
    if (n <= 0)
        return 0;
    buf[n] = 0;
    /* No stdio here: the Rust port emulates stdio buffering, and the C
     * reference's FILE list should look the same with or without us. */
    if (buf[i] == '-') {
        neg = 1;
        i++;
    }
    while (buf[i] >= '0' && buf[i] <= '9')
        s = s * 10 + (buf[i++] - '0');
    while (buf[i] == ' ')
        i++;
    while (buf[i] >= '0' && buf[i] <= '9')
        ns = ns * 10 + (buf[i++] - '0');
    ts->tv_sec = neg ? -s : s;
    ts->tv_nsec = ns;
    return 1;
}

int clock_gettime(clockid_t id, struct timespec *ts)
{
    static int (*real)(clockid_t, struct timespec *);

    if (id == CLOCK_REALTIME && fake(ts))
        return 0;
    if (!real)
        real = (int (*)(clockid_t, struct timespec *)) dlsym(RTLD_NEXT, "clock_gettime");
    return real(id, ts);
}

time_t time(time_t *t)
{
    struct timespec ts;

    if (!fake(&ts))
        clock_gettime(CLOCK_REALTIME, &ts);
    if (t)
        *t = ts.tv_sec;
    return ts.tv_sec;
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz)
{
    struct timespec ts;

    (void) tz;
    if (!fake(&ts))
        clock_gettime(CLOCK_REALTIME, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
    return 0;
}

/* All of our children finished (zombies or reaped)? */
static int children_done(void)
{
    char path[64], buf[4096], stat[512];
    int fd, n, i = 0;

    snprintf(path, sizeof path, "/proc/self/task/%d/children", (int) getpid());
    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
        return 1;
    n = (int) read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 1;
    buf[n] = 0;
    while (i < n) {
        long pid = 0;
        while (i < n && (buf[i] < '0' || buf[i] > '9'))
            i++;
        if (i >= n)
            break;
        while (i < n && buf[i] >= '0' && buf[i] <= '9')
            pid = pid * 10 + (buf[i++] - '0');
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
            continue;
        int m = (int) read(fd, stat, sizeof stat - 1);
        close(fd);
        if (m <= 0)
            continue;
        stat[m] = 0;
        char *p = strrchr(stat, ')');
        if (p && p[1] == ' ' && p[2] != 'Z' && p[2] != 'X')
            return 0;
    }
    return 1;
}

static void advance(unsigned int secs, int *stopping);

unsigned int alarm(unsigned int secs)
{
    static unsigned int (*real)(unsigned int);
    int stopping = 0;

    if (!getenv("TEST_FAKETIME") || !getenv("TEST_VIRTUAL_SLEEP")) {
        if (!real)
            real = (unsigned int (*)(unsigned int)) dlsym(RTLD_NEXT, "alarm");
        return real(secs);
    }
    if (secs == 0)
        return 0;
    advance(secs, &stopping);
    kill(getpid(), stopping ? SIGTERM : SIGALRM);
    return 0;
}

unsigned int sleep(unsigned int secs)
{
    static unsigned int (*real)(unsigned int);
    int stopping = 0;

    if (!getenv("TEST_FAKETIME") || !getenv("TEST_VIRTUAL_SLEEP")) {
        if (!real)
            real = (unsigned int (*)(unsigned int)) dlsym(RTLD_NEXT, "sleep");
        return real(secs);
    }
    advance(secs, &stopping);
    if (stopping)
        kill(getpid(), SIGTERM);
    return 0;
}

/* Wait for our children, then move the fake clock on by secs (stopping at
 * $TEST_STOP, if set). */
static void advance(unsigned int secs, int *stopping)
{
    const char *f = getenv("TEST_FAKETIME");
    const char *stop = getenv("TEST_STOP");
    struct timespec ts, nap = { 0, 2000000 };
    char buf[64], tmp[4096];
    int fd, saved = errno, n;

    while (!children_done())
        nanosleep(&nap, NULL);
    if (!fake(&ts))
        return;
    ts.tv_sec += secs;
    *stopping = stop && ts.tv_sec >= atoll(stop);
    if (*stopping)
        ts.tv_sec = atoll(stop);
    n = snprintf(buf, sizeof buf, "%lld %ld\n", (long long) ts.tv_sec, (long) ts.tv_nsec);
    snprintf(tmp, sizeof tmp, "%s.tmp", f);
    if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)) >= 0) {
        if (write(fd, buf, (size_t) n) < 0) { /* the clock just stays */ }
        close(fd);
        rename(tmp, f);
    }
    errno = saved;
}
