// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file control.c
 * @brief Control socket (Unix stream socket, one command per connection)
 */

#include "control.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

static constexpr time_t IO_TIMEOUT_SEC = 2;          ///< send and receive timeout of a control connection
static constexpr uint64_t CMD_TIMEOUT_MS = 200;      ///< the daemon waits this long at most for a command
static constexpr uint64_t NSEC_PER_MSEC = 1'000'000; ///< nanoseconds per millisecond

static int make_addr(const char *path, struct sockaddr_un *sa) {
    memset(sa, 0, sizeof(*sa));
    if (strlen(path) >= sizeof(sa->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, path, strlen(path) + 1);
    return 0;
}

static void set_timeouts(int fd) {
    const struct timeval tv = {.tv_sec = IO_TIMEOUT_SEC};

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Create the parent directory of path (one level) if it does not exist. */
static int make_parent_dir(const char *path) {
    char dir[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char *slash = nullptr;

    memcpy(dir, path, strlen(path) + 1);
    slash = strrchr(dir, '/');
    if (!slash || slash == dir)
        return 0;
    *slash = '\0';
    if (mkdir(dir, 0755) && errno != EEXIST)
        return -1;
    return 0;
}

/* Close fd without losing the errno of the failure being reported. */
static int fail_close(int fd, int err) {
    if (fd >= 0)
        (void)close(fd);
    errno = err;
    return -1;
}

/* Whether something answers at a Unix socket: a socket nobody listens on refuses the connection. */
static bool answers(const struct sockaddr_un *sa) {
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    bool alive = true; // what cannot be checked is kept

    if (fd < 0)
        return alive;
    if (connect(fd, (const struct sockaddr *)sa, sizeof(*sa)) && (errno == ECONNREFUSED || errno == ENOENT))
        alive = false;
    (void)close(fd);
    return alive;
}

int control_listen(const char *path, int *lock_fd) {
    char lock_path[sizeof(((struct sockaddr_un *)0)->sun_path) + sizeof(".lock")];
    struct sockaddr_un sa;
    struct stat st;
    mode_t old_mask = 0;
    int lock = -1;
    int fd = -1;

    if (make_addr(path, &sa) || make_parent_dir(path))
        return -1;

    // A lock decides whether another tcxflow owns the socket, not a connect() probe: two instances
    // starting at once could both find the socket stale and take it from each other.
    (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    lock = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0)
        return -1;
    if (flock(lock, LOCK_EX | LOCK_NB))
        return fail_close(lock, errno == EWOULDBLOCK ? EADDRINUSE : errno);
    // With the lock held, no other tcxflow uses a socket left at the path. Another program might
    // (the configuration names its socket): it is deleted only if nobody answers there.
    if (!lstat(path, &st)) {
        if (!S_ISSOCK(st.st_mode))
            return fail_close(lock, EEXIST);
        if (answers(&sa))
            return fail_close(lock, EADDRINUSE);
        if (unlink(path) && errno != ENOENT)
            return fail_close(lock, errno);
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return fail_close(lock, errno);
    old_mask = umask(0177); // socket file mode 0600: the counters reveal traffic, so root only
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) || listen(fd, 8)) {
        const int err = errno;

        (void)umask(old_mask);
        (void)close(fd);
        return fail_close(lock, err);
    }
    (void)umask(old_mask);
    *lock_fd = lock;
    return fd;
}

int control_accept(int listen_fd, char *cmd, size_t cmdlen) {
    const int fd = accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
    const uint64_t deadline = clock_ns(CLOCK_MONOTONIC) + (CMD_TIMEOUT_MS * NSEC_PER_MSEC);
    size_t len = 0;

    if (fd < 0)
        return -1;
    set_timeouts(fd);
    // One deadline for the whole command: a slow client must not hold up the exporter.
    while (len + 1 < cmdlen && !memchr(cmd, '\n', len)) {
        const uint64_t now = clock_ns(CLOCK_MONOTONIC);
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        ssize_t n = 0;

        if (now >= deadline || poll(&pfd, 1, (int)((deadline - now) / NSEC_PER_MSEC) + 1) <= 0)
            break;
        n = read(fd, cmd + len, cmdlen - 1 - len);
        if (n <= 0)
            break;
        len += (size_t)n;
    }
    cmd[len] = '\0';
    cmd[strcspn(cmd, "\r\n")] = '\0';
    // Replies are written non-blocking: a client that stops reading gets a cut-off reply, it
    // cannot stall the exporter (a reply is a few KiB and normally fits the socket buffer).
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

int control_request(const char *path, const char *cmd, FILE *out) {
    struct sockaddr_un sa;
    char buf[4096];
    size_t received = 0;
    ssize_t n = 0;
    int fd = -1;

    if (make_addr(path, &sa))
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    set_timeouts(fd);
    if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) || dprintf(fd, "%s\n", cmd) < 0) {
        const int err = errno;

        (void)close(fd);
        errno = err;
        return -1;
    }
    (void)shutdown(fd, SHUT_WR);
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        received += (size_t)n;
        if (fwrite(buf, 1, (size_t)n, out) != (size_t)n)
            break;
    }
    (void)close(fd);
    // tcxflow always answers: no reply at all comes from something else at the path.
    if (!n && !received) {
        errno = ENODATA;
        return -1;
    }
    // A failed write (full disk, closed pipe) must not look like success to a script.
    return n < 0 || ferror(out) || fflush(out) ? -1 : 0;
}
