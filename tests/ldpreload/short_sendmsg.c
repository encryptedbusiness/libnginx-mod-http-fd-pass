/*
 * short_sendmsg.c - LD_PRELOAD fault injector for the fd_pass handoff.
 *
 * Only control-bearing sendmsg calls (the SCM_RIGHTS handoff) are affected:
 *  - every 4th call returns EAGAIN before sending;
 *  - otherwise the iovec is truncated to at most 5 bytes, so the module must
 *    retry the remainder without re-sending the fd.
 *
 * Build (aarch64 Linux):
 *   gcc -shared -fPIC -O2 -o short_sendmsg.so short_sendmsg.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
static int control_calls;

ssize_t
sendmsg(int fd, const struct msghdr *msg, int flags)
{
    struct iovec  iov[8];
    struct msghdr m;
    size_t        cap, len, total;
    int           i, n;

    if (real_sendmsg == NULL) {
        real_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))
                       dlsym(RTLD_NEXT, "sendmsg");
    }

    if (msg == NULL || msg->msg_control == NULL || msg->msg_controllen == 0) {
        return real_sendmsg(fd, msg, flags);
    }

    control_calls++;

    if ((control_calls % 4) == 0) {
        errno = EAGAIN;
        return -1;
    }

    /* Force a short write of at most 5 bytes, keeping the control message. */
    m = *msg;
    cap = 5;
    total = 0;
    n = 0;

    for (i = 0; i < (int) msg->msg_iovlen && i < 8 && cap > 0; i++) {
        len = msg->msg_iov[i].iov_len;
        if (len > cap) {
            len = cap;
        }
        iov[n].iov_base = msg->msg_iov[i].iov_base;
        iov[n].iov_len = len;
        total += len;
        cap -= len;
        n++;
    }

    m.msg_iov = iov;
    m.msg_iovlen = n;

    return real_sendmsg(fd, &m, flags);
}
