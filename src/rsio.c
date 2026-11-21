/* small IPC framework that allows bi-directional communication between
   parent/child processes including the ability to pass fds/sockets

   (C)Copyright 2013-2026 Simon Urbanek

   License: 2-clause BSD

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this
      list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
      ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
      WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
      DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
      ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
      (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
      LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
      ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
      SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "rsio.h"

#if defined WIN32 || defined _WIN32
/* there is no fork() on Windows so rsio is pointless - just provide stubs */
rsio_t *rsio_new(void) { return 0; }
void rsio_free(rsio_t *io) {}
void rsio_close(rsio_t *io) {}
void rsio_set_parent(rsio_t *io) {}
void rsio_set_child(rsio_t *io) {}
void rsio_set_max_len(rsio_t *io, rsmsglen_t max_len) {}
void rsio_set_write_timeout(rsio_t *io, int timeout_ms) {}
int  rsio_fd(rsio_t *io) { return -1; }
int  rsio_read_status(rsio_t *io) { return -1; }
rsmsg_t *rsio_read_msg(rsio_t *io, int timeout_ms) { return 0; }
void rsmsg_free(rsmsg_t *msg) {}
int  rsio_write(rsio_t *io, const void *buf, rsmsglen_t len, unsigned int cmd, int fd) { return RSIO_EINVAL; }
int  rsio_write_msg(rsio_t *io, const rsmsg_t *msg) { return RSIO_EINVAL; }

#else
/* real implementation using socketpair() on unix */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef MSG_NOSIGNAL
#define RSIO_SEND_FLAGS MSG_NOSIGNAL
#else
#define RSIO_SEND_FLAGS 0
#endif

#define MAX_CHUNK (1024*1024)  /* max. payload size per send/recv call */
#define MAX_RECV_FDS 4         /* we accept one fd, but make room to detect (and close) extra ones */

/* wire header (native byte order - both ends are on the same machine) */
#define RSIO_MAGIC      0x52534900U  /* "RSI\0" */
#define RSIO_MAGIC_MASK 0xffffff00U
#define RSIO_HFL_FD     0x01U        /* an fd is attached to this message */
#define HDR_SIZE 16

typedef struct {
    unsigned int magic;  /* RSIO_MAGIC | flags */
    unsigned int cmd;
    rsmsglen_t   len;
} iohdr_t;

struct rsio {
    int fd[2];          /* [0] = parent's end, [1] = child's end */
    int side;           /* -1 = not set yet, 0 = parent, 1 = child */
    rsmsglen_t max_len;
    int wtimeout;
    /* incoming message state */
    union { iohdr_t h; unsigned char b[HDR_SIZE]; } hdr;
    size_t hdr_got;     /* bytes of the header received so far */
    int pending_fd;     /* fd received with the current header */
    rsmsg_t *msg;       /* message being received (payload phase) */
    rsmsglen_t got;     /* payload bytes received so far */
    struct rsio *prev, *next;
};

/* all live channels in this process - needed so a child can close all channels it
   inherited from the parent which don't belong to it */
static rsio_t *channels;

static long long now_ms(void) {
#ifdef CLOCK_MONOTONIC
    struct timespec ts;
    if (!clock_gettime(CLOCK_MONOTONIC, &ts))
	return ((long long) ts.tv_sec) * 1000LL + (long long) (ts.tv_nsec / 1000000);
#endif
    {
	struct timeval tv;
	gettimeofday(&tv, 0);
	return ((long long) tv.tv_sec) * 1000LL + (long long) (tv.tv_usec / 1000);
    }
}

/* remaining time in ms for poll() given a start time and timeout (-1 = infinite) */
static int remaining_ms(long long start, int timeout) {
    long long left;
    if (timeout < 0) return -1;
    left = ((long long) timeout) - (now_ms() - start);
    return (left < 0) ? 0 : (int) left;
}

/* poll for events on a single fd, retrying on EINTR.
   1 = ready, 0 = timeout, -1 = error */
static int wait_fd(int fd, short events, long long start, int timeout) {
    while (1) {
	struct pollfd pfd;
	int r;
	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;
	r = poll(&pfd, 1, remaining_ms(start, timeout));
	if (r < 0 && errno == EINTR) continue;
	if (r < 0) return -1;
	return r ? 1 : 0;
    }
}

static int setup_fd(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl == -1 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) return -1;
    fl = fcntl(fd, F_GETFD);
    if (fl == -1 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == -1) return -1;
#ifdef SO_NOSIGPIPE
    { /* macOS/BSD don't have MSG_NOSIGNAL */
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif
    return 0;
}

static int my_fd(rsio_t *io) {
    return (io && io->side >= 0) ? io->fd[io->side] : -1;
}

static void reset_read_state(rsio_t *io) {
    if (io->msg) {
	rsmsg_free(io->msg); /* also closes its fd */
	io->msg = 0;
    }
    if (io->pending_fd != -1) {
	close(io->pending_fd);
	io->pending_fd = -1;
    }
    io->hdr_got = 0;
    io->got = 0;
}

rsio_t *rsio_new(void) {
    rsio_t *io = (rsio_t*) calloc(1, sizeof(rsio_t));
    if (!io) return 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, io->fd)) {
	free(io);
	return 0;
    }
    if (setup_fd(io->fd[0]) || setup_fd(io->fd[1])) {
	close(io->fd[0]);
	close(io->fd[1]);
	free(io);
	return 0;
    }
    io->side = -1;
    io->max_len = RSIO_DEFAULT_MAX_LEN;
    io->wtimeout = -1;
    io->pending_fd = -1;
    io->next = channels;
    if (channels) channels->prev = io;
    channels = io;
    return io;
}

void rsio_close(rsio_t *io) {
    if (!io) return;
    if (io->fd[0] != -1) { close(io->fd[0]); io->fd[0] = -1; }
    if (io->fd[1] != -1) { close(io->fd[1]); io->fd[1] = -1; }
    reset_read_state(io);
}

void rsio_free(rsio_t *io) {
    if (!io) return;
    rsio_close(io);
    if (io->prev) io->prev->next = io->next; else if (channels == io) channels = io->next;
    if (io->next) io->next->prev = io->prev;
    free(io);
}

void rsio_set_parent(rsio_t *io) {
    if (!io) return;
    if (io->fd[1] != -1) { close(io->fd[1]); io->fd[1] = -1; }
    io->side = 0;
}

void rsio_set_child(rsio_t *io) {
    rsio_t *c = channels;
    /* close all other channels inherited from the parent - they belong to
       our siblings (or the parent's other business). We cannot free them
       since the parent's data structures (copied into us) may still point
       to them, but they are rendered inert. */
    while (c) {
	if (c != io) {
	    rsio_close(c);
	    c->side = -1;
	}
	c = c->next;
    }
    if (!io) return;
    if (io->fd[0] != -1) { close(io->fd[0]); io->fd[0] = -1; }
    io->side = 1;
}

void rsio_set_max_len(rsio_t *io, rsmsglen_t max_len) {
    if (io) io->max_len = max_len;
}

void rsio_set_write_timeout(rsio_t *io, int timeout_ms) {
    if (io) io->wtimeout = timeout_ms;
}

int rsio_fd(rsio_t *io) {
    return my_fd(io);
}

void rsmsg_free(rsmsg_t *msg) {
    if (!msg) return;
    if (msg->fd != -1) close(msg->fd);
    free(msg);
}

/* fatal read error - close the channel */
static int read_fail(rsio_t *io) {
    rsio_close(io);
    return -1;
}

/* collect fds from the control messages, keep the first one (if we don't
   have one already), close all others. Returns -1 if the control data was
   truncated (fds lost) */
static int collect_fds(rsio_t *io, struct msghdr *mh) {
    struct cmsghdr *cm;
    if (mh->msg_controllen > 0)
	for (cm = CMSG_FIRSTHDR(mh); cm; cm = CMSG_NXTHDR(mh, cm)) {
	    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
		int i, nfd = (int) ((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
		int *fds = (int*) CMSG_DATA(cm);
		for (i = 0; i < nfd; i++) {
		    int rfd;
		    memcpy(&rfd, fds + i, sizeof(int)); /* may be unaligned */
		    if (rfd < 0) continue;
		    if (io->pending_fd == -1 && io->hdr_got == 0 && i == 0)
			io->pending_fd = rfd;
		    else
			close(rfd);
		}
	    }
	}
    return (mh->msg_flags & MSG_CTRUNC) ? -1 : 0;
}

int rsio_read_status(rsio_t *io) {
    int fd = my_fd(io);
    if (fd == -1) return -1;
    while (1) {
	if (io->hdr_got < HDR_SIZE) { /* header phase - use recvmsg to get any fds */
	    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int) * MAX_RECV_FDS)]; } cbuf;
	    struct msghdr mh;
	    struct iovec iov;
	    ssize_t n;
	    memset(&mh, 0, sizeof(mh));
	    iov.iov_base = io->hdr.b + io->hdr_got;
	    iov.iov_len  = HDR_SIZE - io->hdr_got;
	    mh.msg_iov = &iov;
	    mh.msg_iovlen = 1;
	    mh.msg_control = cbuf.buf;
	    mh.msg_controllen = sizeof(cbuf.buf);
	    n = recvmsg(fd, &mh, 0);
	    if (n < 0) {
		if (errno == EINTR) continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
		return read_fail(io);
	    }
	    if (n == 0) /* EOF */
		return read_fail(io);
	    if (collect_fds(io, &mh))
		return read_fail(io);
	    io->hdr_got += (size_t) n;
	    if (io->hdr_got == HDR_SIZE) { /* complete header */
		iohdr_t *h = &io->hdr.h;
		int has_fd = (h->magic & RSIO_HFL_FD) ? 1 : 0;
		if ((h->magic & RSIO_MAGIC_MASK) != RSIO_MAGIC || /* garbage */
		    has_fd != ((io->pending_fd == -1) ? 0 : 1) || /* fd mismatch */
		    (io->max_len && h->len > io->max_len) ||    /* too big */
		    h->len > (rsmsglen_t) ((size_t) -1) - sizeof(rsmsg_t) - 1) /* can't allocate */
		    return read_fail(io);
		io->msg = (rsmsg_t*) malloc(sizeof(rsmsg_t) + (size_t) h->len + 1);
		if (!io->msg)
		    return read_fail(io);
		io->msg->cmd = h->cmd;
		io->msg->len = h->len;
		io->msg->fd  = io->pending_fd;
		io->msg->data[h->len] = 0;
		io->pending_fd = -1;
		io->got = 0;
	    }
	    continue;
	}
	/* payload phase */
	if (io->got >= io->msg->len)
	    return 1;
	{
	    rsmsglen_t left = io->msg->len - io->got;
	    size_t chunk = (left > MAX_CHUNK) ? MAX_CHUNK : (size_t) left;
	    /* NOTE: we never read beyond the end of the message, so we cannot
	       accidentally consume (and lose) fds attached to the next one */
	    ssize_t n = recv(fd, io->msg->data + io->got, chunk, 0);
	    if (n < 0) {
		if (errno == EINTR) continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
		return read_fail(io);
	    }
	    if (n == 0)
		return read_fail(io);
	    io->got += (rsmsglen_t) n;
	}
    }
}

rsmsg_t *rsio_read_msg(rsio_t *io, int timeout_ms) {
    long long start = now_ms();
    while (1) {
	int st = rsio_read_status(io);
	if (st == 1) {
	    rsmsg_t *msg = io->msg;
	    io->msg = 0;
	    io->hdr_got = 0;
	    io->got = 0;
	    return msg;
	}
	if (st < 0) return 0;
	if (timeout_ms == 0) return 0;
	st = wait_fd(my_fd(io), POLLIN, start, timeout_ms);
	if (st == 0) return 0; /* timeout */
	if (st < 0) {
	    rsio_close(io);
	    return 0;
	}
    }
}

int rsio_write(rsio_t *io, const void *buf, rsmsglen_t len, unsigned int cmd, int fd) {
    int sfd = my_fd(io);
    iohdr_t hdr;
    rsmsglen_t total, sent = 0;
    long long start = now_ms();
    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } cbuf;

    if (sfd == -1 || (len && !buf) || len > (rsmsglen_t) ((size_t) -1) - HDR_SIZE)
	return RSIO_EINVAL;

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = RSIO_MAGIC | ((fd != -1) ? RSIO_HFL_FD : 0);
    hdr.cmd   = cmd;
    hdr.len   = len;
    total = HDR_SIZE + len;

    while (sent < total) {
	struct msghdr mh;
	struct iovec iov[2];
	int niov = 0;
	ssize_t n;
	memset(&mh, 0, sizeof(mh));
	if (sent < HDR_SIZE) {
	    iov[niov].iov_base = ((char*) &hdr) + sent;
	    iov[niov].iov_len  = HDR_SIZE - (size_t) sent;
	    niov++;
	    if (len) {
		iov[niov].iov_base = (void*) buf;
		iov[niov].iov_len  = (len > MAX_CHUNK) ? MAX_CHUNK : (size_t) len;
		niov++;
	    }
	} else {
	    rsmsglen_t off = sent - HDR_SIZE, left = len - off;
	    iov[niov].iov_base = ((char*) buf) + off;
	    iov[niov].iov_len  = (left > MAX_CHUNK) ? MAX_CHUNK : (size_t) left;
	    niov++;
	}
	mh.msg_iov = iov;
	mh.msg_iovlen = niov;
	if (sent == 0 && fd != -1) { /* the fd travels with the first byte */
	    struct cmsghdr *cm;
	    memset(&cbuf, 0, sizeof(cbuf));
	    mh.msg_control = cbuf.buf;
	    mh.msg_controllen = sizeof(cbuf.buf);
	    cm = CMSG_FIRSTHDR(&mh);
	    cm->cmsg_level = SOL_SOCKET;
	    cm->cmsg_type  = SCM_RIGHTS;
	    cm->cmsg_len   = CMSG_LEN(sizeof(int));
	    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	}
	n = sendmsg(sfd, &mh, RSIO_SEND_FLAGS);
	if (n < 0) {
	    if (errno == EINTR) continue;
	    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
		int w, tout = io->wtimeout;
		if (sent == 0 && tout == 0) return RSIO_EAGAIN;
		/* once a part of the message was sent we must finish it or the
		   stream is corrupted, so allow some grace time beyond the timeout */
		if (sent > 0 && tout >= 0) tout += 1000;
		w = wait_fd(sfd, POLLOUT, start, tout);
		if (w > 0) continue;
		if (w == 0 && sent == 0) return RSIO_EAGAIN; /* timeout, nothing sent - still usable */
	    }
	    /* any other error or a timeout mid-message (stream is corrupted) */
	    rsio_close(io);
	    return RSIO_ERR;
	}
	sent += (rsmsglen_t) n;
    }
    return RSIO_OK;
}

int rsio_write_msg(rsio_t *io, const rsmsg_t *msg) {
    if (!msg) return RSIO_EINVAL;
    return rsio_write(io, msg->data, msg->len, msg->cmd, msg->fd);
}

#endif /* unix implementation */
