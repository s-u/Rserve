/* small IPC framework that allows bi-directional communication between
   parent/child processes including the ability to pass fds/sockets

   (C)Copyright 2013 Simon Urbanek
   
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

/* --- non-API --- */

#ifdef WIN32
/* we could emulate socketpair() on Windows, but it's pointless since
   there is no fork() -- so just plug in empty stubs for now.
*/
rsio_t *rsio_new() { return 0; }
void rsio_free(rsio_t *io) {}
void rsio_close(rsio_t *io) {}
void rsio_set_child(rsio_t *io) {}
void rsio_set_parent(rsio_t *io) {}
void rsmsg_free(rsmsg_t *msg) {}
rsmsg_t *rsio_read_msg(rsio_t *io) { return 0; }
int  rsio_write(rsio_t *io, const void *buf, rsmsglen_t len, int cmd, int fd) { return -1; }
int  rsio_write_msg(rsio_t *io, rsmsg_t *msg) { return -1; }
int  rsio_select_fd(rsio_t *io) { return -1; }
int  rsio_read_status(rsio_t *io) { return -1; }

#else
/* real implementation using socketpair() on unix */

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
/* #include <sys/select.h> -- man page says this is new ... */

#define MAX_IO_PIPES 2048
#define MAX_CHUNK    (1024*1024)  /* max send size */

/* internal flags inside rsio */
#define RSIO_IN_USE  0x02
#define RSIO_CHILD   0x01 /* it *must* be 1 since we use fd[flags & RSIO_CHILD] */

struct rsio {
    int fd[2];
    unsigned int flags, location;
    rsmsg_t   *read_msg;  /* in-flight message being read (incomplete) */
    rsmsglen_t read_msg_complete; /* number of completed bytes in the message */
};

/* we keep a static pool to avoid allocations */
static rsio_t io_pool[MAX_IO_PIPES];
static int io_pool_max, io_pool_count;

#ifdef RSIO_DEBUG
#include <stdio.h>
#endif

rsio_t *rsio_new() {
    rsio_t *io;
    unsigned int i = io_pool_max;
    if (io_pool_count < io_pool_max) /* there is a hole - find it */
	for (i = 0; i < io_pool_max; i++)
	    if (!(io_pool[i].flags & RSIO_IN_USE)) break;
    if (i >= MAX_IO_PIPES) return 0;
    io = io_pool + i;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, io->fd))
	return 0;
    io->flags = RSIO_IN_USE;
    io->location = i;
    io->read_msg = 0;
    io->read_msg_complete = 0;
    io_pool_count++;
    if (io_pool_max == i) io_pool_max++;
    return io;
}

void rsio_close(rsio_t *io) {
    if (io) {
	close(io->fd[0]);
	io->fd[0] = -1;
	close(io->fd[1]);
	io->fd[1] = -1;
	if (io->read_msg) {
	    rsmsg_free(io->read_msg);
	    io->read_msg = 0;
	}
    }
}

void rsio_free(rsio_t *io) {
    if (io) {
	rsio_close(io);
	io->flags = 0;
	if (io->location < io_pool_max) {
	    io_pool_count--;
	    /* shrink as much as possible */
	    while (io_pool_max && ((io_pool[io_pool_max - 1].flags & RSIO_IN_USE) == 0))
		io_pool_max--;
	}
    }
}

void rsio_set_child(rsio_t *io) {
    if (io) {
	io->flags |= RSIO_CHILD;
	close(io->fd[0]);
    }
}

void rsio_set_parent(rsio_t *io) {
    if (io) {
	close(io->fd[1]);
    }
}

void rsmsg_free(rsmsg_t *msg) {
    free(msg);
}

#define CMD_HAS_FD 0x010000
#define CMD_LONG   0x020000
#define CMD_MASK   0x00ffff

typedef struct {
    int cmd;
    unsigned int len1, len2;
} iohdr_t;

/* global buffers for the control - their size is not a constant so we can't allocate them at compile time */
static struct cmsghdr *cmsg_send, *cmsg_recv;

static rsmsg_t *rsio_read_msg_init(rsio_t *io) {
    struct msghdr  msg;
    struct iovec   iov;
    rsmsg_t *res;
    int n, clen = CMSG_LEN(sizeof(int)); /* for the FD */
    int fd;
    iohdr_t hdr;
    rsmsglen_t len;
    if (!io) return 0;
    fd = io->fd[io->flags & RSIO_CHILD];
    if (!cmsg_recv) cmsg_recv = malloc(clen);
    if (!cmsg_recv) return 0;
    cmsg_recv->cmsg_level = SOL_SOCKET;
    cmsg_recv->cmsg_type  = SCM_RIGHTS;
    cmsg_recv->cmsg_len   = clen;
    *(int*)CMSG_DATA(cmsg_recv) = -1; /* initialize recv FD to -1 */
    iov.iov_base    = &hdr;
    iov.iov_len     = 8; /* first 8 bytes are mandatory */
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    msg.msg_control = cmsg_recv;
    msg.msg_controllen = clen;
    n = (int) recvmsg(fd, &msg, MSG_WAITALL);
    if (n < 8) { /* we need at least 8 bytes */
#ifdef RSIO_DEBUG
	fprintf(stderr, "ERROR: rsio(%p)read: recvmsg got %d, expected 8\n", io, n);
#endif
	rsio_close(io);
	return 0;
    }
    len = hdr.len1;
    if (hdr.cmd & CMD_LONG) {
	if (recv(fd, &(hdr.len2), sizeof(hdr.len2), 0) != sizeof(hdr.len2)) {
#ifdef RSIO_DEBUG
	    fprintf(stderr, "ERROR: rsio(%p)read: cmd=0x%x -> LONG but receiving len2 failed\n", io, hdr.cmd);
#endif
	    rsio_close(io);
	    return 0;
	}
#ifdef __LP64__    
	len |= (((rsmsglen_t) hdr.len2) << 32);
#else
	if (hdr.len2) { /* 64-bit size requested, but we can't do that */
#ifdef RSIO_DEBUG
	    fprintf(stderr, "ERROR: rsio(%p)read: cmd=0x%x, 64-bit length on 32-bit system\n", io, hdr.cmd);
#endif
	    rsio_close(io);
	    return 0;
	}
#endif
    }
    /* guarantee one extra byte */
    res = malloc(sizeof(rsmsg_t) + len + 1);
    if (!res) {
#ifdef RSIO_DEBUG
	fprintf(stderr, "ERROR: rsio(%p)read: cannot allocate %lu bytes\n", io, (unsigned long) (sizeof(rsmsg_t) + len));
#endif
	rsio_close(io);
	return 0;
    }
    res->cmd = hdr.cmd & CMD_MASK;
    res->flags = (hdr.cmd & CMD_HAS_FD) ? RSMSG_HAS_FD : 0;
    res->fd = *(int*)CMSG_DATA(cmsg_recv);
    res->len = len;
    return res;
}

/* 0 = would block, 1 = complete message available, -1 = error */
static int rsio_read_msg_data(rsio_t *io, int block) {
    unsigned char *ptr;
    rsmsg_t *res = io->read_msg;
    rsmsglen_t len;
    int fd = io->fd[io->flags & RSIO_CHILD];
    if (!res) return -1;
    if (io->read_msg_complete == res->len) return 1;
    ptr = res->data + io->read_msg_complete;
    len = res->len - io->read_msg_complete;
    while (len) {
	unsigned int chunk = (unsigned int) ((len > MAX_CHUNK) ? MAX_CHUNK : len);
	int n;
	if (!block) {
	    struct timeval timv;
	    fd_set readfds;
	    timv.tv_sec = 0;
	    timv.tv_usec = 0;
	    FD_ZERO(&readfds);
	    FD_SET(fd, &readfds);
	    /* make sure we're non-blocking */
	    if (select(fd + 1, &readfds, 0, 0, &timv) != 1)
		return 0;
	}
	n = (int) recv(fd, ptr, chunk, 0);
	if (n < 1) {
#ifdef RSIO_DEBUG
	    fprintf(stderr, "ERROR: rsio(%p)read: cmd=0x%x, len=%lu, recv=%d (expected %d) with %lu bytes to go\n",
		    io, hdr.cmd, res->len, n, chunk, len);
#endif
	    rsio_close(io);
	    return -1;
	}
	len -= n;
	ptr += n;
	io->read_msg_complete += n;
    }
    return 1;
}

rsmsg_t *rsio_read_msg(rsio_t *io) {
    rsmsg_t *msg;

    if (!io->read_msg) { /* no stored message, get the header */
	if (!(io->read_msg = rsio_read_msg_init(io)))
	    return 0;
	io->read_msg_complete = 0;
    }

    /* read_msg is guaranteed non-NULL from here */
    if (rsio_read_msg_data(io, 1) < 0) /* use blocking read */
	return 0;

    /* here we are guaranteed to have a complete message */
    msg = io->read_msg;
    io->read_msg = 0;
    return msg;
}

/* -1 = error, 0 = read would block, 1 = complete message available */
int rsio_read_status(rsio_t *io) {
    if (!io->read_msg) { /* no header -- need to run init - but check for blocking first */
	int fd = io->fd[io->flags & RSIO_CHILD];
	int res;
	struct timeval timv;
	fd_set readfds;
	timv.tv_sec = 0;
	timv.tv_usec = 0;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	/* make sure we're non-blocking */
	res = select(fd + 1, &readfds, 0, 0, &timv);
	if (res < 0)
	    return -1;
	if (res != 1)
	    return 0;
	io->read_msg_complete = 0;
	io->read_msg = rsio_read_msg_init(io);
	if (!io->read_msg)
	    return -1;
    }
    /* io->read_msg is valid */
    return rsio_read_msg_data(io, 0);
}

int rsio_write(rsio_t *io, const void *buf, rsmsglen_t len, int cmd, int fd) {
    struct msghdr msg;
    struct iovec  iov[2];
    int clen = CMSG_LEN(sizeof(int));
    iohdr_t hdr;
    ssize_t n;

    if (!io) return -2;
    if (fd != -1) {
	if (!cmsg_send) cmsg_send = malloc(clen);
	if (!cmsg_send) return -1;
	cmsg_send->cmsg_level = SOL_SOCKET;
	cmsg_send->cmsg_type  = SCM_RIGHTS;
	cmsg_send->cmsg_len   = clen;
	*(int*)CMSG_DATA(cmsg_send) = fd;
	msg.msg_control  = cmsg_send;
	msg.msg_controllen = clen;
    } else {
	msg.msg_control = 0;
	msg.msg_controllen = 0;
    }
    hdr.cmd = cmd & CMD_MASK;
    if (fd != -1) hdr.cmd |= CMD_HAS_FD;
    hdr.len1 = (unsigned int) len;
#ifdef __LP64__
    hdr.len2 = (unsigned int) (len << 32);
    if (hdr.len2) hdr.cmd |= CMD_LONG;
#else
    hdr.len2 = 0;
#endif
    iov[0].iov_base  = &hdr;
    iov[0].iov_len   = (hdr.cmd & CMD_LONG) ? 12 : 8;
    iov[1].iov_base  = (void*) buf;
    iov[1].iov_len   = len;
    msg.msg_iov      = iov;
    msg.msg_iovlen   = 2;
    msg.msg_name     = 0;
    msg.msg_namelen  = 0;
    if ((n = sendmsg(io->fd[io->flags & RSIO_CHILD], &msg, 0)) != (len + (rsmsglen_t) iov[0].iov_len)) {
	rsio_close(io);
#ifdef RSIO_DEBUG
	fprintf(stderr, "ERROR: rsio(%p)write: cmd=0x%x, write error (%ld, expected %lu)\n",
		io, hdr.cmd, (long)n, (unsigned long)  (len + (rsmsglen_t) iov[0].iov_len));
#endif
	return -1;
    }
    return 0;
}

int rsio_write_msg(rsio_t *io, rsmsg_t *msg) {
    if (!io || !msg) return -2;
    return rsio_write(io, msg->data, msg->len, msg->cmd, (msg->flags & RSMSG_HAS_FD) ? msg->fd : -1);
}

int rsio_select_fd(rsio_t *io) {
    return io ? io->fd[io->flags & RSIO_CHILD] : -1;
}

#endif /* unix implementation */

#ifdef TEST_ME
#include <stdio.h>

int main(int ac, char**av) {
    rsio_t *io = rsio_new();
    if (fork() > 0) {
	printf("parent: %d\n", getpid());
	rsmsg_t *msg = rsio_read_msg(io);
	if (msg) {
	    printf("msg: command=0x%x, has fd:%s (%d), payload '%s'\n", msg->cmd, 
		   (msg->flags & RSMSG_HAS_FD) ? "yes" : "no", msg->fd, msg->data);
	    rsmsg_free(msg);
	    msg = rsio_read_msg(io);
	    if (msg)
		printf("msg: command=0x%x, has fd:%s (%d), payload '%s'\n", msg->cmd, 
		       (msg->flags & RSMSG_HAS_FD) ? "yes" : "no", msg->fd, msg->data);
	} else
	    printf("read failed\n");
	rsio_close(io);
	printf("parent done.\n");
	return 0;
    } else {
	printf("child: %d\n", getpid());
	rsio_set_child(io);
	printf("child: write = %d\n", rsio_write(io, "hello!", 7, 0x1234, 1));
	printf("child: write = %d\n", rsio_write(io, "hello!", 7, 0, -1));
	rsio_close(io);
	printf("child done\n");
	return 0;
    }
}
#endif
