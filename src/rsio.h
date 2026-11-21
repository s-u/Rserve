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

/* Usage:
     io = rsio_new();            -- before fork()
     fork()
     parent: rsio_set_parent(io) -- closes the child's end
     child:  rsio_set_child(io)  -- closes the parent's end AND all other
                                    channels inherited from the parent

   Messages consist of a command (31-bit unsigned), a payload of arbitrary
   length (subject to the receiver's limit, see rsio_set_max_len) and an
   optional file descriptor passed with SCM_RIGHTS.

   All channel descriptors are non-blocking and close-on-exec. Reads are
   incremental (rsio_read_status) so a misbehaving peer cannot block the
   reader. Writes block (via poll) up to the write timeout. SIGPIPE is never
   raised by rsio.

   Once an I/O error is encountered the channel is closed (rsio_fd() returns
   -1) but the rsio_t object stays valid until rsio_free(). */

#ifndef RSIO_H__
#define RSIO_H__

#include <stddef.h>

typedef struct rsio rsio_t;

typedef unsigned long long rsmsglen_t;

/* message as returned by rsio_read_msg() */
typedef struct rsmsg {
    unsigned int cmd;
    int fd;              /* -1 if no fd was passed. The message owns the fd:
                            rsmsg_free() closes it unless the caller takes
                            ownership by setting fd to -1 */
    rsmsglen_t len;      /* payload length */
    unsigned char data[1]; /* payload, always followed by a NUL sentinel */
} rsmsg_t;

/* return values of rsio_write() */
#define RSIO_OK        0
#define RSIO_ERR      -1  /* I/O error - the channel has been closed */
#define RSIO_EINVAL   -2  /* invalid arguments or channel already closed */
#define RSIO_EAGAIN   -3  /* nothing could be sent within the timeout, the
                             channel is still intact */

/* default maximal payload accepted by the reader (can be changed with
   rsio_set_max_len) */
#define RSIO_DEFAULT_MAX_LEN (16*1024*1024)

rsio_t *rsio_new(void);
void rsio_free(rsio_t *io);   /* closes and releases */
void rsio_close(rsio_t *io);  /* closes, object remains valid */

/* one of the two *must* be called after fork() before any I/O */
void rsio_set_parent(rsio_t *io);
void rsio_set_child(rsio_t *io);

/* limit on incoming payload size (0 = no limit), default RSIO_DEFAULT_MAX_LEN */
void rsio_set_max_len(rsio_t *io, rsmsglen_t max_len);
/* write timeout in ms (-1 = infinite, 0 = don't wait), default -1 */
void rsio_set_write_timeout(rsio_t *io, int timeout_ms);

/* the fd to watch for readability (poll/select), -1 if closed */
int rsio_fd(rsio_t *io);
#define rsio_select_fd rsio_fd /* compatibility */

/* non-blocking incremental read:
   -1 = error/EOF (channel closed), 0 = message not complete yet,
    1 = complete message available (fetch with rsio_read_msg) */
int rsio_read_status(rsio_t *io);

/* returns a complete message, waiting up to timeout_ms (-1 = infinite,
   0 = only if already available). Returns NULL on timeout or error
   (check rsio_fd(io) == -1 to distinguish). The caller must release the
   message with rsmsg_free() */
rsmsg_t *rsio_read_msg(rsio_t *io, int timeout_ms);
void rsmsg_free(rsmsg_t *msg);

/* send a message, fd = -1 if no fd is to be passed (the fd is NOT closed,
   the receiver gets a duplicate). Returns one of the RSIO_* codes above */
int rsio_write(rsio_t *io, const void *buf, rsmsglen_t len, unsigned int cmd, int fd);
/* convenience for forwarding (passes msg->fd if present) */
int rsio_write_msg(rsio_t *io, const rsmsg_t *msg);

#endif
