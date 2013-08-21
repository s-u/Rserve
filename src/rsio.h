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

#ifndef RSIO_H__
#define RSIO_H__

typedef struct rsio rsio_t;

#define RSMSG_HAS_FD 0x01

typedef unsigned long rsmsglen_t;

typedef struct {
    int  cmd;
    int  flags;
    int  fd;
    rsmsglen_t len;
    unsigned char data[1];
} rsmsg_t;

rsio_t *rsio_new();
void rsio_free(rsio_t *io);

void rsio_close(rsio_t *io);

/* one of the two *must* be called before any read/write operations */
void rsio_set_child(rsio_t *io);
void rsio_set_parent(rsio_t *io);

void rsmsg_free(rsmsg_t *msg);

/* -1 = error, 0 = read would block, 1 = complete message available */
int rsio_read_status(rsio_t *io);
rsmsg_t *rsio_read_msg(rsio_t *io);
/* 0 on success, -1 on send fail, -2 on out of memory */
int  rsio_write(rsio_t *io, const void *buf, rsmsglen_t len, int cmd, int fd);
int  rsio_write_msg(rsio_t *io, rsmsg_t *msg); /* mainly to allow easy forwarding */

/* this is a compatibility hack for now so we can attach rsio into a set of select() calls.
   note that this can be -1 (closed, unconnected, unimplemented, ...) */
int rsio_select_fd(rsio_t *io);

#endif
