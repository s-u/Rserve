/* Session resume support: registry of children in the server (parent)
   process and the parent <-> child protocol on top of rsio.

   (C)Copyright 2026 Simon Urbanek

   License: GPL v2
*/

#ifndef RS_RESUME_H__
#define RS_RESUME_H__

#include "rsio.h"

#define RS_KEY_LEN 32

/* messages between children and the server process (rsio cmd):
   the low byte is the command, responses carry RSMSG_RESP and failed
   requests additionally RSMSG_ERR (e.g. RSMSG_KEY | RSMSG_RESP | RSMSG_ERR) */
#define RSMSG_RESP     0x100 /* response to a request */
#define RSMSG_ERR      0x200 /* request failed (only with RSMSG_RESP) */
#define RSMSG_CMD_MASK 0x0ff

/* commands 0x01-0x0f: child -> server (requests unless noted otherwise),
   0x10-0xff: server -> child */

#define RSMSG_KEY    0x01 /* child -> server: request the session key (no payload)
				 response: key (RS_KEY_LEN bytes) */
#define RSMSG_ATTACH 0x02 /* child -> server: key + context, fd = new connection
				 response: no payload, error if there is no such session
				 or the hand-over failed */
#define RSMSG_ADOPTED 0x03 /* child -> server: an RSMSG_ADOPT was received (no response).
				 The server holds a copy of the fd until then, because macOS
				 closes connections that are only in flight when any unix
				 socket is closed */
#define RSMSG_ADOPT  0x10 /* server -> session child: context, fd = new connection
				 (no response) */

/* set by configuration (session.resume) */
extern int resume_enabled;

/* --- server (parent) side --- */

/* call before fork() for every child; returns NULL if resume is disabled
   (or the channel could not be created) */
rsio_t *resume_srv_prefork(void);
/* call in the parent after fork() (pid = result of fork(), may be -1) */
void resume_srv_postfork(rsio_t *io, int pid);
/* call in the child after fork() - io may be NULL. Releases the
   parent's registry inherited by the child. */
void resume_child_postfork(rsio_t *io);
/* number of registered children (= channels to watch) */
int resume_srv_count(void);
/* fill fds[] with up to max channel fds, returns the number of entries */
int resume_srv_fds(int *fds, int max);
/* process input from the channel with the given fd (POLLIN/POLLHUP/POLLERR) */
void resume_srv_handle_fd(int fd);
/* remove the child with this pid from the registry (call once it has been reaped) */
void resume_srv_rm(int pid);

/* --- child side --- */

/* 1 if this process has a channel to the server process */
int resume_child_active(void);
/* fd of the channel to the server process (-1 if none) */
int resume_child_fd(void);
/* 1 if this process has obtained a session key (i.e., it can be resumed) */
int resume_child_has_key(void);
/* obtain the session key of this process (issued once by the server and
   then cached). Returns 0 on success, -1 on failure */
int resume_child_key(unsigned char *key);
/* ask the server process to hand the connection fd to the session with
   the given key. Returns 0 if the session got it (the caller should then
   close its copy of fd and not use it any more), -1 on failure */
int resume_child_attach(const unsigned char *key, int fd);
/* 1 if there are queued messages from the server process (i.e.,
   resume_child_next_msg() will return one without reading) */
int resume_child_pending(void);
/* next message from the server process (queued ones first), waiting
   up to timeout_ms (-1 = infinite). NULL on timeout or error */
rsmsg_t *resume_child_next_msg(int timeout_ms);
/* close the channel to the server process without telling it (e.g. in a
   forked compute process - the channel belongs to the session process) */
void resume_child_close(void);

#endif
