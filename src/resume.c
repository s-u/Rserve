/* Session resume support: registry of children in the server (parent)
   process and the parent <-> child protocol on top of rsio.

   (C)Copyright 2026 Simon Urbanek

   License: GPL v2

   The server process keeps one rsio channel per forked child. A child
   (session) can request a key which the server generates and associates
   with the channel of that child -- children never choose keys. A new
   connection that wants to resume a session sends the key and its
   connection fd to the server (RSMSG_ATTACH), the server looks up the
   session and forwards the fd to it (RSMSG_ADOPT).

   The server never blocks on a child: reads are incremental and writes use
   a zero timeout (a child that doesn't drain its channel loses messages).
*/

#include "resume.h"

int resume_enabled = 0;

#if defined WIN32 || defined _WIN32

rsio_t  *resume_srv_prefork(void) { return 0; }
void     resume_srv_postfork(rsio_t *io, int pid) {}
void     resume_child_postfork(rsio_t *io) {}
int      resume_srv_count(void) { return 0; }
int      resume_srv_fds(int *fds, int max) { return 0; }
void     resume_srv_handle_fd(int fd) {}
void     resume_srv_rm(int pid) {}
int      resume_child_active(void) { return 0; }
int      resume_child_fd(void) { return -1; }
int      resume_child_has_key(void) { return 0; }
int      resume_child_key(unsigned char *key) { return -1; }
int      resume_child_attach(const unsigned char *key, int fd) { return -1; }
int      resume_child_pending(void) { return 0; }
rsmsg_t *resume_child_next_msg(int timeout_ms) { return 0; }
void     resume_child_close(void) {}

#else

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>

#include "ulog.h"

/* max. number of forwarded connection fds the server holds per child
   until the child confirms that it has received them (RSMSG_ADOPTED) */
#define MAX_HELD 8

/* max. payload accepted by the server from a child */
#define PARENT_MAX_MSG 4096
/* how long a child waits for the server to respond to a request */
#define REQ_TIMEOUT_MS 10000

typedef struct rchild {
    int pid;
    rsio_t *io;
    int has_key;
    unsigned char key[RS_KEY_LEN];
    int held[MAX_HELD], n_held; /* fds forwarded to this child, oldest first */
    struct rchild *prev, *next;
} rchild_t;

/* server side: registry */
static rchild_t *rchildren;
static int n_rchildren;

/* child side */
static rsio_t *parent_io;
static int have_own_key;
static unsigned char own_key[RS_KEY_LEN];

typedef struct msgq {
    rsmsg_t *msg;
    struct msgq *next;
} msgq_t;
static msgq_t *pending_head, *pending_tail;

/* ---- helpers ---- */

static int key_eq(const unsigned char *a, const unsigned char *b) {
    unsigned char d = 0;
    int i;
    /* not memcmp() to avoid timing probes */
    for (i = 0; i < RS_KEY_LEN; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static int random_bytes(unsigned char *buf, size_t len) {
    int fd;
    size_t got = 0;
#ifdef O_CLOEXEC
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
#else
    fd = open("/dev/urandom", O_RDONLY);
#endif
    if (fd == -1) return -1;
    while (got < len) {
	ssize_t n = read(fd, buf + got, len - got);
	if (n > 0)
	    got += (size_t) n;
	else if (n == 0 || errno != EINTR) {
	    close(fd);
	    return -1;
	}
    }
    close(fd);
    return 0;
}

/* a key must not look like a QAP header of CMD_attachSession (0x32) so that
   the resume endpoint can tell legacy raw-key clients from QAP clients */
static int key_is_ambiguous(const unsigned char *key) {
    return key[0] == 0x32 && key[1] == 0 && key[2] == 0 && key[3] == 0;
}

static int new_key(unsigned char *key) {
    int tries = 0;
    while (tries++ < 16) {
	rchild_t *c = rchildren;
	if (random_bytes(key, RS_KEY_LEN)) return -1;
	if (!key_is_ambiguous(key)) {
	    while (c && !(c->has_key && key_eq(c->key, key))) c = c->next;
	    if (!c) return 0; /* unique */
	}
    }
    return -1;
}

/* close the oldest fd held for the child */
static void release_held(rchild_t *c) {
    if (c->n_held > 0) {
	close(c->held[0]);
	c->n_held--;
	memmove(c->held, c->held + 1, sizeof(int) * c->n_held);
    }
}

static void release_all_held(rchild_t *c) {
    while (c->n_held > 0)
	release_held(c);
}

static void rm_child(rchild_t *c) {
    if (c->prev) c->prev->next = c->next; else rchildren = c->next;
    if (c->next) c->next->prev = c->prev;
    release_all_held(c);
    rsio_free(c->io);
    memset(c->key, 0, RS_KEY_LEN);
    free(c);
    n_rchildren--;
}

/* ---- server side ---- */

rsio_t *resume_srv_prefork(void) {
    rsio_t *io;
    if (!resume_enabled) return 0;
    io = rsio_new();
    if (!io)
	ulog("WARNING: cannot create resume channel (%s), session will not be resumable", strerror(errno));
    return io;
}

void resume_srv_postfork(rsio_t *io, int pid) {
    rchild_t *c;
    if (!io) return;
    if (pid <= 0 || !(c = (rchild_t*) calloc(1, sizeof(rchild_t)))) {
	rsio_free(io);
	return;
    }
    rsio_set_parent(io);
    rsio_set_write_timeout(io, 0);
    rsio_set_max_len(io, PARENT_MAX_MSG);
    c->pid = pid;
    c->io = io;
    c->next = rchildren;
    if (rchildren) rchildren->prev = c;
    rchildren = c;
    n_rchildren++;
}

void resume_child_postfork(rsio_t *io) {
    /* closes all inherited channels except ours */
    rsio_set_child(io);
    /* release the server's registry - none of it is ours */
    while (rchildren) {
	rchild_t *c = rchildren;
	rchildren = c->next;
	release_all_held(c);
	rsio_free(c->io);
	memset(c->key, 0, RS_KEY_LEN);
	free(c);
    }
    n_rchildren = 0;
    parent_io = io;
    have_own_key = 0;
}

int resume_srv_count(void) {
    return n_rchildren;
}

int resume_srv_fds(int *fds, int max) {
    int n = 0;
    rchild_t *c = rchildren;
    while (c && n < max) {
	int fd = rsio_fd(c->io);
	if (fd != -1) fds[n++] = fd;
	c = c->next;
    }
    return n;
}

static void reply(rchild_t *c, unsigned int cmd, const void *buf, rsmsglen_t len) {
    int r = rsio_write(c->io, buf, len, cmd, -1);
    if (r != RSIO_OK)
	ulog("WARNING: resume: cannot reply 0x%x to child %d (%d)", cmd, c->pid, r);
}

static void handle_msg(rchild_t *c, rsmsg_t *msg) {
    if (msg->cmd & RSMSG_RESP) { /* we don't send requests to children */
	ulog("WARNING: resume: unexpected response 0x%x from child %d, ignored", msg->cmd, c->pid);
	rsmsg_free(msg);
	return;
    }
    switch (msg->cmd) {
    case RSMSG_KEY:
	if (!c->has_key) {
	    if (new_key(c->key)) {
		ulog("ERROR: resume: cannot generate session key for child %d", c->pid);
		reply(c, RSMSG_KEY | RSMSG_RESP | RSMSG_ERR, 0, 0);
		break;
	    }
	    c->has_key = 1;
	    ulog("INFO: resume: issued session key for child %d", c->pid);
	}
	reply(c, RSMSG_KEY | RSMSG_RESP, c->key, RS_KEY_LEN);
	break;

    case RSMSG_ATTACH: {
	rchild_t *t = rchildren;
	if (msg->len < RS_KEY_LEN || msg->fd == -1) {
	    ulog("WARNING: resume: invalid attach request from child %d", c->pid);
	    reply(c, RSMSG_ATTACH | RSMSG_RESP | RSMSG_ERR, 0, 0);
	    break;
	}
	while (t && !(t != c && t->has_key && key_eq(t->key, msg->data))) t = t->next;
	if (!t) {
	    ulog("INFO: resume: attach request from child %d for unknown session", c->pid);
	    reply(c, RSMSG_ATTACH | RSMSG_RESP | RSMSG_ERR, 0, 0);
	    break;
	}
	/* forward the connection (and the remaining payload as context) to the session */
	if (rsio_write(t->io, msg->data + RS_KEY_LEN, msg->len - RS_KEY_LEN, RSMSG_ADOPT, msg->fd) == RSIO_OK) {
	    ulog("INFO: resume: connection from child %d handed to session %d", c->pid, t->pid);
	    /* keep our copy until the session has it (see RSMSG_ADOPTED) */
	    if (t->n_held == MAX_HELD)
		release_held(t);
	    t->held[t->n_held++] = msg->fd;
	    msg->fd = -1;
	    reply(c, RSMSG_ATTACH | RSMSG_RESP, 0, 0);
	} else {
	    ulog("WARNING: resume: cannot hand connection to session %d", t->pid);
	    reply(c, RSMSG_ATTACH | RSMSG_RESP | RSMSG_ERR, 0, 0);
	}
	break;
    }

    case RSMSG_ADOPTED: /* notification, no response */
	release_held(c);
	break;

    default:
	ulog("WARNING: resume: unknown request 0x%x from child %d", msg->cmd, c->pid);
	reply(c, msg->cmd | RSMSG_RESP | RSMSG_ERR, 0, 0);
    }
    /* our copy of any fd is closed here - the receiver has its own */
    rsmsg_free(msg);
}

void resume_srv_handle_fd(int fd) {
    rchild_t *c = rchildren;
    int st;
    while (c && rsio_fd(c->io) != fd) c = c->next;
    if (!c) return;
    /* process all complete messages, but don't block */
    while ((st = rsio_read_status(c->io)) == 1) {
	rsmsg_t *msg = rsio_read_msg(c->io, 0);
	if (!msg) break;
	handle_msg(c, msg);
    }
    if (st < 0 || rsio_fd(c->io) == -1) /* EOF or error - child is gone (or broken) */
	rm_child(c);
}

void resume_srv_rm(int pid) {
    rchild_t *c = rchildren;
    while (c && c->pid != pid) c = c->next;
    if (c) rm_child(c);
}

/* ---- child side ---- */

int resume_child_active(void) {
    return (parent_io && rsio_fd(parent_io) != -1) ? 1 : 0;
}

int resume_child_fd(void) {
    return parent_io ? rsio_fd(parent_io) : -1;
}

static void enqueue(rsmsg_t *msg) {
    msgq_t *q = (msgq_t*) malloc(sizeof(msgq_t));
    if (!q) {
	rsmsg_free(msg);
	return;
    }
    q->msg = msg;
    q->next = 0;
    if (pending_tail) pending_tail->next = q; else pending_head = q;
    pending_tail = q;
}

/* read a message from the server; if it carries an fd, confirm that it was
   received so the server can close its copy */
static rsmsg_t *read_msg(int timeout_ms) {
    rsmsg_t *msg = rsio_read_msg(parent_io, timeout_ms);
    if (msg && msg->fd != -1 && parent_io)
	rsio_write(parent_io, 0, 0, RSMSG_ADOPTED, -1);
    return msg;
}

int resume_child_pending(void) {
    return pending_head ? 1 : 0;
}

rsmsg_t *resume_child_next_msg(int timeout_ms) {
    if (pending_head) {
	msgq_t *q = pending_head;
	rsmsg_t *msg = q->msg;
	pending_head = q->next;
	if (!pending_head) pending_tail = 0;
	free(q);
	return msg;
    }
    if (!parent_io) return 0;
    return read_msg(timeout_ms);
}

static long elapsed_ms(const struct timeval *start) {
    struct timeval now;
    gettimeofday(&now, 0);
    return (long) (now.tv_sec - start->tv_sec) * 1000L + (long) (now.tv_usec - start->tv_usec) / 1000L;
}

/* send a request to the server and wait for its response, other messages
   are queued for resume_child_next_msg(). Returns the response or NULL on
   failure (incl. timeout) */
static rsmsg_t *request(unsigned int cmd, const void *buf, rsmsglen_t len, int fd) {
    struct timeval start;
    if (!resume_child_active()) return 0;
    rsio_set_write_timeout(parent_io, REQ_TIMEOUT_MS);
    if (rsio_write(parent_io, buf, len, cmd, fd) != RSIO_OK)
	return 0;
    gettimeofday(&start, 0);
    while (1) {
	rsmsg_t *msg;
	long elapsed = elapsed_ms(&start);
	if (elapsed >= REQ_TIMEOUT_MS) return 0;
	msg = read_msg((int) (REQ_TIMEOUT_MS - elapsed));
	if (!msg) return 0;
	if ((msg->cmd & (RSMSG_CMD_MASK | RSMSG_RESP)) == (cmd | RSMSG_RESP))
	    return msg;
	enqueue(msg); /* e.g. RSMSG_ADOPT - keep for the main loop */
    }
}

int resume_child_has_key(void) {
    return have_own_key;
}

int resume_child_key(unsigned char *key) {
    rsmsg_t *msg;
    int res = -1;
    if (!have_own_key) {
	msg = request(RSMSG_KEY, 0, 0, -1);
	if (!msg) return -1;
	if (!(msg->cmd & RSMSG_ERR) && msg->len == RS_KEY_LEN) {
	    memcpy(own_key, msg->data, RS_KEY_LEN);
	    have_own_key = 1;
	}
	rsmsg_free(msg);
    }
    if (have_own_key) {
	memcpy(key, own_key, RS_KEY_LEN);
	res = 0;
    }
    return res;
}

int resume_child_attach(const unsigned char *key, int fd) {
    rsmsg_t *msg = request(RSMSG_ATTACH, key, RS_KEY_LEN, fd);
    int res = -1;
    if (msg) {
	if (!(msg->cmd & RSMSG_ERR)) res = 0;
	rsmsg_free(msg);
    }
    return res;
}

void resume_child_close(void) {
    while (pending_head) {
	msgq_t *q = pending_head;
	pending_head = q->next;
	rsmsg_free(q->msg);
	free(q);
    }
    pending_tail = 0;
    if (parent_io) {
	rsio_free(parent_io);
	parent_io = 0;
    }
    have_own_key = 0;
    memset(own_key, 0, RS_KEY_LEN);
}

#endif
