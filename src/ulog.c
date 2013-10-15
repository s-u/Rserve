/* UDP logger

   (C)Copyright 2002-2013 Simon Urbanek

   This logger can be used either via simple

   ulog(...)

   call in the printf format, or the message can be constructed
   incerementally via

   ulog_begin()
   ulog_add(...); [ulog_add(...); ...]
   ulog_end()

   calls. ulog_end() commences the transfer.
   Internal state, sockets etc. may be cached after the first use.

*/

#ifndef NO_CONFIG_H
#include "config.h"
#endif

#include "ulog.h"

#ifndef WIN32

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <stdio.h>
#include <stdarg.h>

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

static int   ulog_sock = -1;
static char *ulog_path;

static char hn[512];
static char buf[4096];
static char ts[64];
static char buf_pos;

void ulog_set_path(const char *path) {
    ulog_path = path ? strdup(path) : 0;
}

void ulog_begin() {    
    if (!ulog_path) return;

    if (ulog_sock == -1) { /* first-time user */
	gethostname(hn, sizeof(hn));
	ulog_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (ulog_sock == -1)
	    return;
#if defined O_NONBLOCK && defined F_SETFL
	{ /* try to use non-blocking socket where available */
	    int flags = fcntl(ulog_sock, F_GETFL, 0);
	    if (flags != -1)
		fcntl(ulog_sock, F_SETFL, flags | O_NONBLOCK);
	}
#endif
    }

    {
	struct tm *stm;
	time_t now = time(0);
	stm = gmtime(&now);
	strftime (ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", stm);
    }

    /* FIXME: we could cache user/group/pid and show the former
       in textual form ... */
    /* This format is compatible with the syslog format (RFC5424)
       with hard-coded facility (3) and severity (6) */
    snprintf(buf, sizeof(buf), "<30>1 %s %s Rserve %d %d/%d - ", ts,
	     hn, (int) getpid(), (int) getuid(), (int) getpid());
    buf_pos = strlen(buf);
}

void ulog_add(const char *format, ...) {
    va_list(ap);
    va_start(ap, format);
    if (buf_pos) {
	vsnprintf(buf + buf_pos, sizeof(buf) - buf_pos, format, ap);
	buf_pos += strlen(buf + buf_pos);
    }
    va_end(ap);
}

void ulog_end() {
    struct sockaddr_un sa;
    if (!buf_pos) return;
    bzero(&sa, sizeof(sa));
    sa.sun_family = AF_LOCAL;
    strcpy(sa.sun_path, ulog_path); /* FIXME: check possible overflow? */
    sendto(ulog_sock, buf, buf_pos, 0, (struct sockaddr*) &sa, sizeof(sa));
    buf_pos = 0;
}

void ulog(const char *format, ...) {
    va_list(ap);
    va_start(ap, format);
    ulog_begin();
    if (buf_pos) {
	vsnprintf(buf + buf_pos, sizeof(buf) - buf_pos, format, ap);
	buf_pos += strlen(buf + buf_pos);
	ulog_end();
    }
    va_end(ap);
}

#else

void ulog_set_path(const char *path) { }
void ulog_begin() {}
void ulog_add(const char *format, ...) { }
void ulog_end() {}
void ulog(const char *format, ...) { }

#endif
