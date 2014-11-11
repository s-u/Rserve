/* threaded buffering of stdout/err to pass back to
   a synchronous process

   (C)Copyright 2014 Simon Urbanek

   License any of: BSD, GPL-2, GPL-3
*/

#ifndef NO_CONFIG_H
#include "config.h"
#endif

#if defined WITH_THREADS || ! defined WIN32

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>

static int stdoutFD, stderrFD, triggerFD;

static volatile unsigned int head, tail;
static unsigned int alloc;
static char *buf;

static volatile int ioc_active = 0;

pthread_mutex_t buffer_mux = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t trigger_mux = PTHREAD_MUTEX_INITIALIZER;

void ulog(const char *format, ...);

static void *feed_thread(void *whichFD) {
    int ta = 1024*1024, fd = stdoutFD;
    char *thb = (char*) malloc(ta + 8);
    unsigned int *h = (unsigned int*) thb, mask = 0;
    if (!thb) return 0;
    if (whichFD == &stderrFD) {
	fd = stderrFD;
	mask = 0x80000000;
    }
    ulog("feed_thread started, mask=0x%x\n", mask);
    while (ioc_active) {
	int n = read(fd, thb + 4, ta), dst;
	ulog("feed_thread n = %d\n", n);
	if (n == -1 && errno != EINTR)
	    break;
	pthread_mutex_lock(&buffer_mux);
	dst = tail;
	tail = (tail + n + 4) & (alloc - 1);
	*h = n | mask;
	n += 4;
	if (tail < dst) {
	    memcpy(buf + dst, thb, alloc - dst);
	    n -= alloc - dst;
	    memcpy(buf, thb + alloc - dst, n);
	} else
	    memcpy(buf + dst, thb, n);
	ulog("feed_thread: tail = %d\n", tail);
	pthread_mutex_unlock(&buffer_mux);
	pthread_mutex_unlock(&trigger_mux);
    }
    close(fd);
    return 0;
}

static void *read_thread(void *dummy) {
    ulog("read_thread started\n");
    while (ioc_active) {
	volatile int head0, tail0;
	/* lock just to get a consistent state */
	pthread_mutex_lock(&buffer_mux);
	head0 = head;
	tail0 = tail;
	pthread_mutex_unlock(&buffer_mux);
	/* if there is nothing to do, lock so 
	   we get notified */
	if (head0 == tail0) {
	    pthread_mutex_lock(&trigger_mux);
	    continue;
	}

	ulog("read_thread: [%d/%d]\n", head0, tail0);
	if (head0 > tail0) {
	    while (head0 < alloc) {
		int n = write(triggerFD, buf + head0, alloc - head0);
		if (n > 0 && n < alloc - head0) {
		    pthread_mutex_lock(&buffer_mux);
		    head0 += n;
		    if (head0 >= alloc) head0 -= alloc;
		    head = head0;
		    pthread_mutex_unlock(&buffer_mux);
		    continue;
		}
		if (n < 0 && errno != EINTR) {
		    ulog("ERROR: lost output pipe, aborting\n");
		    close(triggerFD);
		    return 0;
		}
	    }
	    head0 = 0;
	}
	while (head0 < tail0) {
	    int n = write(triggerFD, buf + head0, tail0 - head0);
	    if (n > 0 && n < tail0 - head0) {
		pthread_mutex_lock(&buffer_mux);
		head0 += n;
		head = head0;
		pthread_mutex_unlock(&buffer_mux);
		continue;
	    }
	    if (n < 0 && errno != EINTR) {
		ulog("ERROR: lost output pipe, aborting\n");
		close(triggerFD);
		return 0;
	    }
	    head0 += n;
	}
	pthread_mutex_lock(&buffer_mux);
	head = tail0;
	pthread_mutex_unlock(&buffer_mux);
	/* we don't unlock the trigger mutex
	   since that's how the feed threads wake us up */
    }
    return 0;
}

#include <Rinternals.h>

static int readFD;

/* on fork() remove all forwarding from the children */
static void atfork_prepare() { }
static void atfork_parent() { }
static void atfork_child() {
  ioc_active = 0;
  close(stdoutFD);
  close(stderrFD);
  close(triggerFD);
}

int ioc_setup() {
  int pfd[2];
  pthread_t thread;
  pthread_attr_t thread_attr;

  alloc = 1024*1024;
  buf = malloc(alloc);
  if (!buf)
      Rf_error("cannot allocate buffer");
  
  if (pipe(pfd)) return 0;
  dup2(pfd[1], STDOUT_FILENO);
  close(pfd[1]);
        
  stdoutFD = pfd[0];
  
  if (pipe(pfd)) return 0;
  dup2(pfd[1], STDERR_FILENO);
  close(pfd[1]);
  
  stderrFD = pfd[0];

  if (pipe(pfd)) return 0;
  triggerFD = pfd[1];

  ioc_active = 1;

  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&thread, &thread_attr, feed_thread, &stdoutFD);

#if defined RSERV_DEBUG || defined ULOG_STDERR
  ulog("NOTE: cannot forward stderr in debug builds since it would cause infinite recursion");
#else
  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&thread, &thread_attr, feed_thread, &stderrFD);
#endif

  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&thread, &thread_attr, read_thread, 0);

  pthread_atfork(atfork_prepare, atfork_parent, atfork_child);

  ulog("setup done, fd = %d\n", pfd[0]);
  return (readFD = pfd[0]);
}

SEXP ioc_read(int *type) {
    SEXP res;
    unsigned int h;
    int n = read(readFD, &h, sizeof(h));
    if (n != sizeof(h))
	Rf_error("failed to read header");
    ulog("header = 0x%x\n", h);
    if (type)
	type[0] = (h & 0x80000000) ? 1 : 0;
    h &= 0x7fffffff;
    res = Rf_allocVector(RAWSXP, h);
    n = read(readFD, RAW(res), h);
    if (n != h) 
	Rf_error("read error (n=%d)", n);
    return res;
}

#else

#include <Rinternals.h>

int ioc_setup() {
    return 0;
}

SEXP ioc_read(int *type) {
    Rf_error("I/O redirection or threads not supported on this platform");
    return R_NilValue;
}

#endif
