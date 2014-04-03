/*
 *  Rserv : R-server that allows to use embedded R via TCP/IP
 *  Copyright (C) 2002-13 Simon Urbanek
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  $Id$
 */

/* external defines:

   COOPERATIVE - forces cooperative version of Rserv on unix platforms
                 (default for non-unix platforms)

   FORKED      - each connection is forked to a new process. This is the
                 recommended way to use this server. The advantage is (beside
				 the fact that this works ;)) that each client has a separate
				 namespace since the processes are independent
				 (default for unix platforms)

   SWAPEND     - define if the platform has byte order inverse to Intel (like PPC)

   RSERV_DEBUG - if defined various verbose output is produced

   DAEMON      - if defined the server daemonizes (unix only)

   CONFIG_FILE - location of the config file (default /etc/Rserv.conf)


  reported versions:
 --------------------
 0100 - Rserve 0.1-1 .. 0.1-9
        CMD_eval sends SEXP directly without the data type header. This is in
		fact an inconsistency and was fixed in 0101. New clients should be aware
		of this and support this behavior or reject 0100 connections.

 0101 - Rserve 0.1-10 .. 0.2-x

 0102 - Rserve 0.3
        added support for large parameters/expressions

 0103 - Rserve 0.5
        discard the notion of scalar types

The current implementation uses DT_LARGE/XT_LARGE only for SEXPs larger than 0xfffff0.
No commands except for CMD_set/assignREXP with DT_REXP accept large input,
in particular all file operations. All objects smaller 8MB should be encoded without
the use of DT_LARGE/XT_LARGE.
          
*/

/* config file entries: [default]
   ----------------------
   workdir <path> [depends on the CONFIG_FILE define]
   pwdfile <file> [none=disabled]
   remote enable|disable [disable]
   auth required|disable [disable]
   plaintext enable|disable [disable] (strongly discouraged to enable)
   fileio enable|disable [enable]
   interactive yes|no [yes] (the default may change to "no" in the future!)

   socket <unix-socket-name> [none]
   maxinbuf <size in kB> [262144 = 256MB]
   maxsendbuf <size in kB> [0 = no limit]
   
   cachepwd no|yes|indefinitely
 
   unix only (works only if Rserve was started by root):
   uid <uid>
   gid <gid>
   su now|server|client

   encoding native|latin1|utf8 [native]

   source <file>
   eval <expression(s)>

   control enable|disable [disable]
   r-control enable|disable [disable]

   A note about security: Anyone with access to R has access to the shell
   via "system" command, so you should consider following rules:

   - NEVER EVER run Rserv as root (unless uid/gid is used) - this compromises
     the box totally

   - use "remote disable" whenever you don't need remote access.

   - if you need remote access use "auth required" and "plaintext disable"
     consider also that anyone with the access can decipher other's passwords
     if he knows how to. the authentication prevents hackers from the net
     to break into Rserv, but it doesn't (and cannot) protect from
     inside attacks (since R has no security measures).
 
     You should also use a special, restricted user for running Rserv 
     as a public server, so noone can try to hack the box it runs on.
 
     From 0.6-1 on you can set gid/uid and use "su client", "cachepwd yes"
     and only a root-readable password file such that clients cannot
     read it and also cannot affect the server process (this works on
     unix only).
 
   - don't enable plaintext unless you really have to. Passing passwords
     in plain text over the net is not wise and not necessary since both
     Rserv and JRclient provide encrypted passwords with server-side
     challenge (thus safe from sniffing).
*/

#ifndef NO_CONFIG_H
#include "config.h"
#endif

#if defined STANDALONE_RSERVE || defined RSERVE_PKG

#define USE_RINTERNALS 1
#define SOCK_ERRORS
#define LISTENQ 16
#define MAIN

/* some OSes don't like too large chunks to be sent/received,
   so we imit the socket I/O sizes by this constant.
   It should be a 31-bit value for compatibility.
*/
#ifdef WIN32 /* Windows is really bad (as usual) */
#define max_sio_chunk 1048576
#else
#define max_sio_chunk 134217728
#endif

#if defined NODAEMON && defined DAEMON
#undef DAEMON
#endif

#if !defined WIN32 && !defined unix
#define unix
#endif

/* FORKED is default for unix platforms */
#if defined unix && !defined COOPERATIVE && !defined FORKED
#define FORKED
#endif

#ifndef CONFIG_FILE
#ifdef unix
#define CONFIG_FILE "/etc/Rserv.conf"
#else
#define CONFIG_FILE "Rserv.cfg"
#endif
#endif

/* we have no configure for WIN32 so we have to take care of socklen_t */
#ifdef WIN32
typedef int socklen_t;
#define random() rand()
#define srandom() srand()
#define CAN_TCP_NODELAY
#define _WINSOCKAPI_
#include <windows.h>
#include <winbase.h>
#include <io.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sisocks.h>
#include <string.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef unix
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <unistd.h>
#include <sys/un.h> /* needed for unix sockets */
#endif
#ifdef FORKED
#include <sys/wait.h>
#include <signal.h>
#endif
#ifdef ERROR
#undef ERROR
#endif
#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>
#include <Rversion.h>
#if (R_VERSION >= R_Version(2,3,0))
#ifdef WIN32 /* Windows doesn't have Rinterface */
extern __declspec(dllimport) int R_SignalHandlers;
#else
#define R_INTERFACE_PTRS
#include <Rinterface.h>
#endif
#endif
#include <R_ext/Parse.h>

#include "Rsrv.h"
#include "qap_encode.h"
#include "qap_decode.h"
#include "ulog.h"
#include "md5.h"
/* we don't bother with sha1.h so this is the declaration */
void sha1hash(const char *buf, int len, unsigned char hash[20]);

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#if R_VERSION >= R_Version(2,9,0)
#include <R_ext/Rdynload.h>
#endif

#if defined HAVE_NETINET_TCP_H && defined HAVE_NETINET_IN_H
#define CAN_TCP_NODELAY
#include <netinet/tcp.h>
#include <netinet/in.h>
#endif

/* AF_LOCAL is the POSIX version of AF_UNIX - we need this e.g. for AIX */
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

/* send buffer size (default 2MB)
   Currently Rserve stores entire responses in memory before sending it.
   This is not really neccessary and may (hopefully will) change in the future.
   Send buffer specifies the maximal amount of data sent from Rserve to
   the client in one response.
*/
#ifndef sndBS /* configure may have defined one already */
#define sndBS (2048*1024)
#endif

/* the # of arguments to R_ParseVector changed since R 2.5.0 */
#if R_VERSION < R_Version(2,5,0)
#define RS_ParseVector R_ParseVector
#else
#define RS_ParseVector(A,B,C) R_ParseVector(A,B,C,R_NilValue)
#endif

/* child control commands */
#define CCTL_EVAL     1 /* data: string */
#define CCTL_SOURCE   2 /* data: string */
#define CCTL_SHUTDOWN 3 /* - */

/* general RSMSG error commands */
#define RSMSG_ERR             0x800  /* is RSMSG error */

#define RSMSG_ERR_NOT_FOUND   (RSMSG_ERR | 1)   /* address not found */
#define RSMSG_ERR_NO_IO       (RSMSG_ERR | 2)   /* address exists but has no communication channel */
#define RSMSG_ERR_IO_FAILED   (RSMSG_ERR | 3)   /* error during an attempt to relay the message */

/* bits that govern presence of leading payload in RSMSG messages */
#define RSMSG_HAS_SRC 0x1000  /* has source address (mandatory if a reply is expected) */
#define RSMSG_HAS_DST 0x2000  /* has destination address (if not present, server is implied) */

typedef union { char c[16]; int i[4]; } rsmsg_addr_t;

#define RSMSG_ADDR_LEN (sizeof(rsmsg_addr_t))

#define MAX_CTRL_DATA (1024*1024) /* max. length of data for control commands - larger data will be ignored */

#include "RSserver.h"
#include "websockets.h"
#include "http.h"
#include "tls.h"
#include "oc.h"

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s;
	SOCKET ss;
	int msg_id;
	void *res1, *res2;
	/* the following entries are not populated by Rserve but can be used by server implemetations */
	char *buf, *sbuf;
	int   ver, bp, bl, sp, sl, flags;
	long  l1, l2;
	/* The following fields are informational, populated by Rserve */
    SAIN sa;
    int ucix;
#ifdef unix
    struct sockaddr_un su;
#endif
	char res[128]; /* reserved space for server-specific fields */
};

static int port = default_Rsrv_port;
static int tls_port = -1;
static int active = 1; /* 1 = server loop is active, 0 = shutdown */
static int UCIX   = 1; /* unique connection index */

static char *localSocketName = 0; /* if set listen on this local (unix) socket instead of TCP/IP */
static int localSocketMode = 0;   /* if set, chmod is used on the socket when created */

static int allowIO = 1;  /* 1=allow I/O commands, 0=don't */

static char *workdir = "/tmp/Rserv";
static int   wd_mode = 0755, wdt_mode = 0755;
static char *pwdfile = 0;
static int   wipe_workdir = 0; /* if set acts as rm -rf otherwise jsut rmdir */

static SOCKET csock = -1;

static int parentPID = -1;

#include "rsio.h"

static rsmsg_addr_t server_addr;
static rsmsg_addr_t child_addr;

int is_child = 0;       /* 0 for parent (master), 1 for children */
rsio_t *parent_io;      /* pipe to the master process or NULL if not available */
int can_control = 0;    /* control commands will be rejected unless this flag is set */
int child_control = 0;  /* enable/disable the ability of children to send commands to the master process */
int self_control = 0;   /* enable/disable the ability to use control commands from within the R process */
static int tag_argv = 0;/* tag the ARGV with client/server IDs */
static char *pidfile = 0;/* if set by configuration generate pid file */
static int use_msg_id;   /* enable/disable the use of msg-ids in message frames */
static int disable_shutdown; /* disable the shutdown command */
static int oob_console = 0; /* enable OOB commands for console callbacks */
static int idle_timeout = 0; /* interval to send idle OOBs, 0 = disabled */

#ifdef DAEMON
int daemonize = 1;
#endif

char **main_argv; /* this is only set by standalone! */
int    main_argc;

rlen_t maxSendBufSize = 0; /* max. sendbuf for auto-resize. 0=no limit */

int Rsrv_interactive = 1; /* default for R_Interactive flag */

static char authkey[1024];  /* server-side authentication key */
static int authkey_req = 0; /* number of auth requests */
static char *auth_fn;       /* authentication function */

#ifdef unix
static int umask_value = 0;
#endif

int global_srv_flags = 0;

static char *http_user, *https_user, *ws_user;

static char **allowed_ips = 0;

void stop_server_loop() {
	active = 0;
}

#include "rsdebug.h"
#include "rserr.h"

#ifdef unix
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

static char tmpdir_buf[1024];

#include <Rembedded.h>

#ifdef unix
char wdname[512];
#endif

#if !defined(S_IFDIR) && defined(__S_IFDIR)
# define S_IFDIR __S_IFDIR
#endif

/* modified version of what's used in R */
static int isDir(const char *path)
{
#ifdef Win32
    struct _stati64 sb;
#else
    struct stat sb;
#endif
    int isdir = 0;
    if(!path) return 0;
#ifdef Win32
    if(_stati64(path, &sb) == 0) {
#else
	if(stat(path, &sb) == 0) {
#endif
		isdir = (sb.st_mode & S_IFDIR) > 0; /* is a directory */
	}
	return isdir;
}

static void prepare_set_user(int uid, int gid) {
	const char *tmp = (const char*) R_TempDir;
	/* create a new tmpdir() and make it owned by uid:gid */
	/* we use uid.gid in the name to minimize cleanup issues - we assume that it's ok to
	   share tempdirs between sessions of the same user */
	if (!tmp) {
		/* if there is no R_TempDir then it means that R has not been
		   init'd yet so we have to take care of our own tempdir setting.
		   This is replicating a subset of the logic used in R. */
		const char *tm = getenv("TMPDIR");
		char *tmpl;
		if (!isDir(tm)) {
			tm = getenv("TMP");
			if (!isDir(tm)) {
				tm = getenv("TEMP");
				if (!isDir(tm))
#ifdef Win32
					tm = getenv("R_USER"); /* this one will succeed */
#else
                    tm = "/tmp";
#endif
			}
		}
		/* Note: we'll be leaking this, but that's ok since it's tiny and only once per process */
		tmpl = (char*) malloc(strlen(tm) + 10);
		if (tmpl) {
			strcpy(tmpl, tm);
			strcat(tmpl, "/Rstmp");
			tmp = tmpl;
		}
	}
	snprintf(tmpdir_buf, sizeof(tmpdir_buf), "%s.%d.%d", tmp, uid, gid);
	if (mkdir(tmpdir_buf, 0700)) {} /* it is ok to fail if it exists already */
	/* gid can be 0 to denote no gid change -- but we will be using
	   0700 anyway so the actual gid is not really relevant */
	if (chown(tmpdir_buf, uid, gid)) {}
	R_TempDir = strdup(tmpdir_buf);
	if (workdir && /* FIXME: gid=0 will be bad here ! */
		chown(wdname, uid, gid)) {}
}

/* send/recv wrappers that are more robust */
int cio_send(int s, const void *buffer, int length, int flags) {
	int n;
	while ((n = send(s, buffer, length, flags)) == -1) {
		/* the only case we handle specially is EINTR to recover automatically */
		if (errno != EINTR) break;			
	}
	return n;
}

static int last_idle_time;

/* FIXME: self.* commands can be loaded either from Rserve.so or from stand-alone binary.
   This will cause a mess since some things are private and some are not - we have to sort that out.
   In the meantime a quick hack is to make the relevant config (here enable_oob) global */
int enable_oob = 0;
args_t *self_args;
/* object to send with the idle call; it could be used for notification etc. */
 SEXP idle_object;

static int send_oob_sexp(int cmd, SEXP exp);

/*  */
int cio_recv(int s, void *buffer, int length, int flags) {
	int n;
	struct timeval timv;
    fd_set readfds;
	if (!last_idle_time) {
		last_idle_time = (int) time(NULL);
		if (!idle_object)
			idle_object = R_NilValue;
	}
	while (1) {
		/* the timeout only determines granularity of idle calls */
		timv.tv_sec = 1; timv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(s, &readfds);
		n = select(s + 1, &readfds, 0, 0, &timv);
		if (n == -1) {
			if (errno == EINTR)
				continue; /* recover */
			return -1;
		}
		if (n)
			return recv(s, buffer, length, flags);
		if (idle_timeout) {
			int delta = ((int) time(NULL)) - last_idle_time;
			if (delta > idle_timeout) {
				/* go only in oob mode */
				if (self_args && enable_oob) {
					SEXP q = PROTECT(allocVector(VECSXP, 2));
					SET_VECTOR_ELT(q, 0, mkString("idle"));
					SET_VECTOR_ELT(q, 1, idle_object);
					send_oob_sexp(OOB_SEND, q);
					UNPROTECT(1);
				}
				last_idle_time = (int) time(NULL);
			}
		}
	}
	return -1;
}

static int set_user(const char *usr) {
    struct passwd *p = getpwnam(usr);
	if (!p) return 0;
	prepare_set_user(p->pw_uid, p->pw_gid);
	if (setgid(p->pw_gid)) return 0;
	initgroups(p->pw_name, p->pw_gid);
	if (setuid(p->pw_uid)) return 0;
	return 1;
}

static int fork_http(args_t *arg) {
#ifdef unix
	int res = fork();
	if (res == -1) RSEprintf("WARNING: fork() failed in fork_http(): %s\n",strerror(errno));
#else
	int res = -1;
#endif
	if (res == 0 && http_user && !set_user(http_user)) {
#ifdef STANDALONE_RSERVE
		fprintf(stderr, "ERROR: failed to set user '%s', aborting\n", http_user);
#endif
		exit(1);
	}
	return res;
}

static int fork_https(args_t *arg) {
#ifdef unix
	int res = fork();
	if (res == -1) RSEprintf("WARNING: fork() failed in fork_https(): %s\n",strerror(errno));
#else
	int res = -1;
#endif
	if (res == 0 && https_user && !set_user(https_user)) {
#ifdef STANDALONE_RSERVE
		fprintf(stderr, "ERROR: failed to set user '%s', aborting\n", https_user);
#endif
		exit(1);
	}
	return res;
}

static int fork_ws(args_t *arg) {
#ifdef unix
	int res = fork();
	if (res == -1) RSEprintf("WARNING: fork() failed in fork_ws(): %s\n",strerror(errno));
#else
	int res = -1;
#endif
	if (res == 0 && ws_user && !set_user(ws_user)) {
#ifdef STANDALONE_RSERVE
		fprintf(stderr, "ERROR: failed to set user '%s', aborting\n", ws_user);
#endif
		exit(1);
	}
	return res;
}
#else
static int fork_http(args_t *arg) { return -1; }
static int fork_https(args_t *arg) { return -1; }
static int fork_ws(args_t *arg) { return -1; }
#endif

#ifdef STANDALONE_RSERVE
static const char *rserve_ver_id = "$Id$";
static char rserve_rev[16]; /* this is generated from rserve_ver_id by main */
#endif

#ifdef HAVE_RSA
#include <openssl/rand.h>

static void generate_random_bytes(void *buf, int len) {
	if (RAND_bytes(buf, len) != 1 &&
		RAND_pseudo_bytes(buf, len) == -1) {
		int i;
		for (i = 0; i < len; i++)
			((char*)buf)[i] = (char) random();
	}
}

#else
static void generate_random_bytes(void *buf, int len) {
	int i;
	for (i = 0; i < len; i++)
		((char*)buf)[i] = (char) random();
}
#endif

static void generate_addr(rsmsg_addr_t *addr) {
	generate_random_bytes(addr, sizeof(*addr));
}

#define localUCIX UCIX

/* string encoding handling */
#if (R_VERSION < R_Version(2,8,0)) || (defined DISABLE_ENCODING)
#define mkRChar(X) mkChar(X)
#else
#define USE_ENCODING 1
cetype_t string_encoding = CE_NATIVE;  /* default is native */
#define mkRChar(X) mkCharCE((X), string_encoding)
#endif

static SEXP Rserve_ctrlCMD(int command, SEXP what) {
	long cmd[2] = { 0, 0 };
	const char *str;
	if (!self_control) Rf_error("R control is not premitted in this instance of Rserve");
	if (!parent_io) Rf_error("Connection to the parent process has been lost.");
	if (TYPEOF(what) != STRSXP || LENGTH(what) != 1) Rf_error("Invalid parameter, must be a single string.");
	str = CHAR(STRING_ELT(what, 0)); /* FIXME: should we do some re-coding? This is not ripe for CHAR_FE since the target is our own instance and not the client ... */
	cmd[0] = command;
	cmd[1] = strlen(str) + 1;
	if (rsio_write(parent_io, str, strlen(str) + 1, command, -1)) {
#ifdef RSERV_DEBUG
		printf(" - Rserve_ctrlCMD send to parent pipe (cmd=%ld, len=%ld) failed, closing parent pipe\n", cmd[0], cmd[1]);
#endif
		rsio_free(parent_io);
		parent_io = 0;
		Rf_error("Error writing to parent pipe");
	}
	return ScalarLogical(1);
}

SEXP Rserve_ctrlEval(SEXP what) {
	return Rserve_ctrlCMD(CCTL_EVAL, what);
}

SEXP Rserve_ctrlSource(SEXP what) {
	return Rserve_ctrlCMD(CCTL_SOURCE, what);
}	

/* this is the representation of NAs in strings. We chose 0xff since that should never occur in UTF-8 strings. If 0xff occurs in the beginning of a string anyway, it will be doubled to avoid misrepresentation. */
static const unsigned char NaStringRepresentation[2] = { 255, 0 };

static int set_string_encoding(const char *enc, int verbose) {
#ifdef USE_ENCODING
	if (!strcmp(enc, "native")) string_encoding = CE_NATIVE;
	else if (!strcmp(enc, "latin1")) string_encoding = CE_LATIN1;
	else if (!strcmp(enc, "utf8")) string_encoding = CE_UTF8;
	else {
		if (verbose)
			RSEprintf("WARNING: invalid encoding value '%s' - muse be one of 'native', 'latin1' or 'utf8'.\n", enc);
		return 0;
	}
	return 1;
#else
	if (verbose)
		RSEprintf("WARNING: 'encoding' defined but this Rserve has no encoding support.\n");
	return 0;
#endif
}

/* "smart" atoi - accepts 0x for hex and 0 for octal */
static int satoi(const char *str) {
	if (!str) return 0;
	if (str[0]=='0') {
		if (str[1]=='x')
			return strtol(str + 2, 0, 16);
		if (str[1]>='0' && str[1]<='9')
			return strtol(str + 1, 0, 8);
	}
	return atoi(str);
}

static char *getParseName(int n) {
    switch(n) {
    case PARSE_NULL: return "null";
    case PARSE_OK: return "ok";
    case PARSE_INCOMPLETE: return "incomplete";
    case PARSE_ERROR: return "error";
    case PARSE_EOF: return "EOF";
    }
    return "<unknown>";
}

#ifdef RSERV_DEBUG

static void printSEXP(SEXP e) /* merely for debugging purposes
						  in fact Rserve binary transport supports
						  more types than this function. */
{
    int t = TYPEOF(e);
    int i = 0;

	if (TYPEOF(ATTRIB(e)) == LISTSXP)
		printf("[*has attr*] ");
    
    if (t==NILSXP) {
		printf("NULL value\n");
		return;
    }
    if (t==LANGSXP) {
		printf("language construct\n");
		return;
    }
    if (t==LISTSXP) {
		SEXP l = e;
		printf("dotted-pair list:\n");
		while (l != R_NilValue) {
			if (dumpLimit && i>dumpLimit) { printf("..."); break; };
			if (TAG(l) != R_NilValue) {
				printf("(TAG:"); printSEXP(TAG(l)); printf(") ");
			}
			printSEXP(CAR(l));
			l=CDR(l);
		}
		return;
    }
    if (t==REALSXP) {
		if (LENGTH(e)>1) {
			printf("Vector of real variables: ");
			while(i<LENGTH(e)) {
				printf("%f",REAL(e)[i]);
				if (i<LENGTH(e)-1) printf(", ");
				if (dumpLimit && i>dumpLimit) {
					printf("..."); break;
				}
				i++;
			}
			putchar('\n');
		} else
			printf("Real variable %f\n",*REAL(e));
		return;
    }
    if (t==CPLXSXP) {
		if (LENGTH(e)>1) {
			printf("Vector of complex variables: ");
			while(i<LENGTH(e)) {
				printf("%f+%fi",COMPLEX(e)[i].r,COMPLEX(e)[i].i);
				if (i<LENGTH(e)-1) printf(", ");
				if (dumpLimit && i>dumpLimit) {
					printf("..."); break;
				}
				i++;
			}
			putchar('\n');
		} else
			printf("Complex variable %f+%fi\n",COMPLEX(e)[0].r,COMPLEX(e)[0].i);
		return;
    }
    if (t==RAWSXP) {
		printf("Raw vector: ");
		while(i<LENGTH(e)) {
			printf("%02x",((unsigned int)((unsigned char*)RAW(e))[i])&0xff);
			if (i<LENGTH(e)-1) printf(" ");
			if (dumpLimit && i>dumpLimit) {
				printf("..."); break;
			}
			i++;
		}
		putchar('\n');
		return;
    }
    if (t==EXPRSXP) {
		printf("Vector of %d expressions:\n",LENGTH(e));
		while(i<LENGTH(e)) {
			if (dumpLimit && i>dumpLimit) { printf("..."); break; };
			printSEXP(VECTOR_ELT(e,i));
			i++;
		}
		return;
    }
    if (t==INTSXP) {
		printf("Vector of %d integers:\n",LENGTH(e));
		while(i<LENGTH(e)) {
			if (dumpLimit && i>dumpLimit) { printf("..."); break; }
			printf("%d",INTEGER(e)[i]);
			if (i<LENGTH(e)-1) printf(", ");
			i++;
		}
		putchar('\n');
		return;
    }
    if (t==LGLSXP) {
		printf("Vector of %d logicals:\n",LENGTH(e));
		while(i<LENGTH(e)) {
			if (dumpLimit && i>dumpLimit) { printf("..."); break; }
			printf("%d",INTEGER(e)[i]);
			if (i<LENGTH(e)-1) printf(", ");
			i++;
		}
		putchar('\n');
		return;
    }
    if (t==VECSXP) {
		printf("Vector of %d fields:\n",LENGTH(e));
		while(i<LENGTH(e)) {
			if (dumpLimit && i>dumpLimit) { printf("..."); break; };
			printSEXP(VECTOR_ELT(e,i));
			i++;
		}
		return;
    }
    if (t==STRSXP) {
		printf("String vector of length %d:\n",LENGTH(e));
		while(i<LENGTH(e)) {
			if (dumpLimit && i>dumpLimit) { printf("..."); break; };
			printSEXP(VECTOR_ELT(e,i)); i++;
		}
		return;
    }
    if (t==CHARSXP) {
		printf("scalar string: \"%s\"\n", CHAR(e));
		return;
    }
    if (t==SYMSXP) {
		printf("Symbol, name: "); printSEXP(PRINTNAME(e));
		return;
    }
    if (t==S4SXP) {
		printf("S4 object\n");
		return;
    }
    printf("Unknown type: %d\n",t);
}
#endif

/* if set Rserve doesn't accept other than local connections. */
static int localonly = 1;

/* send a response including the data part */
void Rserve_QAP1_send_resp(args_t *arg, int rsp, rlen_t len, const void *buf) {
	server_t *srv = arg->srv;
	struct phdr ph;
	rlen_t i = 0;
	/* do not tag OOB with CMD_RESP */
	if (!(rsp & CMD_OOB)) rsp |= CMD_RESP;
    ph.cmd = itop(rsp);	
    ph.len = itop(len);
#ifdef __LP64__
	ph.res = itop(len >> 32);
#else
	ph.res = 0;
#endif
	ph.msg_id = (int) arg->msg_id;
#ifdef RSERV_DEBUG
    printf("OUT.sendRespData\nHEAD ");
    printDump(&ph,sizeof(ph));
	if (len == 0)
		printf("(no body)\n");
	else {
		printf("BODY ");
		printDump(buf, len);
	}

	if (io_log) {
		struct timeval tv;
		snprintf(io_log_fn, sizeof(io_log_fn), "/tmp/Rserve-io-%d.log", getpid());
		FILE *f = fopen(io_log_fn, "a");
		if (f) {
			double ts = 0;
			if (!gettimeofday(&tv, 0))
				ts = ((double) tv.tv_sec) + ((double) tv.tv_usec) / 1000000.0;
			if (first_ts < 1.0) first_ts = ts;
			fprintf(f, "%.3f [+%4.3f]  SRV --> CLI  [sendRespData]  (%x, %ld bytes)\n   HEAD ", ts, ts - first_ts, rsp, (long) len);
			fprintDump(f, &ph, sizeof(ph));
			fprintf(f, "   BODY ");
			if (len) fprintDump(f, buf, len); else fprintf(f, "<none>\n");
			fclose(f);
		}
	}
#endif
    
    srv->send(arg, (char*)&ph, sizeof(ph));
	
	while (i < len) {
		int rs = srv->send(arg, (char*)buf + i, (len - i > max_sio_chunk) ? max_sio_chunk : (len - i));
		if (rs < 1)
			break;
		i += rs;
	}
}

/* initial ID string */
char *IDstring="Rsrv0103QAP1\r\n\r\n--------------\r\n";

/* require authentication flag (default: no) */
int authReq = 0;
/* use plain password flag (default: no) */
int usePlain = 0;

/* max. size of the input buffer (per connection) */
rlen_t maxInBuf = 256 * (1024 * 1024); /* default is 256MB */

/* if non-zero then the password file is loaded before client su so it can be unreadable by the clients */
int cache_pwd = 0;
char *pwd_cache;

/* if client_su is set then Rserve switches uid/gid */
#define SU_NOW    0
#define SU_SERVER 1
#define SU_CLIENT 2
static int su_time = SU_NOW;

static void load_pwd_cache() {
	FILE *f = fopen(pwdfile, "r");
	if (f) {
		int fs = 0;
		fseek(f, 0, SEEK_END);
		fs = ftell(f);
		fseek(f, 0, SEEK_SET);
		pwd_cache = (char*) malloc(fs + 1);
		if (pwd_cache) {
			if (fread(pwd_cache, 1, fs, f) != fs) {
				free(pwd_cache);
				pwd_cache = 0;
			} else
				pwd_cache[fs] = 0;
		}
		fclose(f);
	}
}

struct source_entry {
    struct source_entry* next;
    char line[8];
} *src_list=0, *src_tail=0;

static int ws_port = -1, enable_qap = 1, enable_ws_qap = 0, enable_ws_text = 0, wss_port = 0;
static int ws_qap_oc = 0, qap_oc = 0;
static int http_port = -1;
static int https_port = -1;
static int switch_qap_tls = 0;
static int ws_upgrade = 0;
static int http_raw_body = 0;

static int use_ipv6 = 0;

static int requested_uid = 0, requested_gid = 0;
static char *requested_chroot = 0;
static int auto_uid = 0, auto_gid = 0;
static int default_uid = 0, default_gid = 0;
static int random_uid = 0, random_gid = 0;
static int random_uid_low = 32768, random_uid_high = 65530;

#ifdef HAVE_RSA
static int rsa_load_key(const char *buf);
#endif

/* FIXME: we are not preventing collisions - we have to keep track of
   the uid assignments to children and no reuse those alive */
static int get_random_uid() {
	int uid = random_uid_low +
		UCIX % (random_uid_high - random_uid_low + 1);
	return uid;
}

static int performConfig(int when) {
	int fail = 0;
#ifdef unix
	if (when == SU_NOW) {
		if (requested_chroot && chroot(requested_chroot)) {
			perror("chroot");
			RSEprintf("chroot(\"%s\"): failed.\n", requested_chroot);
			fail++;
		}
	}
	if (cache_pwd)
		load_pwd_cache();/* load pwd file into memory before su */
	if (when == SU_CLIENT && random_uid) { /* FIXME: we */
		int ruid = get_random_uid();
		prepare_set_user(ruid, random_gid ? ruid : 0);
		if (random_gid)
			setgid(ruid);
		setuid(ruid);
	} else if (su_time == when) {
		if (requested_uid) prepare_set_user(requested_uid, requested_gid);
		if (requested_gid) setgid(requested_gid);
		if (requested_uid) setuid(requested_uid);
	}
#endif
	return fail;
}

/* called once the server process is setup (e.g. after
   daemon fork for forked servers) */
static void RSsrv_init() {
	if (pidfile) {
		FILE *f = fopen(pidfile, "w");
		if (f) {
			fprintf(f, "%d\n", getpid());
			fclose(f);
		} else RSEprintf("WARNING: cannot write into pid file '%s'\n", pidfile);
	}

	generate_addr(&server_addr);
}

static void RSsrv_done() {
	if (pidfile) {
		unlink(pidfile);
		pidfile = 0;
	}
}

static char expand_buffer[1024];
static char expand_tmp[128];

static const char *expand_conf_string(const char *str) {
	char *dst = expand_buffer;
	const char *c = str, *x = str;
	if (!str || !*str) return "";
	while ((x = strstr(c, "${"))) {
		char *tr = strchr(x + 2, '}');
		if (tr && tr - x < 64) {
			char *repl;
			int rlen;
			if (x > c) {
				memcpy(dst, c, x - c);
				dst += x - c;
			}
			memcpy(expand_tmp, x + 2, tr - x - 2);
			expand_tmp[tr - x - 2] = 0;
			repl = getenv(expand_tmp);
			if (!repl) repl = "";
			rlen = strlen(repl);
			if (rlen) {
				memcpy(dst, repl, rlen);
				dst += rlen;
			}
			c = tr + 1;
		} else { /* jsut ignore the ${ part */
			memcpy(dst, x, 2);
			dst += 2;
			c = x + 2;
		}
	}
	if (dst == expand_buffer) return str; /* nothing got expanded */
	strcpy(dst, c); /* copy the remaining content */
	return expand_buffer;
}

static int conf_is_true(const char *str) {
	return  (str && (*str == '1' || *str == 'y' || *str == 'e' || *str == 'T')) ? 1 : 0;
}

/* attempts to set a particular configuration setting
   returns: 1 = setting accepted, 0 = unknown setting, -1 = setting known but failed */
static int setConfig(const char *c, const char *p) {
	p = expand_conf_string(p);
#ifdef RSERV_DEBUG
	if (p == expand_buffer) printf("conf> after expansion parameter=\"%s\"\n", p);
#endif
	if (!strcmp(c, "log.io")) {
#ifdef RSERV_DEBUG
		io_log = conf_is_true(p);
#endif
		return 1;
	}
	if (!strcmp(c, "deamon") /* typo! but we keep it for compatibility */ || !strcmp(c, "daemon")) {
#ifdef DAEMON
		daemonize = conf_is_true(p);
#endif
		return 1;
	}
	if (!strcmp(c, "msg.id")) {
		use_msg_id = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "remote")) {
		localonly = !conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "tag.argv")) {
		tag_argv = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "ulog")) {
		ulog_set_path((*p) ? p : 0);
		return 1;
	}
	if (!strcmp(c, "keep.alive")) {
		if (conf_is_true(p))
			global_srv_flags |= SRV_KEEPALIVE;
		else
			global_srv_flags &= ~ SRV_KEEPALIVE;
		return 1;
	}
	if (!strcmp(c, "switch.qap.tls")) {
		switch_qap_tls = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "qap.oc") || !strcmp(c, "rserve.oc")) {
		qap_oc = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "console.oob")) {
		oob_console = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "websockets.qap.oc")) {
		ws_qap_oc = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "random.uid")) {
		random_uid = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "random.gid")) {
		random_gid = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "random.uid.range")) {
		const char *c = p;
		int lo = atoi(c);
		if (lo < 1)
			RSEprintf("ERROR: invalid random.uid.range start (%d)\n", lo);
		else {
			while (*c >= '0' && *c <= '9') c++;
			while (*c && (*c < '0' || *c > '9')) c++;
			if (*c) {
				int hi = atoi(c);
				if (hi <= lo)
					RSEprintf("ERROR: invalid random.uid.range (%d..%d)\n", lo, hi);
				else {
					random_uid_low  = lo;
					random_uid_high = hi;
				}
			}
		}
		return 1;
	}
	if (!strcmp(c, "auto.uid")) {
		auto_uid = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "auto.gid")) {
		auto_gid = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "default.uid")) {
		default_uid = satoi(p);
		return 1;
	}
	if (!strcmp(c, "default.gid")) {
		default_gid = satoi(p);
		return 1;
	}
	if (!strcmp(c, "oob.idle.interval")) {
		idle_timeout = (*p) ? atoi(p) : 0;
		return 1;
	}
	if (!strcmp(c,"port") || !strcmp(c, "qap.port")) {
		if (*p) {
			int np = satoi(p);
			if (np > 0) port = np;
		}
		return 1;
	}
	if (!strcmp(c, "ipv6")) {
		use_ipv6 = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "http.upgrade.websockets")) {
		ws_upgrade = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "http.raw.body")) {
		http_raw_body = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c,"websockets.port")) {
		if (*p) {
			int np = satoi(p);
			if (np > 0) ws_port = np;
		}
		return 1;
	}
	if (!strcmp(c,"http.port")) {
		if (*p) {
			int np = satoi(p);
			if (np > 0) http_port = np;
		}
		return 1;
	}
	if (!strcmp(c, "tls.key")) {
		tls_t *tls = shared_tls(0);
		if (!tls)
			tls = shared_tls(new_tls());
		set_tls_pk(tls, p);
		return 1;
	}
	if (!strcmp(c, "tls.ca")) {
		tls_t *tls = shared_tls(0);
		if (!tls)
			tls = shared_tls(new_tls());
		set_tls_ca(tls, p, 0);
		return 1;
	}
	if (!strcmp(c, "tls.cert")) {
		tls_t *tls = shared_tls(0);
		if (!tls)
			tls = shared_tls(new_tls());
		set_tls_cert(tls, p);
		return 1;
	}
	if (!strcmp(c, "pid.file") && *p) {
		pidfile = strdup(p);
		return 1;
	}
	if (!strcmp(c, "rsa.key")) {
#ifdef HAVE_RSA
		if (*p) {
			FILE *f = fopen(p, "r");
			if (f) {
				char *buf = (char*) malloc(65536);
				if (buf) {
					int n = fread(buf, 1, 65535, f);
					buf[n] = 0;
					if (rsa_load_key(buf) == -1)
						RSEprintf("ERROR: not a valid RSA private key in '%s'\n", p);
				} else RSEprintf("ERROR: cannot allocate memory for the RSA key\n");
				fclose(f);
			} else RSEprintf("ERROR: cannot open rsa.key file '%s'\n", p);
		}
#else
		RSEprintf("WARNING: rsa.key specified but RSA is not supported in this build!\n");
#endif
		return 1;
	}
	if (!strcmp(c, "tls.port") || !strcmp(c, "qap.tls.port")) {
		if (*p) {
			int np = satoi(p);
			if (np > 0) tls_port = np;
		}
		return 1;
	}
	if (!strcmp(c,"https.port") || !strcmp(c, "http.tls.port")) {
		if (*p) {
			int np = satoi(p);
			if (np > 0) https_port = np;
		}
		return 1;
	}
	if (!strcmp(c, "websockets.tls.port")) {
		if (*p) {
			int np = satoi(p);
			if (np > 0) wss_port = np;
		}
		return 1;
	}
	if (!strcmp(c, "rserve") || !strcmp(c, "qap")) {
		enable_qap = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "websockets.qap")) {
		enable_ws_qap = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "websockets.text")) {
		enable_ws_text = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "websockets") && conf_is_true(p)) {
		enable_ws_qap = 1;
		enable_ws_text = 1;
		return 1;
	}
	if (!strcmp(c,"maxinbuf")) {
		if (*p) {
			long ns = atol(p);
			if (ns > 32) {
				maxInBuf = ns;
				maxInBuf *= 1024;
			}
		}
		return 1;
	}
	if (!strcmp(c,"source") || !strcmp(c,"eval")) {
#ifdef RSERV_DEBUG
		printf("Found source entry \"%s\"\n", p);
#endif
		if (*p) {
			struct source_entry* se= (struct source_entry*) malloc(sizeof(struct source_entry)+strlen(p)+16);
			if (!strcmp(c,"source")) {
				strcpy(se->line, "try(source(\"");
				strcat(se->line, p);
				strcat(se->line, "\"))");
			} else
				strcpy(se->line, p);
			se->next=0;
			if (!src_tail)
				src_tail=src_list=se;
			else {
				src_tail->next=se;
				src_tail=se;
			}
		}
		return 1;
	}
	if (!strcmp(c,"maxsendbuf")) {
		if (*p) {
			long ns = atol(p);
			if (ns > 32) {
				maxSendBufSize = ns;
				maxSendBufSize *= 1024;
			}
		}
		return 1;
	}
#ifdef unix
	if (!strcmp(c, "su") && *p) {
		if (*p == 'n') su_time = SU_NOW;
		else if (*p == 's') su_time = SU_SERVER;
		else if (*p == 'c') su_time = SU_CLIENT;
		else {
			RSEprintf("su value invalid - must be 'now', 'server' or 'client'.\n");
			return -1;
		}
		return 1;
	}
	if (!strcmp(c, "http.user") && *p) {
		http_user = strdup(p);
		return 1;
	}
	if (!strcmp(c, "https.user") && *p) {
		https_user = strdup(p);
		return 1;
	}
	if (!strcmp(c, "websockets.user") && *p) {
		ws_user = strdup(p);
		return 1;
	}
	if (!strcmp(c,"uid") && *p) {
		requested_uid = satoi(p);
		return 1;
	}
	if (!strcmp(c,"gid") && *p) {
		requested_gid = satoi(p);
		return 1;
	}
	if (!strcmp(c,"chroot") && *p) {
		requested_chroot = strdup(p);
		return 1;
	}
	if (!strcmp(c,"umask") && *p) {
		umask_value = satoi(p);
		return 1;
	}
#endif
	if (!strcmp(c,"allow") && *p) {
		char **l;
		if (!allowed_ips) {
			allowed_ips = (char**) malloc(sizeof(char*)*128);
			*allowed_ips = 0;
		}
		l = allowed_ips;
		while (*l) l++;
		if (l - allowed_ips >= 127) {
			RSEprintf("WARNING: Maximum of allowed IPs (127) exceeded, ignoring 'allow %s'\n", p);
			return -1;
		} else {
			*l = strdup(p);
			l++;
			*l = 0;
		}
		return 1;
	}
	if (!strcmp(c, "control") && conf_is_true(p)) {
		child_control = 1;
		return 1;
	}
	if (!strcmp(c, "shutdown")) {
		disable_shutdown = !conf_is_true(p);
		return 1;
	}
	if (!strcmp(c,"workdir")) {
		workdir = (*p) ? strdup(p) : 0;
		return 1;
	}
	if (!strcmp(c,"workdir.clean") && p) {
		wipe_workdir = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "workdir.mode")) {
		int cm = satoi(p);
		if (!cm)
			RSEprintf("ERROR: invalid workdir.mode\n");
		else {
			wd_mode = cm;
			if ((wd_mode & 0700) != 0700)
				RSEprintf("WARNING: workdir.mode does not contain 0700 - this may cause problems\n");
		}
		return 1;
	}
	if (!strcmp(c, "workdir.parent.mode")) {
		int cm = satoi(p);
		if (!cm)
			RSEprintf("ERROR: invalid workdir.parent.mode\n");
		else {
			wdt_mode = cm;
			if ((wdt_mode & 0700) != 0700)
				RSEprintf("WARNING: workdir.parent.mode does not contain 0700 - this may cause problems\n");
		}
		return 1;
	}
	if (!strcmp(c,"encoding") && *p) {
		set_string_encoding(p, 1);
		return 1;
	}
	if (!strcmp(c,"socket")) {
		localSocketName = (*p) ? strdup(p) : 0;
		return 1;
	}
	if (!strcmp(c,"sockmod") && *p) {
		localSocketMode = satoi(p);
		return 1;
	}
	if (!strcmp(c,"pwdfile")) {
		pwdfile = (*p) ? strdup(p) : 0;
		return 1;
	}
	if (!strcmp(c,"auth.function")) {
		auth_fn = (*p) ? strdup(p) : 0;
		return 1;
	}
	if (!strcmp(c,"auth")) {
		authReq = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c,"interactive")) {
		Rsrv_interactive = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c,"plaintext")) {
		usePlain = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c,"oob")) {
		enable_oob = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c,"fileio")) {
		allowIO = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "r-control") || !strcmp(c, "r.control")) {
		self_control = conf_is_true(p);
		return 1;
	}
	if (!strcmp(c, "cachepwd")) {
		cache_pwd = (*p == 'i') ? 2 : conf_is_true(p);
		return 1;
	}
	return 0;
}

/* load config file */
static int loadConfig(const char *fn)
{
	FILE *f;
	char buf[512];
	char *c,*p,*c1;
    
#ifdef RSERV_DEBUG
	printf("Loading config file %s\n",fn);
#endif
	f = fopen(fn,"r");
	if (!f) {
#ifdef RSERV_DEBUG
		printf("Failed to find config file %s\n",fn);
#endif
		return -1;
	}
	
	buf[511] = 0;
	while(!feof(f))
		if (fgets(buf,511,f)) {
			c = buf;
			while(*c == ' ' || *c == '\t') c++;
			if (!*c || *c == '\n' || *c == '#' || *c == ';') continue; /* skip comments and empty lines */
			p = c;
			while(*p && *p != '\t' && *p != ' ' && *p != '=' && *p != ':') {
				if (*p >= 'A' && *p <= 'Z') *p |= 0x20; /* to lower case */
				p++;
			}
			if (*p) {
				*p = 0;
				p++;
				while(*p && (*p == '\t' || *p == ' ')) p++;
			}
			c1 = p;
			while(*c1)
				if(*c1 == '\n' || *c1 == '\r') *c1 = 0; else c1++;

#ifdef RSERV_DEBUG
			printf("conf> command=\"%s\", parameter=\"%s\"\n", c, p);
#endif
			setConfig(c, p);
		}
    fclose(f);
#ifndef HAS_CRYPT
    if (!usePlain) {
		RSEprintf("WARNING: useplain=no, but this Rserve has no crypt support!\nSet useplain=yes or compile with crypt support (if your system supports crypt).\nFalling back to plain text password.\n");
		usePlain=1;
    }
#endif
#ifdef RSERV_DEBUG
    printf("Loaded config file %s\n",fn);
#endif

	if (cache_pwd == 2) load_pwd_cache();
				
	return 0;
}

/* size of the input buffer (default 512kB)
   was 2k before 1.23, but since 1.22 we support CMD_assign/set and hence
   the incoming packets can be substantially bigger.

   since 1.29 we support input buffer resizing,
   therefore we start with a small buffer and allocate more if necessary
*/

static rlen_t inBuf = 32768; /* 32kB should be ok unless CMD_assign sends large data */

/* static buffer size used for file transfer.
   The user is still free to allocate its own size  */
#define sfbufSize 32768 /* static file buffer size */

/* pid of the last child (not really used ATM) */
static int lastChild;

#ifdef FORKED
static void sigHandler(int i) {
    if (i==SIGTERM || i==SIGHUP)
		active = 0;
}

static void brkHandler(int i) {
#ifdef STANDALONE_RSERVE
    fprintf(stderr, "\nCaught break signal, shutting down Rserve.\n");
#else
	Rprintf("Caught break signal, shutting down Rserve.\n");
#endif
    active = 0;
    /* kill(getpid(), SIGUSR1); */
}
#endif

/* used for generating salt code (2x random from this array) */
const char *code64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWYXZabcdefghijklmnopqrstuvwxyz";

/** parses a string, stores the number of expressions in parts and the resulting statis in status.
    the returned SEXP may contain multiple expressions */ 
SEXP parseString(const char *s, int *parts, ParseStatus *status) {
    int maxParts = 1;
    const char *c = s;
    SEXP cv, pr = R_NilValue;
    
    while (*c) {
		if (*c == '\n' || *c == ';') maxParts++;
		c++;
    }
    
    PROTECT(cv = allocVector(STRSXP, 1));
    SET_STRING_ELT(cv, 0, mkRChar(s));  
    
    while (maxParts > 0) {
		pr = RS_ParseVector(cv, maxParts, status);
		if (*status != PARSE_INCOMPLETE && *status != PARSE_EOF) break;
		maxParts--;
    }
    UNPROTECT(1);
    *parts = maxParts;
    
    return pr;
}

/** parse a string containing the specified number of expressions */
SEXP parseExps(char *s, int exps, ParseStatus *status) {
    SEXP cv, pr;
    
    PROTECT(cv = allocVector(STRSXP, 1));
    SET_STRING_ELT(cv, 0, mkRChar(s));  
    pr = RS_ParseVector(cv, 1, status);
    UNPROTECT(1);
    return pr;
}

void voidEval(const char *cmd) {
    ParseStatus stat;
    int Rerror;
    int j = 0;
    SEXP xp = parseString(cmd,&j,&stat);
    
    PROTECT(xp);
#ifdef RSERV_DEBUG
    printf("voidEval: buffer parsed, stat=%d, parts=%d\n",stat,j);
    if (xp)
		printf("result type: %d, length: %d\n",TYPEOF(xp),LENGTH(xp));
    else
		printf("result is <null>\n");
#endif
    if (stat!=1) {
		UNPROTECT(1);
		return;
    } else {
#ifdef RSERV_DEBUG
		printf("R_tryEval(xp,R_GlobalEnv,&Rerror);\n");
#endif
		if (TYPEOF(xp) == EXPRSXP && LENGTH(xp) > 0) {
			int bi = 0;
			while (bi < LENGTH(xp)) {
				SEXP pxp = VECTOR_ELT(xp, bi);
				Rerror = 0;
#ifdef RSERV_DEBUG
				printf("Calling R_tryEval for expression %d [type=%d] ...\n", bi+1, TYPEOF(pxp));
#endif
				R_tryEval(pxp, R_GlobalEnv, &Rerror);
				bi++;
#ifdef RSERV_DEBUG
				printf("Expression %d, error code: %d\n", bi, Rerror);
				if (Rerror) printf(">> early error, aborting further evaluations\n");
#endif
				if (Rerror) break;
			}
		} else {
			Rerror = 0;
			R_tryEval(xp, R_GlobalEnv, &Rerror);
		}
		UNPROTECT(1);
    }
    return;
}

#define sendRespData(A, C, L, D) srv->send_resp(A, C, L, D)
#define sendResp(A,C) srv->send_resp(A, C, 0, 0)

struct sockaddr_in session_peer_sa;
SOCKET session_socket;
unsigned char session_key[32];

/* detach session and setup everything such that in can be resumed at some point */
int detach_session(args_t *arg) {
    SAIN ssa;
	SOCKET s = arg->s;
	server_t *srv = arg->srv;
	int port = 32768;
	SOCKET ss = FCF("open socket",socket(AF_INET,SOCK_STREAM,0));
    int reuse = 1; /* enable socket address reusage */
	socklen_t sl = sizeof(session_peer_sa);
	struct dsresp {
		int pt1;
		int port;
		int pt2;
		unsigned char key[32];
	} dsr;

	if (getpeername(s, (SA*) &session_peer_sa, &sl)) {
		sendResp(arg, SET_STAT(RESP_ERR,ERR_detach_failed));
		return -1;
	}

    setsockopt(ss,SOL_SOCKET,SO_REUSEADDR,(const char*)&reuse,sizeof(reuse));

	while ((port = (((int) random()) & 0x7fff)+32768)>65000) {};

	while (bind(ss,build_sin(&ssa,0,port),sizeof(ssa))) {
		if (errno!=EADDRINUSE) {
#ifdef RSERV_DEBUG
			printf("session: error in bind other than EADDRINUSE (0x%x)",  errno);
#endif
			closesocket(ss);
			sendResp(arg, SET_STAT(RESP_ERR,ERR_detach_failed));
			return -1;
		}
		port++;
		if (port>65530) {
#ifdef RSERV_DEBUG
			printf("session: can't find available prot to listed on.\n");
#endif
			closesocket(ss);
			sendResp(arg, SET_STAT(RESP_ERR,ERR_detach_failed));
			return -1;
		}
	}

    if (listen(ss,LISTENQ)) {
#ifdef RSERV_DEBUG
		printf("session: cannot listen.\n");
#endif
		closesocket(ss);
		sendResp(arg, SET_STAT(RESP_ERR,ERR_detach_failed));
		return -1;
	}

	{
		int i=0;
		while (i<32) session_key[i++]=(unsigned char) rand();
	}

#ifdef RSERV_DEBUG
	printf("session: listening on port %d\n", port);
#endif

	dsr.pt1  = itop(SET_PAR(DT_INT,sizeof(int)));
	dsr.port = itop(port);
	dsr.pt2  = itop(SET_PAR(DT_BYTESTREAM,32));
	memcpy(dsr.key, session_key, 32);							
	
	sendRespData(arg, RESP_OK, 3*sizeof(int)+32, &dsr);
	closesocket(s);
#ifdef RSERV_DEBUG
	printf("session: detached, closing connection.\n");
#endif
	session_socket = ss;
	return 0;
}

/* static char *sres_id = "RsS1                        \r\n\r\n"; */

/* resume detached session. return the new socket after resume is complete, but don't send the response message */
SOCKET resume_session() {
	SOCKET s=-1;
	SAIN lsa;
	socklen_t al=sizeof(lsa);
	char clk[32];

#ifdef RSERV_DEBUG
	printf("session: resuming session, waiting for connections.\n");
#endif

	while ((s=accept(session_socket, (SA*)&lsa,&al))>1) {
		if (lsa.sin_addr.s_addr != session_peer_sa.sin_addr.s_addr) {
#ifdef RSERV_DEBUG
			printf("session: different IP, rejecting\n");
#endif
			closesocket(s);
		} else {
			int n=0;
			if ((n=recv(s, (char*)clk, 32, 0)) != 32) {
#ifdef RSERV_DEBUG
				printf("session: expected 32, got %d = closing\n", n);
#endif
				closesocket(s);
			} else if (memcmp(clk, session_key, 32)) {
#ifdef RSERV_DEBUG
				printf("session: wrong key, closing\n");
#endif
				closesocket(s);
			} else {
#ifdef RSERV_DEBUG
				printf("session: accepted\n");
#endif
				return s;
			}
		}
	}
	return -1;
}

#ifdef WIN32
# include <process.h>
#endif
typedef struct child_process {
	pid_t pid;
	rsio_t *io;
	rsmsg_addr_t addr;
	struct child_process *prev, *next;
} child_process_t;

child_process_t *children;

/* handling of the password file - we emulate stdio API but allow both
   file and buffer back-ends transparently */
typedef struct pwdf {
	FILE *f;
	char *ptr;
} pwdf_t;
	
	
static pwdf_t *pwd_open() {
	pwdf_t *f = malloc(sizeof(pwdf_t));
	if (!f) return 0;
	if (cache_pwd && pwd_cache) {
		f->ptr = pwd_cache;
		f->f = 0;
		return f;
	}
	f->f = fopen(pwdfile, "r");
	if (!f->f) {
		free(f);
		return 0;
	}
	return f;
}
	
static char *pwd_gets(char *str, int n, pwdf_t *f) {
	char *c, *s = str;
	if (f->f) return fgets(str, n, f->f);
	c = f->ptr;
	while (*c == '\r' || *c == '\n') c++; /* skip empty lines */
	while (*c && *c != '\r' && *c != '\n' && (--n > 0)) *(s++) = *(c++);
	if (*c == '\n' || *c == '\r') {
		*c = 0; c++;
	}
	f->ptr = c;
	*s = 0;
	return str;
}
	
static int pwd_eof(pwdf_t *f) {
	if (f->f) return feof(f->f);
	return (f->ptr[0]) ? 0 : 1;
}
	
static void pwd_close(pwdf_t *f) {
	if (f->f)
		fclose(f->f);
	free(f);
}

/* forward decl for OCAP iteration */
typedef struct qap_runtime qap_runtime_t;

int OCAP_iteration(qap_runtime_t *rt, struct phdr *oob_hdr);

static int new_msg_id(args_t *args) {
	return use_msg_id ? (int) random() : 0;
}

static char dump_buf[32768]; /* scratch buffer that is static so mem alloc doesn't fail */

static int send_oob_sexp(int cmd, SEXP exp) {
	if (!self_args) Rf_error("OOB commands can only be used from code evaluated inside an Rserve client instance");
	if (!enable_oob) Rf_error("OOB command is disallowed by the current Rserve configuration - use 'oob enable' to allow its use");
	{
		args_t *a = self_args;
		server_t *srv = a->srv;
		char *sendhead = 0, *sendbuf;

		/* check buffer size vs REXP size to avoid dangerous overflows
		   todo: resize the buffer as necessary */
		rlen_t rs = QAP_getStorageSize(exp);
		/* FIXME: add a 4k security margin - it should no longer be needed,
		   originally the space was grown proportionally to account for a bug,
		   but that bug has been fixed. */
		rs += 4096;
#ifdef RSERV_DEBUG
		printf("result storage size = %ld bytes\n",(long)rs);
#endif
		sendbuf = (char*) malloc(rs);
		if (!sendbuf)
			Rf_error("Unable to allocate large enough buffer to send the object");
		else {
			/* first we have 4 bytes of a header saying this is an encoded SEXP, then comes the SEXP */
			char *sxh = sendbuf + 8;
			char *tail = (char*)QAP_storeSEXP((unsigned int*)sxh, exp, rs);

			/* set type to DT_SEXP and correct length */
			if ((tail - sxh) > 0xfffff0) { /* we must use the "long" format */
				rlen_t ll = tail - sxh;
				((unsigned int*)sendbuf)[0] = itop(SET_PAR(DT_SEXP | DT_LARGE, ll & 0xffffff));
				((unsigned int*)sendbuf)[1] = itop(ll >> 24);
				sendhead = sendbuf;
			} else {
				sendhead = sendbuf + 4;
				((unsigned int*)sendbuf)[1] = itop(SET_PAR(DT_SEXP,tail - sxh));
			}
#ifdef RSERV_DEBUG
			printf("stored SEXP; length=%ld (incl. DT_SEXP header)\n",(long) (tail - sendhead));
#endif
			a->msg_id = new_msg_id(a);
			sendRespData(a, cmd, tail - sendhead, sendhead);
			ulog("OOB sent (cmd=0x%x, %d bytes)", cmd, tail-sendhead);
			free(sendbuf);
		}
	}	
	return 1;
}

SEXP Rserve_oobSend(SEXP exp, SEXP code) {
	int oob_code = asInteger(code);
	return ScalarLogical(send_oob_sexp(OOB_USR_CODE(oob_code) | OOB_SEND, exp) == 1 ? TRUE : FALSE);
}

SEXP Rserve_oobMsg(SEXP exp, SEXP code) {
	struct phdr ph;
	int oob_code = asInteger(code), n;
	int res = send_oob_sexp(OOB_USR_CODE(oob_code) | OOB_MSG, exp);
	args_t *a = self_args; /* send_oob_sexp has checked this already so it's ok */
	server_t *srv = a->srv;
	int msg_id = a->msg_id; /* remember the msg id since it may get clobered */
	if (res != 1) /* never happens since send_oob_sexp returns only on success */
		Rf_error("Sending OOB_MSG failed");

	/* FIXME: this is very similar (but not the same) as the
	   read loop in Rserve itself - we should modularize this
	   and re-use the parts */
#ifdef RSERV_DEBUG
	printf("OOB-msg (%x) - waiting for response packet\n", oob_code);
#endif
	
	if (a->srv->flags & SRV_QAP_OC) { /* OCAP -- allow nested iteration */
		while ((n = OCAP_iteration(0, &ph)) == 1) {} /* run OCAP until we get our response or an error */
		n = (n == 2) ? sizeof(ph) : -1;
	} else
		n = srv->recv(a, (char*)&ph, sizeof(ph));

	if (n == sizeof(ph)) {
		size_t plen = 0, i;
#ifdef RSERV_DEBUG
		printf("\nOOB response header read result: %d\n", n);
		if (n > 0) printDump(&ph, n);
#endif
		ph.len = ptoi(ph.len);
		ph.cmd = ptoi(ph.cmd);
#ifdef __LP64__
		ph.res = ptoi(ph.res);
		plen = (unsigned int) ph.len;
		plen |= (((size_t) (unsigned int) ph.res) << 32);
#else
		plen = ph.len;
#endif
		a->msg_id = ph.msg_id;
#ifdef RSERV_DEBUG
		if (io_log) {
			struct timeval tv;
			snprintf(io_log_fn, sizeof(io_log_fn), "/tmp/Rserve-io-%d.log", getpid());
			FILE *f = fopen(io_log_fn, "a");
			if (f) {
				double ts = 0;
				if (!gettimeofday(&tv, 0))
					ts = ((double) tv.tv_sec) + ((double) tv.tv_usec) / 1000000.0;
				if (first_ts < 1.0) first_ts = ts;
				fprintf(f, "%.3f [+%4.3f]  SRV <-- CLI  [OOB recv]  (%x, %ld bytes)\n   HEAD ", ts, ts - first_ts, ph.cmd, (long) plen);
				fprintDump(f, &ph, sizeof(ph));
				fclose(f);
			}
		}
#endif
		if (plen) {
			char *orb = (char*) malloc(plen + 8);
			if (!orb) {
				/* error, but we have to pull the while packet as to not kill the queue */
				size_t chk = (sizeof(dump_buf) < max_sio_chunk) ? sizeof(dump_buf) : max_sio_chunk;
				i = plen;
				while((n = srv->recv(a, dump_buf, (i < chk) ? i : chk))) {
					if (n > 0) i -= n;
					if (i < 1 || n < 1) break;
				}
				if (i > 0) { /* something went wrong */
					/* FIXME: is this ok? do we need a common close function to shutdown TLS etc.? */
					closesocket(a->s);
					a->s = -1;
					Rf_error("cannot allocate buffer for OOB msg result + read error, aborting conenction");
				}
				/* packet discarded so connection is ok, but it is still a mem alloc error */
				Rf_error("cannot allocate buffer for OOB msg result");
			}
			/* ok, got the buffer, fill it */
			i = 0;
			while ((n = srv->recv(a, orb + i, (plen - i > max_sio_chunk) ? max_sio_chunk : (plen - i)))) {
				if (n > 0) i += n;
				if (i >= plen || n < 1) break;
			}
#ifdef RSERV_DEBUG
			if (io_log) {
				FILE *f = fopen(io_log_fn, "a");
				if (f) {
					fprintf(f, "   BODY ");
					if (i) fprintDump(f, orb, i); else fprintf(f, "<none>\n");
					fclose(f);
				}
			}
#endif
			if (i < plen) { /* uh, oh, the stream is corrupted */
				closesocket(a->s);
				a->s = -1;
				ulog("ERROR: read error while reading OOB msg respose, aborting connection");
				free(orb);
				Rf_error("read error while reading OOB msg respose, aborting connection");
			}
			ulog("OOBmsg response received");
			/* parse the payload - we ony support SEXPs though (and DT_STRING) */
			{
				unsigned int *hi = (unsigned int*) orb, pt = PAR_TYPE(ptoi(hi[0]));
				unsigned long psz = PAR_LEN(ptoi(hi[0]));
				SEXP res;
				if (pt & DT_LARGE) {
					psz |= hi[1] << 24;
					pt ^= DT_LARGE;
					hi++;
				}
				if (pt == DT_STRING) {
					const char *s = (const char *) ++hi, *se = s + psz;
					while (se-- > s) if (!*se) break;
					if (se == s && *s) {
						free(orb);
						Rf_error("unterminated string in OOB msg response");
					}
					res = mkString(s);
					free(orb);
					return res;
				}
				if (pt != DT_SEXP) {
					free(orb);
					Rf_error("unsupported parameter type %d in OOB msg response", PAR_TYPE(ptoi(hi[0])));
				}
				hi++;
				/* FIXME: we should use R allocation for orb since it will leak if there is an error in any allocation in decoding --- but we can't do the before reading since it would fail to read the stream in case of an error - so we're stuck a bit ... */
				res = QAP_decode(&hi);
				free(orb);
				return res;
			}
		}				
	} else {
		closesocket(a->s);
		a->s = -1;
		ulog("ERROR: read error in OOB msg header");
		Rf_error("read error im OOB msg header");
	}
	return R_NilValue;
}


/* server forking
   For a regular forked server this is simply fork(), but for pre-forked servers
   ... ?
 */
int RS_fork(args_t *arg) {
#ifdef unix
	return (arg->srv && arg->srv->fork) ? arg->srv->fork(arg) : fork();
#else
	return -1;
#endif
}

static void restore_signal_handlers(); /* forward decl */

/* return 0 if the child was prepared. Returns the result of fork() is forked and this is the parent */
int Rserve_prepare_child(args_t *args) {
#ifdef FORKED  
	long rseed = random();

    rseed ^= time(0);

	if (is_child) return 0; /* this is a no-op if we are already a child
							   FIXME: thould this be an error ? */

	parent_io = 0;

	/* we use the input pipe only if child control is enabled. disabled pipe means no registration */
	if (child_control || self_control)
		parent_io = rsio_new();

	generate_addr(&child_addr);

    if ((lastChild = RS_fork(args)) != 0) { /* parent/master part */
		int forkErrno = errno; //grab errno close to source before it can be changed by other failures
		/* close the connection socket - the child has it already */
		closesocket(args->s);
		if (lastChild == -1) {
			RSEprintf("WARNING: fork() failed in Rserve_prepare_child(): %s\n",strerror(forkErrno));
			if (parent_io) {
				rsio_free(parent_io);
				parent_io = 0;
			}
		}
		if (parent_io) { /* if we have a valid pipe register the child */
			child_process_t *cp = (child_process_t*) malloc(sizeof(child_process_t));
			rsio_set_parent(parent_io);
#ifdef RSERV_DEBUG
			printf("child %d was spawned, registering input pipe\n", (int)lastChild);
#endif
			cp->io = parent_io;
			cp->addr = child_addr;
			cp->pid = lastChild;
			cp->next = children;
			if (children) children->prev = cp;
			cp->prev = 0;
			children = cp;
		}
		return lastChild;
    }

	/* child part */
	restore_signal_handlers(); /* the handlers handle server shutdown so not needed in the child */

	if (main_argv && tag_argv && strlen(main_argv[0]) >= 8)
		strcpy(main_argv[0] + strlen(main_argv[0]) - 8, "/RsrvCHx");
	is_child = 1;
	if (parent_io) /* if we have a vaild pipe to the parent set it up */
		rsio_set_child(parent_io);

	srandom(rseed);
    
    parentPID = getppid();
    close_all_srv_sockets(); /* close all server sockets - this includes arg->ss */

#ifdef CAN_TCP_NODELAY
    {
     	int opt = 1;
        setsockopt(args->s, IPPROTO_TCP, TCP_NODELAY, (const char*) &opt, sizeof(opt));
    }
#endif

	performConfig(SU_CLIENT);

#endif

	self_args = args;

	return 0;
}

/* text protocol (exposed by WS) */
void Rserve_text_connected(void *thp) {
	args_t *arg = (args_t*) thp;
	server_t *srv = arg->srv;
	int bl = 1024*1024, bp = 0, n;
    ParseStatus stat;

	char *buf = (char*) malloc(bl--);
	if (!buf) {
		RSEprintf("ERROR: cannot allocate buffer\n");
		return;
	}

	self_args = arg;
	
	snprintf(buf, bl, "OK\n");
	srv->send(arg, buf, strlen(buf));

	while ((n = srv->recv(arg, buf + bp, bl - bp)) > 0) {
		bp += n;
		if (!(arg->flags & F_INFRAME)) { /* end of frame */
			SEXP xp;
			int parts;
			buf[bp] = 0;
			xp = parseString(buf, &parts, &stat);
			if (stat != PARSE_OK) {
				snprintf(buf, bl, "ERROR: Parse error: %s\n", getParseName(stat));
				srv->send(arg, buf, strlen(buf));
			} else {
				SEXP exp = R_NilValue;
				int err = 0;
				PROTECT(xp);
				if (TYPEOF(xp) == EXPRSXP && LENGTH(xp) > 0) {
					int bi = 0;
					while (bi < LENGTH(xp)) {
						SEXP pxp = VECTOR_ELT(xp, bi);
#ifdef RSERV_DEBUG
						printf("Calling R_tryEval for expression %d [type=%d] ...\n", bi + 1, TYPEOF(pxp));
#endif
						exp = R_tryEval(pxp, R_GlobalEnv, &err);
						bi++;
#ifdef RSERV_DEBUG
						printf("Expression %d, error code: %d\n", bi, err);
						if (err) printf(">> early error, aborting further evaluations\n");
#endif
						if (err) break;
					}
				} else
					exp = R_tryEval(xp, R_GlobalEnv, &err);
				if (!err && TYPEOF(exp) != STRSXP)
					exp = R_tryEval(lang2(install("as.character"), exp), R_GlobalEnv, &err);
				if (!err && TYPEOF(exp) == STRSXP) {
					int i = 0, l = LENGTH(exp);
					long tl = 0;
					char *sb = buf;
					while (i < l) {
						tl += strlen(Rf_translateCharUTF8(STRING_ELT(exp, i))) + 1;
						i++;
					}
					if (tl > bl) {
						sb = (char*) malloc(tl);
						if (!sb) {
							RSEprintf("ERROR: cannot allocate buffer for the result string\n");
							snprintf(buf, bl, "ERROR: cannot allocate buffer for the result string\n");
							srv->send(arg, buf, strlen(buf));
						}
					}
					if (sb) {
						tl = 0;
						for (i = 0; i < l; i++) {
							strcpy(sb + tl, Rf_translateCharUTF8(STRING_ELT(exp, i)));
							tl += strlen(sb + tl);
							if (i < l - 1) sb[tl++] = '\n';
						}
						srv->send(arg, sb, tl);
						if (sb != buf) free(sb);
					}
				} else {
					if (err)
						snprintf(buf, bl, "ERROR: evaluation error %d\n", err);
					else
						snprintf(buf, bl, "ERROR: result cannot be coerced into character\n");
					srv->send(arg, buf, strlen(buf));
				}
			}
			bp = 0;
		} else { /* continuation of a frame */
			if (bp >= bl) {
				RSEprintf("WARNING: frame exceeds max size, ignoring\n");
				while ((arg->flags & F_INFRAME) && srv->recv(arg, buf, bl) > 0) ;
				bp = 0;
			}
		}
	}
}

static char auth_buf[4096];

static const char *hexc = "0123456789abcdef";
static const char *sec_salt = "##secure"; /* special object to denote secure login */

static int auth_user(const char *usr, const char *pwd, const char *salt) {
	int authed = 0;
	unsigned char md5h[16];
	unsigned char sh1h[20];
	char md5_pwd[34];  /* MD5 hex representation of the password */
	char sha1_pwd[42]; /* SHA1 hex representation of the password */
	md5hash(pwd, strlen(pwd), md5h);
	sha1hash(pwd, strlen(pwd), sh1h);
	{ /* create hex-encoded versions of the password hashes */
		char *mp = md5_pwd;
		int k;
		for (k = 0; k < 16; k++) {
			*(mp++) = hexc[md5h[k] >> 4];
			*(mp++) = hexc[md5h[k] & 15];
		}
		*mp = 0;
		mp = sha1_pwd;
		for (k = 0; k < 20; k++) {
			*(mp++) = hexc[sh1h[k] >> 4];
			*(mp++) = hexc[sh1h[k] & 15];
		}
		*mp = 0;
	}
	authed = 1;
#ifdef RSERV_DEBUG
	printf("Authentication attempt (login='%s', pwd='%s', pwdfile='%s')\n", usr, pwd, pwdfile);
#endif
	if (auth_fn) {
		SEXP res, authv = PROTECT(allocVector(STRSXP, 2));
		int eres = 0;
		SET_STRING_ELT(authv, 0, mkChar(usr));
		SET_STRING_ELT(authv, 1, mkChar(pwd));
		res = R_tryEval(lang2(install(auth_fn), authv), R_GlobalEnv, &eres);
		UNPROTECT(1);
		return (res && TYPEOF(res) == LGLSXP && LENGTH(res) == 1 && LOGICAL(res)[0] == TRUE);
	}
	if (pwdfile) {
		pwdf_t *pwf;
		int ctrl_flag = 0, u_uid = 0, u_gid = 0;
		authed = 0; /* if pwdfile exists, default is access denied */
					/* we abuse variables of other commands since we are
					   the first command ever used so we can trash them */
		pwf = pwd_open();
		if (pwf) {
			auth_buf[sizeof(auth_buf) - 1] = 0;
			while(!pwd_eof(pwf))
				if (pwd_gets(auth_buf, sizeof(auth_buf) - 1, pwf)) {
					char *login = auth_buf, *c1 = auth_buf, *c2, *l_uid = 0, *l_gid = 0; /* <TAB> and <SPC> are valid separators */
					while(*c1 && *c1 != ' ' && *c1 != '\t') { /* [@]username[/uid[,gid]] {$MD5/SHA1hash|password} */
						if (*c1 == '/' && !l_uid) {
							*c1 = 0; l_uid = c1 + 1;
						} else if (*c1 == ',' && l_uid) {
							*c1 = 0; if (!l_gid) l_gid = c1 + 1;
						}
						c1++;
					}
					if (l_uid) u_uid = satoi(l_uid);
					if (l_gid) u_gid = satoi(l_gid);
					if (l_uid && !l_gid) u_gid = u_uid;

					if (*c1) {
						*c1 = 0;
						c1++;
						while(*c1 == ' ' || *c1 == '\t') c1++; /* skip leading blanks */
					}
					c2 = c1;
					while(*c2)
						if (*c2 == '\r' || *c2=='\n') *c2 = 0; else c2++;

					ctrl_flag = 0;
					if (*login == '#') continue; /* skip comment lines */

					if (*login == '@') { /* only users with @ prefix can use control commands */
						login++;
						ctrl_flag = 1;
					}

					if (*login == '*') { /* general authentication - useful to set control access but leave client access open */
						authed = 1;
#ifdef RSERV_DEBUG
						printf("Public authentication enabled (found * entry), allowing login without checking.\n");
#endif
						break;
					}
					if (!strcmp(login, usr)) { /* login found */
#ifdef RSERV_DEBUG
						printf("Found login '%s', checking password.\n", usr);
						printf(" - stored pwd = '%s', md5='%s', sha1='%s'\n", c1, md5_pwd, sha1_pwd);
#endif
						if ((usePlain || salt == sec_salt) &&
							((*c1 == '$' && strlen(c1) == 33 && !strcmp(c1 + 1, md5_pwd)) ||
							 (*c1 == '$' && strlen(c1) == 41 && !strcmp(c1 + 1, sha1_pwd)) ||
							 ((*c1 != '$' || (strlen(c1) != 33 && strlen(c1) !=41)) && !strcmp(c1, pwd)))) {
							authed = 1;
#ifdef RSERV_DEBUG
							printf(" - %s password matches.\n", (*c1 == '$' && strlen(c1) == 33) ? "MD5" :
								   ((*c1 == '$' && strlen(c1) == 41) ? "SHA1" : "plain"));
#endif
						} else {
#ifdef HAS_CRYPT
							c2 = crypt(c1, salt);
#ifdef RSERV_DEBUG
							printf(" - checking crypted '%s' vs '%s'\n", c2, pwd);
#endif
							if (!strcmp(c2, pwd)) authed = 1;
#endif
						}
					}
					if (authed) break;
				} /* if fgets */
			pwd_close(pwf);
			if (authed) {
				can_control = ctrl_flag;
#ifdef unix
				if (auto_uid && !u_uid && !default_uid) {
					authed = 0;
#ifdef DEBUG_RSERV
					printf(" - no uid in the user entry and no default.uid, refusing authentication\n");
#endif
					
				} else {
					if (auto_uid)
						prepare_set_user(u_uid ? u_uid : default_uid,
										 auto_gid ? (u_gid ? u_gid : default_gid) : 0);
					if (auto_gid)
						setgid(u_gid ? u_gid : default_gid);
					if (auto_uid)
						setuid(u_uid ? u_uid : default_uid);
				}
#endif
			}
		} /* if (pwf) */
	}
#ifdef DEBUG_RSERV
	printf(" - authentication %s\n", authed ? "succeeded" : "failed");
#endif
	return authed;
}

#ifdef HAVE_RSA
#include <openssl/rsa.h>
#include <openssl/rand.h>
#ifdef RSERV_DEBUG
#include <openssl/err.h>
#endif

static RSA *rsa_srv_key;

static char rsa_buf[32768];

#define SRV_KEY_LEN 512

/* from base64.c */
int base64decode(const char *src, void *dst, int max_len);

static int rsa_load_key(const char *buf) {
	int n;
	const char *c = buf;
	const unsigned char *ptr;
	while (1) {
		while (*c == ' ' || *c == '\t') c++;
		if (*c == '-') { /* header line */
			while (*c && *c != '\n' && *c != '\r') c++;
			while (*c == '\n' || *c == '\r') c++;
			continue;
		}
		if (*c == '\n' || *c == '\r')
			while (*c == '\n' || *c == '\r') c++;
		else break;		
	}
	if (!*c) return -1;
	n = base64decode(c, rsa_buf, sizeof(rsa_buf));
	if (n < 1) return -1;
	ptr = (const unsigned char*) rsa_buf;
	rsa_srv_key = d2i_RSAPrivateKey(NULL, &ptr, n);
	if (!rsa_srv_key) return -1;
	return 0;
}

static int rsa_gen_resp(char **dst) {
	unsigned char *kb;
	unsigned char *pt;
	int kl;
	if (!rsa_srv_key) {
#ifdef RSERV_DEBUG
		printf("rsa_gen_resp: generating RSA key\n");
#endif
		rsa_srv_key = RSA_generate_key(4096, 65537, 0, 0);
#ifdef RSERV_DEBUG
		printf(" - done\n");
#endif
	}
	if (!rsa_srv_key || RAND_bytes((unsigned char*) authkey, sizeof(authkey)) == 0)
		return 0;
	kb = calloc(65536, 1);
	if (!kb)
		return 0;
	kb[0] = SRV_KEY_LEN & 0xff;
	kb[1] = (SRV_KEY_LEN >> 8) & 0xff;
	memcpy(kb + 4, authkey, SRV_KEY_LEN);
	pt = kb + SRV_KEY_LEN + 8;
	kl = i2d_RSAPublicKey(rsa_srv_key, &pt);
	kb[SRV_KEY_LEN + 4] = kl & 0xff;
	kb[SRV_KEY_LEN + 5] = (kl >> 8) & 0xff;
	*dst = (char*) kb;
	return SRV_KEY_LEN + kl + 8;
}

static int rsa_decode(char *dst, const char *src, int len) {
	int dec = 0, blk = RSA_size(rsa_srv_key);
	while (len > 0) {
		int db = (len > blk) ? blk : len;
		int n = RSA_private_decrypt(db, (unsigned char*)src, (unsigned char*) dst, rsa_srv_key, RSA_PKCS1_OAEP_PADDING);
		if (n <= 0) {
#ifdef RSERV_DEBUG
			printf("rsa_decode (dec=%d, len=%d, db=%d) failed: %s\n", dec, len, db, ERR_error_string(ERR_get_error(), 0));
#endif
			return -1;
		}
		dst += n;
		dec += n;
		src += db;
		len -= db;
	}
	return dec;
}

/* the client encodes, so we don't use it for now
static int rsa_encode(char *dst, char *src, int len) {
	return RSA_public_encrypt(len, (unsigned char*)src, (unsigned char*) dst, rsa_srv_key, RSA_PKCS1_OAEP_PADDING);
}
*/

#endif

#ifdef unix

#include <unistd.h>
#include <dirent.h>

/* this should always be defined by POSIX but some broken system reportedly don't define it */
#ifndef PATH_MAX
#define PATH_MAX 512
#endif

static void rm_rf(const char *what) {
	struct stat st;
	if (!lstat(what, &st)) {
		chmod(what, st.st_mode | ((st.st_mode & S_IFDIR) ? S_IRWXU : S_IWUSR));
		if (st.st_mode & S_IFDIR) { /* dirs need to be deleted recursively */
			DIR *dir = opendir(what);
			char path[PATH_MAX];
			if (dir) {
				struct dirent *d;
				while ((d = readdir(dir))) {
					if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
						continue;
					snprintf(path, sizeof(path), "%s/%s", what, d->d_name);
					rm_rf(path);
				}
				closedir(dir);
			}
			rmdir(what);
		} else
			unlink(what);
	}
}
#endif

static char *child_workdir;

char *get_workdir() {
	return child_workdir;
}

static void setup_workdir() {
#ifdef unix
    if (workdir) {
		if (chdir(workdir) && mkdir(workdir, wdt_mode)) {}
		/* we override umask for the top-level
		   since it is shared */
		if (chmod(workdir, wdt_mode)) {}

		wdname[511]=0;
		snprintf(wdname, 511, "%s/conn%d", workdir, (int)getpid());
		rm_rf(wdname);
		mkdir(wdname, wd_mode);
		/* we don't override umask for the individual ones -- should we? */
		if (chdir(wdname)) {}
		child_workdir = strdup(wdname);
    }
#endif
}

void Rserve_cleanup() {
	/* run .Rserve.done() if present */
	SEXP fun, fsym = install(".Rserve.done");
	fun = findVarInFrame(R_GlobalEnv, fsym);
	if (Rf_isFunction(fun)) {
		int Rerror = 0;
#ifdef unix
		if (child_workdir &&
			chdir(child_workdir)) {} /* guarantee that we are running in the workign directory */
#endif
		R_tryEval(lang1(fsym), R_GlobalEnv, &Rerror);
	}
#ifdef unix
	if (child_workdir) {
		if (workdir &&
			chdir(workdir)) {} /* change to the level up */
		if (wipe_workdir)
			rm_rf(child_workdir);
		else
			rmdir(wdname);
	}
#endif

	/* this is probably superfluous ... just make sure no one
	   tries to use parent_io after Rserve_cleanup() */
	if (parent_io) {
		rsio_free(parent_io);
		parent_io = 0;
	}
}

/*---- this is an attempt to factor out the OCAP mode into a minimal
       set of code that is not shared with other protocols to make
	   it more safe and re-entrant.
  ----*/
       

struct qap_runtime {
	struct args *args;  /* input args */
    char  *buf;         /* send/recv buffer */
    rlen_t buf_size;    /* size of the buffer */
	int level;          /* re-entrance level */
};

static qap_runtime_t *current_runtime;

qap_runtime_t *get_qap_runtime() {
	return current_runtime;
}

/* NOTE: the runtime becomes the owner of args! */
static qap_runtime_t *new_qap_runtime(struct args *args) {
	qap_runtime_t *n = (qap_runtime_t*) malloc(sizeof(qap_runtime_t));
	if (!n) return n;
	n->args = args;
	n->level = 0;
	n->buf_size = 8*1024*1024;
	n->buf = (char*) malloc(n->buf_size);
	if (!n->buf) {
		free(n);
		return 0;
	}
	return n;
}

static void free_qap_runtime(qap_runtime_t *rt) {
	if (rt) {
		if (rt->buf) {
			free(rt->buf);
			rt->buf = 0;
		}
		if (rt->args) {
			free(rt->args);
			rt->args = 0;
		}
		if (rt == current_runtime)
			current_runtime = 0;
		free(rt);
	}
}

#ifdef R_INTERFACE_PTRS
/* -- callbacks -- */
static void RS_Busy(int which) {
}

static void RS_ResetConsole() {
}

static void RS_FlushConsole() {
}

static void RS_ClearerrConsole() {
}

static void RS_WriteConsoleEx(const char *buf, int len, int oType) {
	SEXP s = PROTECT(allocVector(VECSXP, 2));
	SET_VECTOR_ELT(s, 0, mkString(oType ? "console.err" : "console.out"));
	SET_VECTOR_ELT(s, 1, ScalarString(Rf_mkCharLenCE(buf, len, CE_UTF8)));
	UNPROTECT(1);
	send_oob_sexp(OOB_SEND, s);
}

static void RS_ShowMessage(const char *buf) {
	SEXP s = PROTECT(allocVector(VECSXP, 2));
	SET_VECTOR_ELT(s, 0, mkString("console.msg"));
	SET_VECTOR_ELT(s, 1, ScalarString(Rf_mkCharCE(buf, CE_UTF8)));
	UNPROTECT(1);
	send_oob_sexp(OOB_SEND, s);
}
#endif

void Rserve_OCAP_connected(void *thp) {
    struct args *args = (struct args*)thp;
	server_t *srv = args->srv;
	int fres = Rserve_prepare_child(args);
	qap_runtime_t *rt;

	if (fres != 0) { /* not a child (error or parent) */
		free(args);
		return;
	}

	/* this should never happen, but just in case ... */
	if (!(args->srv->flags & SRV_QAP_OC)) {
		RSEprintf("FATAL: OCAP is disabled yet we are in OCAPconnected");
		free(args);
		return;
	}

	setup_workdir();

	/* setup TLS if desired */
	if ((args->srv->flags & SRV_TLS) && shared_tls(0))
		add_tls(args, shared_tls(0), 1);

	{ /* OCinit */
		SOCKET s = args->s;
		rlen_t rs;
		int Rerr = 0;
		SEXP oc;

#ifdef RSERV_DEBUG
		printf("evaluating oc.init()\n");
#endif
		ulog("OCinit");

#ifdef R_INTERFACE_PTRS
		if (oob_console) {
			ptr_R_ShowMessage = RS_ShowMessage;
			/* ptr_R_ReadConsole = RS_ReadConsole; */
			ptr_R_WriteConsole = NULL;
			ptr_R_WriteConsoleEx = RS_WriteConsoleEx;
			ptr_R_ResetConsole = RS_ResetConsole;
			ptr_R_FlushConsole = RS_FlushConsole;
			ptr_R_ClearerrConsole = RS_ClearerrConsole;
			ptr_R_Busy = RS_Busy;
			R_Outputfile = NULL;
			R_Consolefile = NULL;
		}
#endif
		
		oc = R_tryEval(PROTECT(LCONS(install("oc.init"), R_NilValue)), R_GlobalEnv, &Rerr);
		UNPROTECT(1);
		ulog("OCinit-result: %s", Rerr ? "FAILED" : "OK");
		if (Rerr) { /* cannot get any capabilities, bail out */
#ifdef RSERV_DEBUG
			printf("ERROR: failed to eval oc.init() - aborting!");
#endif
			closesocket(s);
			free(args);
			return;			
		}

		current_runtime = rt = new_qap_runtime(args);
		if (!rt) {
			ulog("OCAP-ERROR: cannot allocate QAP runtime");
			closesocket(s);
			free(args);
			return;
		}

		args->flags |= F_OUT_BIN; /* in OC everything is binary */
		PROTECT(oc);
		rs = QAP_getStorageSize(oc);
#ifdef RSERV_DEBUG
		printf("oc.init storage size = %ld bytes\n",(long)rs);
#endif
		if (rs > rt->buf_size - 64L) {  /* is the send buffer too small ? */
			unsigned int osz = (rs > 0xffffffff) ? 0xffffffff : rs;
			osz = itop(osz);
#ifdef RSERV_DEBUG
			printf("ERROR: object too big (%ld available, %ld required)\n", (long) rt->buf_size, (long) rs);
#endif
			/* FIXME: */
			sendRespData(args, SET_STAT(RESP_ERR, ERR_object_too_big), 4, &osz);
			free_qap_runtime(rt);
			closesocket(s);
			UNPROTECT(1);
			return;
	    } else {
			char *sxh = rt->buf + 8, *sendhead = 0;
			char *tail = (char*)QAP_storeSEXP((unsigned int*)sxh, oc, rs);
			
			UNPROTECT(1);
			/* set type to DT_SEXP and correct length */
			if ((tail - sxh) > 0xfffff0) { /* we must use the "long" format */
				rlen_t ll = tail - sxh;
				((unsigned int*)rt->buf)[0] = itop(SET_PAR(DT_SEXP | DT_LARGE, ll & 0xffffff));
				((unsigned int*)rt->buf)[1] = itop(ll >> 24);
				sendhead = rt->buf;
			} else {
				sendhead = rt->buf + 4;
				((unsigned int*)rt->buf)[1] = itop(SET_PAR(DT_SEXP,tail - sxh));
			}
#ifdef RSERV_DEBUG
			printf("stored SEXP; length=%ld (incl. DT_SEXP header)\n",(long) (tail - sendhead));
#endif
			sendRespData(args, CMD_OCinit, tail - sendhead, sendhead);
		}
	}

	/* everything is binary from now on */
	args->flags |= F_OUT_BIN;
	
#if 0 /* do we care? */
	can_control = 0;
	if (!authReq && !pwdfile) /* control is allowed by default only if authentication is not required and passwd is not present. In all other cases it will be set during authentication. */
		can_control = 1;
#endif

	while (OCAP_iteration(rt, 0)) {}
	
	Rserve_cleanup();
	free_qap_runtime(rt);
}

/* 1 = iteration successful - OCAP called
   2 = iteration successful - OOB pending (only signalled if oob_hdr is non-null)
   0 = iteration failed - assume conenction has been closed */
int OCAP_iteration(qap_runtime_t *rt, struct phdr *oob_hdr) {
	struct args *args;
    struct phdr ph;
	server_t *srv;
	SOCKET s;
	int rn, msg_id;

	if (!rt) rt = current_runtime;
	if (!rt || !rt->args) return 0;

	args = rt->args;
	srv = args->srv;
	s = args->s;
	
    while((rn = srv->recv(args, (char*)&ph, sizeof(ph))) == sizeof(ph)) {
		size_t plen = 0;
		unsigned int len32, hi32;
		int cmd;
#ifdef RSERV_DEBUG
		printf("\nOCAP iter header read result: %d\n", rn);
		if (rn > 0) printDump(&ph, rn);
#endif
		/* NOTE: do not touch ph since we may need to pass it unharmed to oob */
		len32 = (unsigned int) ptoi(ph.len);
		cmd = ptoi(ph.cmd);
		plen = len32;
#ifdef __LP64__
		hi32 = (unsigned int) ptoi(ph.res);
		plen |= (((size_t) hi32) << 32);
#endif

#ifdef RSERV_DEBUG
		if (io_log) {
			struct timeval tv;
			snprintf(io_log_fn, sizeof(io_log_fn), "/tmp/Rserve-io-%d.log", getpid());
			FILE *f = fopen(io_log_fn, "a");
			if (f) {
				double ts = 0;
				if (!gettimeofday(&tv, 0))
					ts = ((double) tv.tv_sec) + ((double) tv.tv_usec) / 1000000.0;
				if (first_ts < 1.0) first_ts = ts;
				fprintf(f, "%.3f [+%4.3f]  SRV <-- CLI  [OCAP iter]  (%x, %ld bytes)\n   HEAD ", ts, ts - first_ts, cmd, (long) plen);
				fprintDump(f, &ph, sizeof(ph));
				fclose(f);
			}
		}
#endif

		if (oob_hdr && (cmd & CMD_OOB)) { /* we're nested in OOB and OOB has arrived - copy header and get out */
			memcpy(oob_hdr, &ph, sizeof(ph));
			ulog("OCiteration passing to OOB");
			return 2;
		}

		msg_id = args->msg_id = ph.msg_id;

		/* in OC mode everything but OCcall is invalid */
		if (cmd != CMD_OCcall) {
			ulog("VIOLATION: OCAP iteration - only OCcall is allowed but got 0x%x, aborting", cmd);
			sendResp(args, SET_STAT(RESP_ERR, ERR_disabled));
			closesocket(s);
			args->s = -1;
			return 0;
		}

		{
			if (!maxInBuf || plen < maxInBuf) {
				rlen_t i;
				if (plen >= rt->buf_size) {
#ifdef RSERV_DEBUG
					printf("resizing input buffer (was %ld, need %ld) to %ld\n", (long)rt->buf_size, (long) plen, (long)(((plen | 0x1fffL) + 1L)));
#endif
					free(rt->buf); /* the buffer is just a scratchpad, so we don't need to use realloc */
					rt->buf = (char*) malloc(rt->buf_size = ((plen | 0x1fffL) + 1L)); /* use 8kB granularity */
					if (!rt->buf) {
#ifdef RSERV_DEBUG
						fprintf(stderr,"FATAL: out of memory while resizing buffer to %ld,\n", (long)rt->buf_size);
#endif
						ulog("ERROR: out of memory while resizing resizing buffer to %ld,\n", (long)rt->buf_size);
						sendResp(args, SET_STAT(RESP_ERR,ERR_out_of_mem));
						closesocket(s);
						args->s = -1;
						return 0;
					}
				}
#ifdef RSERV_DEBUG
				printf("loading buffer (awaiting %ld bytes)\n",(long) plen);
#endif
				i = 0;
				while ((rn = srv->recv(args, ((char*)rt->buf) + i, (plen - i > max_sio_chunk) ? max_sio_chunk : (plen - i)))) {
					if (rn > 0) i += rn;
					if (i >= plen || rn < 1) break;
				}

#ifdef RSERV_DEBUG
				if (io_log) {
					FILE *f = fopen(io_log_fn, "a");
					if (f) {
						fprintf(f, "   BODY ");
						if (i) fprintDump(f, rt->buf, i); else fprintf(f, "<none>\n");
						fclose(f);
					}
				}
#endif

				if (i < plen) {
					ulog("ERROR: incomplete OCAP message - closing connection");
					sendResp(args, SET_STAT(RESP_ERR, ERR_conn_broken));
					closesocket(s);
					args->s = -1;
					return 0;
				}
				memset(rt->buf + plen, 0, 8);
			} else {
#ifdef RSERV_DEBUG
				fprintf(stderr,"ERROR: input is larger than input buffer limit\n");
#endif
				ulog("ERROR: input packet is larger than input buffer limit");
				sendResp(args, SET_STAT(RESP_ERR, ERR_data_overflow));
				closesocket(s);
				args->s = -1;
				return 0;
			}
		}

		{
			int valid = 0, Rerror = 0;
			SEXP val = R_NilValue, eval_result = 0, exp = R_NilValue;
			unsigned int *ibuf = (unsigned int*) rt->buf;
			/* FIXME: this is a bit hacky since we skipped parameter parsing */
			int par_t = ibuf[0] & 0xff;
			const char *c_ocname = 0;
			if (par_t == DT_SEXP || par_t == (DT_SEXP | DT_LARGE)) {
				unsigned int *sptr;
				sptr = ibuf + ((par_t & DT_LARGE) ? 2 : 1);
				/* FIXME: we're not checking the size?!? */
				val = QAP_decode(&sptr);
				if (val && TYPEOF(val) == LANGSXP) {
					SEXP ocref = CAR(val);
					if (TYPEOF(ocref) == STRSXP && LENGTH(ocref) == 1) {
						SEXP ocv = oc_resolve(CHAR(STRING_ELT(ocref, 0)));
						if (ocv && ocv != R_NilValue && CAR(ocv) != R_NilValue) {
							/* valid reference -- replace it in the call */
							SEXP occall = CAR(ocv), ocname = TAG(ocv);
							SETCAR(val, occall);
							if (ocname != R_NilValue) c_ocname = CHAR(PRINTNAME(ocname));
							ulog("OCcall '%s': ", (ocname == R_NilValue) ? "<null>" : c_ocname);
							valid = 1;
						}
					}
				}
			}
			/* invalid calls lead to immediate termination with no message */
			if (!valid) {
				ulog("ERROR OCcall: invalid reference");
				closesocket(s);
				args->s = -1;
				return 0;
			}
			PROTECT(val);
#ifdef RSERV_DEBUG
			printf("  running eval on SEXP (after OC replacement): ");
			printSEXP(val);
#endif
			eval_result = R_tryEval(val, R_GlobalEnv, &Rerror);
			args->msg_id = msg_id; /* restore msg_id - oob in eval would clober it */
			UNPROTECT(1);
			ulog("OCresult '%s'", c_ocname ? c_ocname : "<null>");

			if (eval_result) exp = PROTECT(eval_result);
#ifdef RSERV_DEBUG
			printf("expression(s) evaluated (Rerror=%d).\n",Rerror);
			if (!Rerror) printSEXP(exp);
#endif
			if (Rerror) {
				sendResp(args, SET_STAT(RESP_ERR, (Rerror < 0) ? Rerror : -Rerror));
				return 1;
			} else {
				char *sendhead = 0;
				rlen_t tempSB = 0;
				/* check buffer size vs REXP size to avoid dangerous overflows
				   todo: resize the buffer as necessary
				*/
				rlen_t rs = QAP_getStorageSize(exp);
				/* FIXME: add a 4k security margin - it should no longer be needed,
				   originally the space was grown proportionally to account for a bug,
				   but that bug has been fixed. */
				rs += 4096;
#ifdef RSERV_DEBUG
				printf("result storage size = %ld bytes (buffer %ld bytes)\n",(long)rs, (long)rt->buf_size);
#endif
				if (rs > rt->buf_size - 64L) { /* is the send buffer too small ? */
					if (maxSendBufSize && rs + 64L > maxSendBufSize) { /* first check if we're allowed to resize */
						unsigned int osz = (rs > 0xffffffff) ? 0xffffffff : rs;
						osz = itop(osz);
#ifdef RSERV_DEBUG
						printf("ERROR: object too big (buffer=%ld)\n", rt->buf_size);
#endif
						ulog("WARNING: object too big to send");
						sendRespData(args, SET_STAT(RESP_ERR, ERR_object_too_big), 4, &osz);
						return 1;
					} else { /* try to allocate a large, temporary send buffer */
						tempSB = rs + 64L;
						tempSB &= rlen_max << 12;
						tempSB += 0x1000;
#ifdef RSERV_DEBUG
						printf("Trying to allocate temporary send buffer of %ld bytes.\n", (long)tempSB);
#endif
						free(rt->buf);
						rt->buf = (char*)malloc(tempSB);
						if (!rt->buf) {
#ifdef RSERV_DEBUG
							printf("Failed to allocate temporary send buffer of %ld bytes. Restoring old send buffer of %ld bytes.\n", (long)tempSB, (long)rt->buf_size);
#endif
							rt->buf = (char*)malloc(rt->buf_size);
							if (!rt->buf) { /* we couldn't re-allocate the buffer */
#ifdef RSERV_DEBUG
								fprintf(stderr,"FATAL: out of memory while re-allocating send buffer to %ld (fallback#1)\n", (long) rt->buf_size);
#endif
								sendResp(args, SET_STAT(RESP_ERR, ERR_out_of_mem));
								closesocket(s);
								args->s = -1;
								return 0;
							} else {
								unsigned int osz = (rs > 0xffffffff) ? 0xffffffff : rs;
								osz = itop(osz);
#ifdef RSERV_DEBUG
								printf("ERROR: object too big (sendBuf=%ld) and couldn't allocate big enough send buffer\n", (long) rt->buf_size);
#endif
								sendRespData(args, SET_STAT(RESP_ERR, ERR_object_too_big), 4, &osz);
								return 1;
							}
						}
					}
				}
				{
					/* first we have 4 bytes of a header saying this is an encoded SEXP, then comes the SEXP */
					char *sxh = rt->buf + 8;
					char *tail = (char*)QAP_storeSEXP((unsigned int*)sxh, exp, rs);
					
					/* set type to DT_SEXP and correct length */
					if ((tail - sxh) > 0xfffff0) { /* we must use the "long" format */
						rlen_t ll = tail - sxh;
						((unsigned int*)rt->buf)[0] = itop(SET_PAR(DT_SEXP | DT_LARGE, ll & 0xffffff));
						((unsigned int*)rt->buf)[1] = itop(ll >> 24);
						sendhead = rt->buf;
					} else {
						sendhead = rt->buf + 4;
						((unsigned int*)rt->buf)[1] = itop(SET_PAR(DT_SEXP,tail - sxh));
					}
#ifdef RSERV_DEBUG
					printf("stored SEXP; length=%ld (incl. DT_SEXP header)\n",(long) (tail - sendhead));
#endif
					sendRespData(args, RESP_OK, tail - sendhead, sendhead);
					if (tempSB) { /* if this is just a temporary sendbuffer then shrink it back to normal */
#ifdef RSERV_DEBUG
						printf("Releasing temporary sendbuf and restoring old size of %ld bytes.\n", (long) rt->buf_size);
#endif
						free(rt->buf);
						rt->buf = (char*)malloc(rt->buf_size);
						if (!rt->buf) { /* this should be really rare since tempSB was much larger */
#ifdef RSERV_DEBUG
							fprintf(stderr,"FATAL: out of memory while re-allocating send buffer to %ld (fallback#2),\n", (long) rt->buf_size);
#endif
							sendResp(args, SET_STAT(RESP_ERR, ERR_out_of_mem));
							ulog("ERROR: out of memory while shrinking send buffer");
							closesocket(s);
							args->s = -1;
							return 0;
						}
					}
				}
				if (eval_result) UNPROTECT(1); /* exp / eval_result */
			}
#ifdef RSERV_DEBUG
			printf("reply sent.\n");
			return 1;
#endif
		}
	}
	closesocket(s);
	args->s = -1;
	return 0;
}

/* working thread/function. the parameter is of the type struct args* */
/* This server function implements the Rserve QAP1 protocol */
void Rserve_QAP1_connected(void *thp) {
    SOCKET s;
    struct args *a = (struct args*)thp;
    struct phdr ph;
	server_t *srv = a->srv;
    char *buf, *c, *cc, *c1;
    int pars;
    int process;
	int rn;
    ParseStatus stat;
    char *sendbuf;
    rlen_t sendBufSize;
    char *tail;
    char *sfbuf;
    int Rerror;
    int authed=0;
    int unaligned=0;
#ifdef HAS_CRYPT
    char salt[5];
#endif
    rlen_t tempSB=0;
    
    int parT[16];
    rlen_t parL[16];
    void *parP[16];
    
    SEXP xp,exp;
    FILE *cf=0;

	int pc_res;

	/* OCAP has moved out to its own path
	   for security reasons (this compatibility
	   re-direct should go away after testing) */
	if (a->srv->flags & SRV_QAP_OC) {
		Rserve_OCAP_connected(a);
		return;
	}

	pc_res = Rserve_prepare_child(a);
	if (pc_res != 0) { /* either failed or parent */
		free(a);
		return;
	}

	/* FIXME: re-factor to use qap_runtime jsut like OCAP does */
    buf = (char*) malloc(inBuf + 8);
    sfbuf = (char*) malloc(sfbufSize);
    if (!buf || !sfbuf) {
		RSEprintf("FATAL: cannot allocate initial buffers. closing client connection.\n");
		s = a->s;
		free(a);
		closesocket(s);
		return;
    }
    memset(buf, 0, inBuf + 8);

	setup_workdir();

    sendBufSize = sndBS;
    sendbuf = (char*) malloc(sendBufSize);
#ifdef RSERV_DEBUG
    printf("connection accepted.\n");
#endif
    s = a->s;
	/* FIXME: we used to free a here, but now that we use it we have to defer that ... */
    
    csock = s;
    
	if ((a->srv->flags & SRV_TLS) && shared_tls(0))
		add_tls(a, shared_tls(0), 1);

	{
		strcpy(buf,IDstring);
		if (authReq) {
#ifdef HAS_CRYPT
			/* advertize crypt */
			memcpy(buf+16,"ARuc",4);
			salt[0]='K';
			salt[1]=code64[rand()&63];
			salt[2]=code64[rand()&63];
			salt[3]=' '; salt[4]=0;
			memcpy(buf+20,salt,4);
			/* append plaintext if enabled */
			if (usePlain) memcpy(buf + 24,"ARpt",4);
#else
			/* if crypt is not an option, we may need to advertize plain text if enabled */
			if (usePlain) memcpy(buf + 16, "ARpt", 4);
#endif
		}
#ifdef HAVE_TLS
		if (switch_qap_tls) {
			char *ep = buf + 16;
			while (*ep != '-') ep += 4;
			memcpy(ep, "TLS\n", 4);
		}
#endif
#ifdef RSERV_DEBUG
		printf("sending ID string.\n");
#endif
		srv->send(a, (char*)buf, 32);
	}

	/* everything is binary from now on */
	a->flags |= F_OUT_BIN;
	
	can_control = 0;
	if (!authReq && !pwdfile) /* control is allowed by default only if authentication is not required and passwd is not present. In all other cases it will be set during authentication. */
		can_control = 1;

    while((rn = srv->recv(a, (char*)&ph, sizeof(ph))) == sizeof(ph)) {
		SEXP eval_result = 0;
		size_t plen = 0;
		SEXP pp = R_NilValue; /* packet payload (as a raw vector) for special commands */
		int msg_id;
		Rerror = 0;
#ifdef RSERV_DEBUG
		printf("\nheader read result: %d\n", rn);
		if (rn > 0) printDump(&ph, rn);
#endif
		ph.len = ptoi(ph.len);
		ph.cmd = ptoi(ph.cmd);
#ifdef __LP64__
		ph.res = ptoi(ph.res);
		plen = (unsigned int) ph.len;
		plen |= (((size_t) (unsigned int) ph.res) << 32);
#else
		plen = ph.len;
#endif
		msg_id = a->msg_id = use_msg_id ? ph.msg_id : 0;
		process = 0;
		pars = 0;

#ifdef RSERV_DEBUG
		if (io_log) {
			struct timeval tv;
			snprintf(io_log_fn, sizeof(io_log_fn), "/tmp/Rserve-io-%d.log", getpid());
			FILE *f = fopen(io_log_fn, "a");
			if (f) {
				double ts = 0;
				if (!gettimeofday(&tv, 0))
					ts = ((double) tv.tv_sec) + ((double) tv.tv_usec) / 1000000.0;
				if (first_ts < 1.0) first_ts = ts;
				fprintf(f, "%.3f [+%4.3f]  SRV <-- CLI  [QAP loop]  (%x, %ld bytes)\n   HEAD ", ts, ts - first_ts, ph.cmd, (long) plen);
				fprintDump(f, &ph, sizeof(ph));
				fclose(f);
			}
		}
#endif

			/* in OC mode everything but OCcall is invalid */
		if ((a->srv->flags & SRV_QAP_OC) && ph.cmd != CMD_OCcall) {
			sendResp(a, SET_STAT(RESP_ERR, ERR_disabled));
			free(sendbuf); free(sfbuf);
			closesocket(s);
			return;
		}

		if ((ph.cmd & CMD_SPECIAL_MASK) == CMD_SPECIAL_MASK) {
			/* this is a very special case - we load the packet payload into a raw vector directly to prevent unnecessaru copying */
			pp = allocVector(RAWSXP, plen);
			char *pbuf = (char*) RAW(pp);
			size_t i = 0;
#ifdef RSERV_DEBUG
			printf("loading (raw) buffer (awaiting %d bytes)\n", (int)plen);
#endif
			while((rn = srv->recv(a, pbuf + i, (plen - i > max_sio_chunk) ? max_sio_chunk : (plen - i)))) {
				if (rn > 0) i += rn;
				if (i >= plen || rn < 1) break;
			}
		} else if (plen > 0) {
			unsigned int phead;
			int parType = 0;
			rlen_t parLen = 0;
	    
			if (!maxInBuf || plen < maxInBuf) {
				rlen_t i;
				if (plen >= inBuf) {
#ifdef RSERV_DEBUG
					printf("resizing input buffer (was %ld, need %ld) to %ld\n", (long)inBuf, (long) plen, (long)(((plen | 0x1fffL) + 1L)));
#endif
					free(buf); /* the buffer is just a scratchpad, so we don't need to use realloc */
					buf = (char*) malloc(inBuf = ((plen | 0x1fffL) + 1L)); /* use 8kB granularity */
					if (!buf) {
#ifdef RSERV_DEBUG
						fprintf(stderr,"FATAL: out of memory while resizing buffer to %d,\n", (int)inBuf);
#endif
						sendResp(a, SET_STAT(RESP_ERR,ERR_out_of_mem));
						free(sendbuf); free(sfbuf);
						closesocket(s);
						return;
					}	    
				}
#ifdef RSERV_DEBUG
				printf("loading buffer (awaiting %ld bytes)\n",(long) plen);
#endif
				i = 0;
				while ((rn = srv->recv(a, ((char*)buf) + i, (plen - i > max_sio_chunk) ? max_sio_chunk : (plen - i)))) {
					if (rn > 0) i += rn;
					if (i >= plen || rn < 1) break;
				}

#ifdef RSERV_DEBUG
				if (io_log) {
					FILE *f = fopen(io_log_fn, "a");
					if (f) {
						fprintf(f, "   BODY ");
						if (i) fprintDump(f, buf, i); else fprintf(f, "<none>\n");
						fclose(f);
					}
				}
#endif

				if (i < plen) break;
				memset(buf + plen, 0, 8);
		
				unaligned = 0;
#ifdef RSERV_DEBUG
				printf("parsing parameters (buf=%p, len=%ld)\n", buf, (long) plen);
				if (plen > 0) printDump(buf,plen);
#endif
				c = buf;
				while((c < buf + plen) && (phead = ptoi(*((unsigned int*)c)))) {
					rlen_t headSize = 4;
					parType = PAR_TYPE(phead);
					parLen = PAR_LEN(phead);
					if ((parType & DT_LARGE) > 0) { /* large parameter */
						headSize += 4;
						parLen |= ((rlen_t)((unsigned int)ptoi(*(unsigned int*)(c + 4)))) << 24;
						parType ^= DT_LARGE;
					} 
#ifdef RSERV_DEBUG
					printf("PAR[%d]: %08lx (PAR_LEN=%ld, PAR_TYPE=%d, large=%s, c=%p, ptr=%p)\n", pars, i,
						   (long)parLen, parType, (headSize==8)?"yes":"no", c, c + headSize);
#endif
#ifdef ALIGN_DOUBLES
					if (unaligned) { /* on Sun machines it is deadly to process unaligned parameters,
										therefore we respond with ERR_inv_par */
#ifdef RSERV_DEBUG
						printf("Platform specific: last parameter resulted in unaligned stream for the current one, sending ERR_inv_par.\n");
#endif
						sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
						process = 1; ph.cmd = 0;
						break;
					}
#endif
					if (parLen & 3) unaligned=1;         
					parT[pars] = parType;
					parL[pars] = parLen;
					parP[pars] = c + headSize;
					pars++;
					c += parLen + headSize; /* par length plus par head */
					if (pars > 15) break;
				} /* we don't parse more than 16 parameters */
			} else {
				RSEprintf("WARNING: discarding buffer because too big (awaiting %ld bytes)\n", (long)plen);
				size_t i = plen, chk = (inBuf < max_sio_chunk) ? inBuf : max_sio_chunk;
				while((rn = srv->recv(a, (char*)buf, (i < chk) ? i : chk))) {
					if (rn > 0) i -= rn;
					if (i < 1 || rn < 1) break;
				}
				if (i > 0) break;
				/* if the pars are bigger than my buffer, send data_overflow response
				   (since 1.23/0.1-6; was inv_par before) */
				sendResp(a, SET_STAT(RESP_ERR, ERR_data_overflow));
				process = 1; ph.cmd = 0;
			}
		}

		/** IMPORTANT! The pointers in par[..] point to RAW data, i.e. you have
			to use ptoi(..) in order to get the real integer value. */
	
		/** NOTE: Rserve doesn't check for alignment of parameters. This is ok
			for most platforms, but on Sun hardware this means that an user
			can send a package that will cause segfault in the client thread
			by sending unaligned parameters. This won't affect the server, only
			the connection child process dies.
			Since 0.1-10 we report ERR_inv_par on Sun for non-aligned parameters.
		*/
	
#ifdef RSERV_DEBUG
		printf("CMD=%08x, pars=%d\n", ph.cmd, pars);
#endif

		/* FIXME: now that OCAP has a separate server path,
		   should we really support OCcall outside of OCAP mode?
		   This piece is only run if OCAP mode is disabled */
		if (ph.cmd == CMD_OCcall) {
			int valid = 0;
			SEXP val = R_NilValue;
			if (pars >= 1 && (parT[0] == DT_SEXP || parT[0] == (DT_SEXP | DT_LARGE))) {
				int boffs = 0;
				unsigned int *sptr;
				if (parT[0] & DT_LARGE) boffs++;
				sptr = ((unsigned int*)parP[0]) + boffs;
				val = QAP_decode(&sptr);
				if (val && TYPEOF(val) == LANGSXP) {
					SEXP ocref = CAR(val);
					if (TYPEOF(ocref) == STRSXP && LENGTH(ocref) == 1) {
						SEXP ocv = oc_resolve(CHAR(STRING_ELT(ocref, 0)));
						if (ocv && ocv != R_NilValue && CAR(ocv) != R_NilValue) {
							/* valid reference -- replace it in the call */
							SEXP occall = CAR(ocv), ocname = TAG(ocv);
							SETCAR(val, occall);
							ulog("OCcall '%s': ", (ocname == R_NilValue) ? "<null>" : CHAR(PRINTNAME(ocname)));
							valid = 1;
						}
					}
				}
			}
			/* invalid calls lead to immediate termination with no message */
			if (!valid) {
				ulog("ERROR OCcall: invalid reference");
				free(sendbuf); free(sfbuf);
				closesocket(s);				
				return;
			}
			PROTECT(val);
#ifdef RSERV_DEBUG
			printf("  running eval on SEXP (after OC replacement): ");
			printSEXP(val);
#endif
			eval_result = R_tryEval(val, R_GlobalEnv, &Rerror);
			UNPROTECT(1);
			ulog("OCresult");
			process = 1;
		}

		if (ph.cmd == CMD_switch) {
			if (pars < 1 || parT[0] != DT_STRING) 
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				c = (char*) parP[0];
				if (!strcmp(c, "TLS")) {
					if (switch_qap_tls && shared_tls(0)) {
						sendResp(a, RESP_OK);
						add_tls(a, shared_tls(0), 1);
					} else
						sendResp(a, SET_STAT(RESP_ERR, ERR_disabled));
				} else
					sendResp(a, SET_STAT(RESP_ERR, ERR_unsupportedCmd));
			}
			continue;
		}

		if (ph.cmd == CMD_keyReq) {
			if (pars < 1 || parT[0] != DT_STRING) 
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				c = (char*) parP[0];
#ifdef HAVE_RSA
				/* rsa-authkey - generates authkey and sends server's public RSA key */
				if (strstr(c, "rsa-authkey")) {
					if (++authkey_req < 2) {
						char *pload = 0;
						int pl = rsa_gen_resp(&pload);
						if (pl < 1)
							sendResp(a, SET_STAT(RESP_ERR, ERR_cryptError));
						else
							sendRespData(a, RESP_OK, pl, pload);
						if (pload)
							free(pload);
					} else {
						sendResp(a, SET_STAT(RESP_ERR, ERR_securityClose));
						closesocket(s);
						free(sendbuf); free(sfbuf); free(buf);
						return;
					}
				} else
#endif
					sendResp(a, SET_STAT(RESP_ERR, ERR_unavailable));
			}
			continue;
		}

		if (ph.cmd == CMD_secLogin) {
#ifdef HAVE_RSA
			if (pars < 1 || parT[0] != DT_BYTESTREAM || parL[0] >= sizeof(rsa_buf))
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				int dl = 0;
				if (!rsa_srv_key || (dl = rsa_decode(rsa_buf, (char*) parP[0], parL[0])) < 1) {
#ifdef RSERV_DEBUG
					printf("CMD_secLogin: decode failed - rsa_srv_key=%p, dl = %d (payload %d)\n", (void*)rsa_srv_key, dl, (int) parL[0]);
#endif
					sendResp(a, SET_STAT(RESP_ERR, ERR_auth_failed));
				} else {
					unsigned char *rb = (unsigned char*) rsa_buf;
					if (rb[0] != (SRV_KEY_LEN & 0xff) || rb[1] != ((SRV_KEY_LEN >> 8) & 0xff) || rb[2] || rb[3] || memcmp(rb + 4, authkey, SRV_KEY_LEN)) {
#ifdef RSERV_DEBUG
						printf("CMD_secLogin: authkey mismatch\n");
#endif
						sendResp(a, SET_STAT(RESP_ERR, ERR_auth_failed));
					} else {
						unsigned int asl = rb[SRV_KEY_LEN + 5];
						asl <<= 8;
						asl |= rb[SRV_KEY_LEN + 4];
#ifdef RSERV_DEBUG
						printf("CMD_secLogin: authkey matches, asl payload: %d\n", asl);
#endif
						if (asl + SRV_KEY_LEN + 8 > dl)
							sendResp(a, SET_STAT(RESP_ERR, ERR_auth_failed));
						else {
							char *ac, *au = 0, *ap = 0;
							int i;
							au = ac = ((char*) rb) + SRV_KEY_LEN + 8;
							for (i = 0; i < asl; i++)
								if (ac[i] == '\n') {
									ac[i] = 0;
									if (!ap) ap = ac + i + 1;
								}
							if (ac[asl - 1])
								ac[asl] = 0;
							authed = auth_user(au, ap ? ap : "", sec_salt);
							a->msg_id = msg_id; /* just in case R-side auth used OOB (it shouldn't) */
							if (authed) {
								process = 1;
								sendResp(a, RESP_OK);
							}
						}
					}
				}
			}
#else
			sendResp(a, SET_STAT(RESP_ERR, ERR_unavailable));
			continue;
#endif
		}

		if (!authed && ph.cmd==CMD_login) {
			if (pars < 1 || parT[0] != DT_STRING) 
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
#ifdef HAS_CRYPT
				const char *my_salt = salt + 1;
#else
				const char *my_salt = 0;
#endif
				c = (char*)parP[0];
				cc = c;
				while(*cc && *cc != '\n') cc++;
				if (*cc) { *cc = 0; cc++; };
				c1 = cc;
				while(*c1) if(*c1 == '\n' || *c1 == '\r') *c1=0; else c1++;
				/* c=login, cc=pwd */
				authed = auth_user(c, cc, my_salt);
				a->msg_id = msg_id; /* just in case R-side auth used OOB (it shouldn't) */
				if (authed) {
					process = 1;
					sendResp(a, RESP_OK);
				}
			}
		}

		/* if not authed by now, close connection */
		if (authReq && !authed) {
			sendResp(a, SET_STAT(RESP_ERR, ERR_auth_failed));
			closesocket(s);
			free(sendbuf); free(sfbuf); free(buf);
			return;
		}

		if (ph.cmd==CMD_shutdown) { /* FIXME: now that we have control commands we may rethink this ... */
			if (disable_shutdown) { 
				sendResp(a, SET_STAT(RESP_ERR, ERR_disabled));
				continue;
			}

			sendResp(a, RESP_OK);
#ifdef RSERV_DEBUG
			printf("initiating clean shutdown.\n");
#endif
			active = 0;
			closesocket(s);
			free(sendbuf); free(sfbuf); free(buf);
#ifdef FORKED
			if (parentPID > 0)
				kill(parentPID, SIGTERM);
			exit(0);
#endif
			return;
		}

		if (ph.cmd == CMD_ctrlEval || ph.cmd == CMD_ctrlSource || ph.cmd == CMD_ctrlShutdown) {
			process = 1;
#ifdef RSERV_DEBUG
			printf("control command: %s [can control: %s, pipe: %p]\n", (ph.cmd == CMD_ctrlEval) ? "eval" : ((ph.cmd == CMD_ctrlSource) ? "source" : "shutdown"), can_control ? "yes" : "no", parent_io);
#endif
			if (!can_control) /* no right to do this */
				sendResp(a, SET_STAT(RESP_ERR, ERR_accessDenied));
			else {
				/* source and eval require a parameter */
				if ((ph.cmd == CMD_ctrlEval || ph.cmd == CMD_ctrlSource) && (pars < 1 || parT[0] != DT_STRING))
					sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
				else {
					if (!parent_io)
						sendResp(a, SET_STAT(RESP_ERR, ERR_ctrl_closed));
					else {
						long cmd[2] = { 0, 0 };
						if (ph.cmd == CMD_ctrlEval) { cmd[0] = CCTL_EVAL; cmd[1] = strlen(parP[0]) + 1; }
						else if (ph.cmd == CMD_ctrlSource) { cmd[0] = CCTL_SOURCE; cmd[1] = strlen(parP[0]) + 1; }
						else cmd[0] = CCTL_SHUTDOWN;
						if (rsio_write(parent_io, parP[0], cmd[1], cmd[0], -1)) {
#ifdef RSERV_DEBUG
							printf(" - send to parent pipe (cmd=%ld, len=%ld) failed, closing parent pipe\n", cmd[0], cmd[1]);
#endif
							rsio_free(parent_io);
							parent_io = 0;
							sendResp(a, SET_STAT(RESP_ERR, ERR_ctrl_closed));
						} else
							sendResp(a, RESP_OK);
					}
				}
			}
		}

		if (ph.cmd == CMD_setEncoding) { /* set string encoding */
			process = 1;
			if (pars<1 || parT[0] != DT_STRING) 
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				char *c = (char*) parP[0];
#ifdef RSERV_DEBUG
				printf(">>CMD_setEncoding '%s'.\n", c ? c : "<null>");
#endif
#ifdef USE_ENCODING
				if (c && set_string_encoding(c, 0))
					sendResp(a, RESP_OK);
				else
					sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
#else
				sendResp(a, SET_STAT(RESP_ERR, ERR_unsupportedCmd));
#endif
			}
		}

		if (ph.cmd == CMD_setBufferSize) {
			process = 1;
			/* FIXME: configuration allows 64-bit numbers but CMD_setBufferSize does not */
			if (pars < 1 || parT[0] != DT_INT) 
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				rlen_t ns = ptoi(((unsigned int*)(parP[0]))[0]);
#ifdef RSERV_DEBUG
				printf(">>CMD_setSendBuf to %ld bytes.\n", (long)ns);
#endif
				if (ns > 0) { /* 0 means don't touch the buffer size */
					if (ns < 32768) ns = 32768; /* we enforce a minimum of 32kB */
					free(sendbuf);
					sendbuf = (char*)malloc(sendBufSize);
					if (!sendbuf) {
#ifdef RSERV_DEBUG
						fprintf(stderr,"FATAL: out of memory while resizing send buffer to %ld,\n", sendBufSize);
#endif
						sendResp(a, SET_STAT(RESP_ERR, ERR_out_of_mem));
						free(buf); free(sfbuf);
						closesocket(s);
						return;
					}
					sendBufSize = ns;
				}
				sendResp(a, RESP_OK);
			}
		}

		if (ph.cmd==CMD_openFile||ph.cmd==CMD_createFile) {
			process=1;
			if (!allowIO) sendResp(a, SET_STAT(RESP_ERR,ERR_accessDenied));
			else {
				if (pars<1 || parT[0]!=DT_STRING) 
					sendResp(a, SET_STAT(RESP_ERR,ERR_inv_par));
				else {
					c=(char*)(parP[0]);
					if (cf) fclose(cf);
#ifdef RSERV_DEBUG
					printf(">>CMD_open/createFile(%s)\n",c);
#endif
					cf=fopen(c,(ph.cmd==CMD_openFile)?"rb":"wb");
					if (!cf)
						sendResp(a, SET_STAT(RESP_ERR, ERR_IOerror));
					else
						sendResp(a, RESP_OK);
				}
			}
		}
	
		if (ph.cmd==CMD_removeFile) {
			process=1;
			if (!allowIO) sendResp(a, SET_STAT(RESP_ERR, ERR_accessDenied));
			else {
				if (pars<1 || parT[0]!=DT_STRING) 
					sendResp(a, SET_STAT(RESP_ERR,ERR_inv_par));
				else {
					c=(char*)parP[0];
#ifdef RSERV_DEBUG
					printf(">>CMD_removeFile(%s)\n",c);
#endif
					if (remove(c))
						sendResp(a, SET_STAT(RESP_ERR, ERR_IOerror));
					else
						sendResp(a, RESP_OK);
				}
			}
		}
	
		if (ph.cmd == CMD_closeFile) {
			process = 1;
			if (!allowIO)
				sendResp(a, SET_STAT(RESP_ERR, ERR_accessDenied));
			else {
				if (cf) fclose(cf);
#ifdef RSERV_DEBUG
				printf(">>CMD_closeFile\n");
#endif
				cf = 0;
				sendResp(a, RESP_OK);
			}
		}
	
		if (ph.cmd==CMD_readFile) {
			process = 1;
			if (!allowIO) sendResp(a, SET_STAT(RESP_ERR, ERR_accessDenied));
			else {
				if (!cf)
					sendResp(a, SET_STAT(RESP_ERR, ERR_notOpen));
				else {
					rlen_t fbufl = sfbufSize;
					char *fbuf = sfbuf;
					if (pars == 1 && parT[0] == DT_INT)
						fbufl = ptoi(((unsigned int*)(parP[0]))[0]);
#ifdef RSERV_DEBUG
					printf(">>CMD_readFile(%ld)\n", fbufl);
#endif
					if (fbufl < 0) fbufl = sfbufSize;
					if (fbufl > sfbufSize) {
#ifdef RSERV_DEBUG
						printf(" - requested size %ld is larger than default buffer %ld, allocating extra buffer\n",
						       (long) fbufl, (long) sfbufSize);
#endif
						fbuf = (char*)malloc(fbufl);
					}
					if (!fbuf) /* well, logically not clean (it's out of memory), but in practice likely true */
						sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
					else {
						size_t i = fread(fbuf, 1, fbufl, cf);
						if (i > 0)
							sendRespData(a, RESP_OK, i, fbuf);
						else
							sendResp(a, RESP_OK);
						if (fbuf != sfbuf)
							free(fbuf);
					}
				}
			}
		}
	
		if (ph.cmd==CMD_writeFile) {
			process=1;
			if (!allowIO) sendResp(a, SET_STAT(RESP_ERR, ERR_accessDenied));
			else {
				if (!cf)
					sendResp(a, SET_STAT(RESP_ERR, ERR_notOpen));
				else {
					if (pars < 1 || parT[0] != DT_BYTESTREAM)
						sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
					else {
						size_t i = 0;
#ifdef RSERV_DEBUG
						printf(">>CMD_writeFile(%ld,...)\n", (long) parL[0]);
#endif
						c = (char*)parP[0];
						if (parL[0] > 0)
							i = fwrite(c, 1, parL[0], cf);
						if (i > 0 && i != parL[0])
							sendResp(a, SET_STAT(RESP_ERR, ERR_IOerror));
						else
							sendResp(a, RESP_OK);
					}
				}
			}
		}
	
		/*--- CMD_setSEXP / CMD_assignSEXP ---*/
	
		if (ph.cmd==CMD_setSEXP || ph.cmd==CMD_assignSEXP) {
			process=1;
			if (pars < 2 || parT[0] != DT_STRING) 
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				SEXP val, sym=0;
				unsigned int *sptr;
				int parType = parT[1];
				int boffs = 0;
		
				c=(char*)parP[0]; /* name of the symbol */
#ifdef RSERV_DEBUG
				printf(">>CMD_set/assignREXP (%s, REXP)\n",c);
#endif
		
				if (ph.cmd==CMD_assignSEXP) {
					sym = parseExps(c, 1, &stat);
					if (stat != 1) {
#ifdef RSERV_DEBUG
						printf(">>CMD_assignREXP-failed to parse \"%s\", stat=%d\n",c,stat);
#endif
						sendResp(a, SET_STAT(RESP_ERR, stat));
						goto respSt;
					}
					if (TYPEOF(sym)==EXPRSXP && LENGTH(sym)>0) {
						sym = VECTOR_ELT(sym,0);
						/* we should de-allocate the vector here .. if we can .. */
					}
				}
		
				switch (parType) {
				case DT_STRING:
#ifdef RSERV_DEBUG
					printf("  assigning string \"%s\"\n",((char*)(parP[1])));
#endif
					PROTECT(val = allocVector(STRSXP,1));
					SET_STRING_ELT(val, 0, mkRChar((char*)(parP[1])));
					defineVar(sym ? sym : install(c), val ,R_GlobalEnv);
					UNPROTECT(1);
					sendResp(a, RESP_OK);
					break;
				case DT_SEXP|DT_LARGE:
					boffs = 1; /* we're not using the size, so in fact we just
								advance the pointer and don't care about the length */
				case DT_SEXP:
					sptr = ((unsigned int*)parP[1]) + boffs;
					val = QAP_decode(&sptr);
					if (val == 0)
						sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
					else {
						PROTECT(val);
#ifdef RSERV_DEBUG
						printf("  assigning SEXP: ");
						printSEXP(val);
#endif
						defineVar(sym ? sym : install(c), val, R_GlobalEnv);
						UNPROTECT(1);
						sendResp(a, RESP_OK);
					}
					break;
				default:
					sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
				}
			}
		}
	
		if (ph.cmd==CMD_detachSession) {
			process=1;
			if (!detach_session(a)) {
				s = resume_session();
				sendResp(a, RESP_OK);
			}
		}
		
		if (ph.cmd==CMD_serEval || ph.cmd==CMD_serEEval || ph.cmd == CMD_serAssign) {
			int Rerr = 0;
			SEXP us = R_tryEval(LCONS(install("unserialize"),CONS(pp,R_NilValue)), R_GlobalEnv, &Rerr);
			PROTECT(us);
			a->msg_id = msg_id; /* just in case R-side used OOB */
			process = 1;
			if (Rerr == 0) {
				if (ph.cmd == CMD_serAssign) {
					if (TYPEOF(us) != VECSXP || LENGTH(us) < 2) {
						sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
					} else {
						R_tryEval(LCONS(install("<-"),CONS(VECTOR_ELT(us, 0), CONS(VECTOR_ELT(us, 1), R_NilValue))), R_GlobalEnv, &Rerr);
						a->msg_id = msg_id; /* just in case R-side used OOB (unlikely, but ...) */
						if (Rerr == 0)
							sendResp(a, RESP_OK);
						else
							sendResp(a, SET_STAT(RESP_ERR, Rerr));
					}
				} else {
					SEXP ev = R_tryEval(us, R_GlobalEnv, &Rerr);
					a->msg_id = msg_id; /* just in case R-side used OOB */
					if (Rerr == 0 && ph.cmd == CMD_serEEval) /* one more round */
						ev = R_tryEval(ev, R_GlobalEnv, &Rerr);
					PROTECT(ev);
					if (Rerr == 0) {
						SEXP sr = R_tryEval(LCONS(install("serialize"),CONS(ev, CONS(R_NilValue, R_NilValue))), R_GlobalEnv, &Rerr);
						a->msg_id = msg_id; /* just in case R-side used OOB */
						if (Rerr == 0 && TYPEOF(sr) == RAWSXP) {
							sendRespData(a, RESP_OK, LENGTH(sr), RAW(sr));
						} else if (Rerr == 0) Rerr = -2;
					}
					UNPROTECT(1);
				}
				UNPROTECT(1);
				if (Rerr) {
					sendResp(a, SET_STAT(RESP_ERR, Rerr));
				}
			}
		}

		if (ph.cmd == CMD_voidEval || ph.cmd == CMD_eval || ph.cmd == CMD_detachedVoidEval) {
			int is_large = (parT[0] & DT_LARGE) ? 1 : 0;
			if (is_large) parT[0] ^= DT_LARGE;
			process = 1;
			if (pars < 1 || (parT[0] != DT_STRING && parT[0] != DT_SEXP))
				sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
			else if (parT[0] == DT_SEXP) {
				unsigned int *sptr = ((unsigned int*)parP[0]) + is_large;
				SEXP val = QAP_decode(&sptr);
				if (!val) {
#ifdef RSERV_DEBUG
					printf("  FAILED to decode SEXP parameter\n");
#endif
					sendResp(a, SET_STAT(RESP_ERR, ERR_inv_par));
				} else {
					PROTECT(val);
#ifdef RSERV_DEBUG
					printf("  running eval on SEXP: ");
					printSEXP(val);
#endif
					eval_result = R_tryEval(val, R_GlobalEnv, &Rerror);
					a->msg_id = msg_id; /* just in case R-side used OOB */
					UNPROTECT(1);
				}
			} else {
				int j = 0;
				c = (char*)parP[0];
				if (is_large) c += 4;
#ifdef RSERV_DEBUG
				printf("parseString(\"%s\")\n",c);
#endif
				xp = parseString(c, &j, &stat);
				PROTECT(xp);
#ifdef RSERV_DEBUG
				printf("buffer parsed, stat=%d, parts=%d\n", stat, j);
				if (xp)
					printf("result type: %d, length: %d\n",TYPEOF(xp),LENGTH(xp));
				else
					printf("result is <null>\n");
#endif				
				if (stat == 1 && ph.cmd == CMD_detachedVoidEval && detach_session(a))
					sendResp(a, SET_STAT(RESP_ERR, ERR_detach_failed));
				else if (stat != 1)
					sendResp(a, SET_STAT(RESP_ERR, stat));
				else {
#ifdef RSERV_DEBUG
					printf("R_tryEval(xp,R_GlobalEnv,&Rerror);\n");
#endif
					if (ph.cmd==CMD_detachedVoidEval)
						s = -1;
					if (TYPEOF(xp) == EXPRSXP && LENGTH(xp) > 0) {
						int bi = 0;
						while (bi < LENGTH(xp)) {
							SEXP pxp = VECTOR_ELT(xp, bi);
							Rerror = 0;
#ifdef RSERV_DEBUG
							printf("Calling R_tryEval for expression %d [type=%d] ...\n",bi+1,TYPEOF(pxp));
#endif
							eval_result = R_tryEval(pxp, R_GlobalEnv, &Rerror);
							bi++;
#ifdef RSERV_DEBUG
							printf("Expression %d, error code: %d\n", bi, Rerror);
							if (Rerror) printf(">> early error, aborting further evaluations\n");
#endif
							if (Rerror) break;
						}
					} else {
						Rerror = 0;
						eval_result = R_tryEval(xp, R_GlobalEnv, &Rerror);
					}
				}
				UNPROTECT(1); /* xp */
				a->msg_id = msg_id; /* just in case R-side used OOB */
			}
		}

		/* any command above can set eval_result -- in that case we 
		   encode the result and send it as the reply */
		if (eval_result || Rerror) {
			if (eval_result) exp = PROTECT(eval_result);
#ifdef RSERV_DEBUG
			printf("expression(s) evaluated (Rerror=%d).\n",Rerror);
			if (!Rerror) printSEXP(exp);
#endif
			if (ph.cmd == CMD_detachedVoidEval && s == -1)
				s = resume_session();
			if (Rerror) {
				sendResp(a, SET_STAT(RESP_ERR, (Rerror < 0) ? Rerror : -Rerror));
			} else {
				if (ph.cmd == CMD_voidEval || ph.cmd == CMD_detachedVoidEval)
					sendResp(a, RESP_OK);
				else {
					char *sendhead = 0;
					int canProceed = 1;
					/* check buffer size vs REXP size to avoid dangerous overflows
					   todo: resize the buffer as necessary
					*/
					rlen_t rs = QAP_getStorageSize(exp);
					/* FIXME: add a 4k security margin - it should no longer be needed,
					   originally the space was grown proportionally to account for a bug,
					   but that bug has been fixed. */
					rs += 4096;
#ifdef RSERV_DEBUG
					printf("result storage size = %ld bytes\n",(long)rs);
#endif
					if (rs > sendBufSize - 64L) { /* is the send buffer too small ? */
						canProceed = 0;
						if (maxSendBufSize && rs + 64L > maxSendBufSize) { /* first check if we're allowed to resize */
							unsigned int osz = (rs > 0xffffffff) ? 0xffffffff : rs;
							osz = itop(osz);
#ifdef RSERV_DEBUG
							printf("ERROR: object too big (sendBuf=%ld)\n", sendBufSize);
#endif
							sendRespData(a, SET_STAT(RESP_ERR, ERR_object_too_big), 4, &osz);
						} else { /* try to allocate a large, temporary send buffer */
							tempSB = rs + 64L;
							tempSB &= rlen_max << 12;
							tempSB += 0x1000;
#ifdef RSERV_DEBUG
							printf("Trying to allocate temporary send buffer of %ld bytes.\n", (long)tempSB);
#endif
							free(sendbuf);
							sendbuf = (char*)malloc(tempSB);
							if (!sendbuf) {
								tempSB = 0;
#ifdef RSERV_DEBUG
								printf("Failed to allocate temporary send buffer of %ld bytes. Restoring old send buffer of %ld bytes.\n", (long)tempSB, (long)sendBufSize);
#endif
								sendbuf = (char*)malloc(sendBufSize);
								if (!sendbuf) { /* we couldn't re-allocate the buffer */
#ifdef RSERV_DEBUG
									fprintf(stderr,"FATAL: out of memory while re-allocating send buffer to %ld (fallback#1)\n", sendBufSize);
#endif
									sendResp(a, SET_STAT(RESP_ERR, ERR_out_of_mem));
									free(buf); free(sfbuf);
									closesocket(s);
									return;
								} else {
									unsigned int osz = (rs > 0xffffffff) ? 0xffffffff : rs;
									osz = itop(osz);
#ifdef RSERV_DEBUG
									printf("ERROR: object too big (sendBuf=%ld) and couldn't allocate big enough send buffer\n", sendBufSize);
#endif
									sendRespData(a, SET_STAT(RESP_ERR, ERR_object_too_big), 4, &osz);
								}
							} else canProceed = 1;
						}
					}
					if (canProceed) {
						/* first we have 4 bytes of a header saying this is an encoded SEXP, then comes the SEXP */
						char *sxh = sendbuf + 8;
						tail = (char*)QAP_storeSEXP((unsigned int*)sxh, exp, rs);
						
						/* set type to DT_SEXP and correct length */
						if ((tail - sxh) > 0xfffff0) { /* we must use the "long" format */
							rlen_t ll = tail - sxh;
							((unsigned int*)sendbuf)[0] = itop(SET_PAR(DT_SEXP | DT_LARGE, ll & 0xffffff));
							((unsigned int*)sendbuf)[1] = itop(ll >> 24);
							sendhead = sendbuf;
						} else {
							sendhead = sendbuf + 4;
							((unsigned int*)sendbuf)[1] = itop(SET_PAR(DT_SEXP,tail - sxh));
						}
#ifdef RSERV_DEBUG
						printf("stored SEXP; length=%ld (incl. DT_SEXP header)\n",(long) (tail - sendhead));
#endif
						sendRespData(a, RESP_OK, tail - sendhead, sendhead);
						if (tempSB) { /* if this is just a temporary sendbuffer then shrink it back to normal */
#ifdef RSERV_DEBUG
							printf("Releasing temporary sendbuf and restoring old size of %ld bytes.\n", sendBufSize);
#endif
							free(sendbuf);
							sendbuf = (char*)malloc(sendBufSize);
							if (!sendbuf) { /* this should be really rare since tempSB was much larger */
#ifdef RSERV_DEBUG
								fprintf(stderr,"FATAL: out of memory while re-allocating send buffer to %ld (fallback#2),\n", sendBufSize);
#endif
								sendResp(a, SET_STAT(RESP_ERR, ERR_out_of_mem));
										free(buf); free(sfbuf);
										closesocket(s);
										return;		    
							}
						}
					}
				}
				if (eval_result) UNPROTECT(1); /* exp / eval_result */
			}
#ifdef RSERV_DEBUG
			printf("reply sent.\n");
#endif
		} /* END  if (eval_result) */

    respSt:

		if (s == -1) { rn = 0; break; }

		if (!process)
			sendResp(a, SET_STAT(RESP_ERR, ERR_inv_cmd));
    }
#ifdef RSERV_DEBUG
    if (rn == 0)
		printf("Connection closed by peer.\n");
    else {
		printf("malformed packet (n=%d). closing socket to prevent garbage.\n", rn);
		if (rn > 0) printDump(&ph, rn);
    }
#endif
    if (rn > 0)
		sendResp(a, SET_STAT(RESP_ERR, ERR_conn_broken));
    closesocket(s);
    free(sendbuf); free(sfbuf); free(buf);
    
#ifdef RSERV_DEBUG
    printf("done.\n");
#endif
#ifdef FORKED
    /* we should not return to the main loop, but terminate instead */
    exit(0);
#endif
}

typedef void (*sig_fn_t)(int);

#ifdef unix
/* NULL ptr is used on some systems as SIG_DFL so we have
   to define our own value for "not set" */
static void sig_not_set(int x) {}

sig_fn_t old_HUP = sig_not_set, old_TERM = sig_not_set, old_INT = sig_not_set;

static void setup_signal_handlers() {
#ifdef FORKED
	if (old_HUP == sig_not_set) old_HUP = signal(SIGHUP, sigHandler);
	if (old_TERM == sig_not_set) old_TERM = signal(SIGTERM, sigHandler);
	if (old_INT == sig_not_set) old_INT = signal(SIGINT, brkHandler);
#endif
}

static void restore_signal_handlers() {
	if (old_HUP != sig_not_set) {
		signal(SIGHUP, old_HUP);
		old_HUP = sig_not_set;
	}
	if (old_TERM != sig_not_set) {
		signal(SIGTERM, old_TERM);
		old_TERM = sig_not_set;
	}
	if (old_INT != sig_not_set) {
		signal(SIGINT, old_INT);
		old_INT = sig_not_set;
	}
}
#else
static void setup_signal_handlers() {
}
static void restore_signal_handlers() {
}
#endif

#define MAX_SERVERS 128
static int servers;
static server_t *server[MAX_SERVERS];

int add_server(server_t *srv) {
	if (!srv) return 0;
	if (servers >= MAX_SERVERS) {
		RSEprintf("ERROR: too many servers\n");
		return 0;
	}
	server[servers++] = srv;
#ifdef RSERV_DEBUG
	printf("INFO: adding server %p (total %d servers)\n", (void*) srv, servers);
#endif

	return 1;
}

int rm_server(server_t *srv) {
	int i = 0;
	if (!srv) return 0;
	while (i < servers) {
		if (server[i] == srv) {
			int j = i + 1;
			while (j < servers) { server[j - 1] = server[j]; j++; }
			servers--;
		} else i++;
	}
	if (srv->fin) srv->fin(srv);
#ifdef RSERV_DEBUG
	printf("INFO: removing server %p (total %d servers left)\n", (void*) srv, servers);
#endif
	return 1;
}

int server_recv(args_t *arg, void *buf, rlen_t len) {
	return recv(arg->s, buf, len, 0);
}

int server_send(args_t *arg, const void *buf, rlen_t len) {
	return send(arg->s, buf, len, 0);
}

server_t *create_Rserve_QAP1(int flags) {
	server_t *srv;
	if (use_ipv6) flags |= SRV_IPV6;
	if (localonly) flags |= SRV_LOCAL;
	srv = create_server((flags & SRV_TLS) ? tls_port : port, localSocketName, localSocketMode, flags);
	if (srv) {
		srv->connected = Rserve_QAP1_connected;
		srv->send_resp = Rserve_QAP1_send_resp;
		srv->fin       = server_fin;
		srv->recv      = server_recv;
		srv->send      = server_send;
		add_server(srv);
		return srv;
	}
	return 0;
}

void serverLoop() {
    struct timeval timv;
    int selRet = 0;
    fd_set readfds;

	if (main_argv && tag_argv == 1 && strlen(main_argv[0]) >= 8) {
		strcpy(main_argv[0] + strlen(main_argv[0]) - 8, "/RsrvSRV");
		tag_argv = 2;
	}
    
    while(active && (servers || children)) { /* main serving loop */
		int i;
		int maxfd = 0;
#ifdef FORKED
		while (waitpid(-1, 0, WNOHANG) > 0);
#endif
		/* 500ms (used to be 10ms) - it shouldn't really matter since
		   it's ok for us to sleep -- the timeout will only influence
		   how often we collect terminated children and (maybe) how
		   quickly we react to shutdown */
		timv.tv_sec = 0; timv.tv_usec = 500000;
		FD_ZERO(&readfds);
		for (i = 0; i < servers; i++)
			if (server[i])
				{
					int ss = server[i]->ss;
					if (ss > maxfd)
						maxfd = ss;
					FD_SET(ss, &readfds);
				}
		
		if (children) {
			child_process_t *cp = children;
			while (cp) {
				if (cp->io) {
					int fd = rsio_select_fd(cp->io);
					if (fd != -1) {
						FD_SET(fd, &readfds);
						if (fd > maxfd) maxfd = fd;
					}
				}
				cp = cp->next;
			}
		}

		selRet = select(maxfd + 1, &readfds, 0, 0, &timv);

		if (selRet > 0) {
			for (i = 0; i < servers; i++) {
				socklen_t al;
				struct args *sa;
				server_t *srv = server[i];
				int ss = srv->ss;
				int succ = 0;
				if (server[i] && FD_ISSET(ss, &readfds)) {
					sa = (struct args*)malloc(sizeof(struct args));
					memset(sa, 0, sizeof(struct args));
					al = sizeof(sa->sa);
#ifdef unix
					if (server[i]->unix_socket) {
						al = sizeof(sa->su);
						sa->s = CF("accept", accept(ss, (SA*)&(sa->su), &al));
					} else
#endif
						sa->s = CF("accept", accept(ss, (SA*)&(sa->sa), &al));
					accepted_server(srv, sa->s);
					sa->ucix = UCIX++;
					sa->ss = ss;
					sa->srv = srv;
					/*
					  memset(sa->sk,0,16);
					  sa->sfd=-1;
					  #if defined SESSIONS && defined FORKED
					  {
					  int pd[2];
					  if (!pipe(&pd)) {
					  
					  }
					  }
					  #endif
					*/
					if (allowed_ips && !srv->unix_socket && !use_ipv6) {
						/* FIXME: IPv6 unsafe - filtering won't work on IPv6 addresses */
						char **laddr = allowed_ips;
						int allowed = 0;
						while (*laddr)
							if (sa->sa.sin_addr.s_addr == inet_addr(*(laddr++)))
								{ allowed=1; break; }
						if (allowed) {
#ifdef RSERV_DEBUG
							printf("INFO: accepted connection for server %p, calling connected\n", (void*) srv);
#endif
							srv->connected(sa);
							succ = 1;
#ifdef FORKED
							/* when the child returns it means it's done (likely an error)
							   but it is forked, so the only right thing to do is to exit */
							if (is_child)
								exit(2);
#endif
						} else {
#ifdef RSERV_DEBUG
							printf("INFO: peer is not on allowed IP list, closing connection\n");
#endif
							closesocket(sa->s);
						}
					} else { /* ---> remote enabled */
#ifdef RSERV_DEBUG
						printf("INFO: accepted connection for server %p, calling connected\n", (void*) srv);
#endif
						srv->connected(sa);
						succ = 1;
						if (is_child) /* same as above */
							exit(2);
					}
#ifdef Win32
				}
			}
		}
#else
				}
				if (succ) { /* if there was an actual connection, offer to run .Rserve.served */
					SEXP fun, fsym = install(".Rserve.served");
					int evalErr = 0;
					fun = findVarInFrame(R_GlobalEnv, fsym);
					if (Rf_isFunction(fun))
                        R_tryEval(lang1(fsym), R_GlobalEnv, &evalErr);
				}
			} /* end loop over servers */

			if (children) { /* one of the children signalled */
				child_process_t *cp = children;
				while (cp) {
					if (cp->io && FD_ISSET(rsio_select_fd(cp->io), &readfds)) {
						rsmsg_t *msg;
						int msg_stat = rsio_read_status(cp->io);
						if (msg_stat < 0) { /* error, assume corruption and remove the child */
							child_process_t *ncp = cp->next;
#ifdef RSERV_DEBUG
							printf("pipe to child %d closed, removing child\n", (int) cp->pid);
#endif
							rsio_free(cp->io);
							cp->io = 0;
							/* remove the child from the list */
							if (cp->prev) cp->prev->next = ncp; else children = ncp;
							if (ncp) ncp->prev = cp->prev;
							free(cp);
							cp = ncp;
						} else if (msg_stat == 1 && (msg = rsio_read_msg(cp->io))) { /* we got a valid message */
							rsmsg_addr_t *src = 0, *dst = 0;
							rsmsglen_t msg_pos = 0;
							msg->data[msg->len] = 0; /* rsio guarantees extra sentinel byte */
							if ((msg->cmd & RSMSG_HAS_SRC) && msg->len >= RSMSG_ADDR_LEN) { /* has source address */
								src = (rsmsg_addr_t*) (msg->data);
								msg_pos += RSMSG_ADDR_LEN;
							}
							if ((msg->cmd & RSMSG_HAS_DST) && (msg->len - msg_pos) >= RSMSG_ADDR_LEN) { /* has destination address */
								dst = (rsmsg_addr_t*) (msg->data + RSMSG_ADDR_LEN);
								msg_pos += RSMSG_ADDR_LEN;
							}
							/* is this message addressed to us ? */
							if (!dst || !memcmp(&server_addr, dst, RSMSG_ADDR_LEN)) {
								if (msg->cmd == CCTL_EVAL) {
#ifdef RSERV_DEBUG
									printf(" - control calling voidEval(\"%s\")\n", msg->data + msg_pos);
#endif
									voidEval((const char*) (msg->data + msg_pos));
								} else if (msg->cmd == CCTL_SOURCE) {
									int evalRes = 0;
									SEXP exp;
									SEXP sfn = PROTECT(allocVector(STRSXP, 1));
									SET_STRING_ELT(sfn, 0, mkRChar((const char*) (msg->data + msg_pos)));
									exp = LCONS(install("source"), CONS(sfn, R_NilValue));
#ifdef RSERV_DEBUG
									printf(" - control calling source(\"%s\")\n", msg->data + msg_pos);
#endif
									R_tryEval(exp, R_GlobalEnv, &evalRes);
#ifdef RSERV_DEBUG
									printf(" - result: %d\n", evalRes);
#endif
									UNPROTECT(1);								
								} else if (msg->cmd == CCTL_SHUTDOWN) {
#ifdef RSERV_DEBUG
									printf(" - shutdown via control, setting active to 0\n");
#endif
									active = 0;
								}
							} else { /* let's see if we can route it */
								child_process_t *cdst = children;
								rsmsg_addr_t saddr[2];
								saddr[0] = server_addr;
								saddr[1] = *dst;
								while (cdst) {
									if (!memcmp(&(cdst->addr), dst, RSMSG_ADDR_LEN)) {
										if (!cdst->io) {
											rsio_write(cp->io, saddr, RSMSG_ADDR_LEN * 2, RSMSG_ERR_NO_IO | RSMSG_HAS_DST | RSMSG_HAS_SRC, -1);
										} else {
											if (rsio_write_msg(cdst->io, msg) != 0)
												rsio_write(cp->io, saddr, RSMSG_ADDR_LEN * 2, RSMSG_ERR_IO_FAILED | RSMSG_HAS_DST | RSMSG_HAS_SRC, -1);
										}
										break;
									}
									cdst = cdst->next;
								}
								if (!cdst) /* address not found */
									rsio_write(cp->io, saddr, RSMSG_ADDR_LEN * 2, RSMSG_ERR_NOT_FOUND | RSMSG_HAS_DST | RSMSG_HAS_SRC, -1);
							}
							rsmsg_free(msg);
							cp = cp->next;	
						} else /* the last case is 0 where some data was processed but not an entire message */
							cp = cp->next;
					} else
						cp = cp->next;
				} /* loop over children */
			} /* end if (children) */
		} /* end if (selRet > 0) */
#endif
    } /* end while(active) */
}

#ifndef STANDALONE_RSERVE

/* run Rserve inside R */
SEXP run_Rserve(SEXP cfgFile, SEXP cfgPars) {
	server_stack_t *ss;
	if (TYPEOF(cfgFile) == STRSXP && LENGTH(cfgFile) > 0) {
		int i, n = LENGTH(cfgFile);
		for (i = 0; i < n; i++)
			loadConfig(CHAR(STRING_ELT(cfgFile, i)));
	}
	if (TYPEOF(cfgPars) == STRSXP && LENGTH(cfgPars) > 0) {
		int i, n = LENGTH(cfgPars);
		SEXP sNam = Rf_getAttrib(cfgPars, R_NamesSymbol);
		if (TYPEOF(sNam) != STRSXP || LENGTH(sNam) != n)
			Rf_error("invalid configuration parameters");
		for (i = 0; i < n; i++) {
			const char *key = CHAR(STRING_ELT(sNam, i));
			const char *value = CHAR(STRING_ELT(cfgPars, i));
			int res = setConfig(key, value);
			if (res == 0)
				Rf_warning("Unknown configuration setting `%s`, ignored.", key);
		}
	}
	
	RSsrv_init();
	/* FIXME: should we really do this ? setuid, chroot etc. are not meant to work inside R ... */
	performConfig(SU_NOW);

	ss = create_server_stack();

	if (enable_qap) {
		server_t *srv = create_Rserve_QAP1((qap_oc ? SRV_QAP_OC : 0) | global_srv_flags);
		if (!srv) {
			release_server_stack(ss);
			RSsrv_done();
			Rf_error("Unable to start Rserve server");
		}
		push_server(ss, srv);
	}

	if (tls_port > 0) {
		server_t *srv = create_Rserve_QAP1(SRV_TLS | (qap_oc ? SRV_QAP_OC : 0) | global_srv_flags);
		if (!srv) {
			release_server_stack(ss);
			RSsrv_done();
			Rf_error("Unable to start TLS/Rserve server");
		}
		push_server(ss, srv);
	}

	if (http_port > 0) {
		int flags =  (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) |
			(ws_qap_oc ? SRV_QAP_OC : 0) | global_srv_flags;
		server_t *srv = create_HTTP_server(http_port, flags |
										   (ws_upgrade ? HTTP_WS_UPGRADE : 0) |
										   (http_raw_body ? HTTP_RAW_BODY : 0));
		if (!srv) {
			release_server_stack(ss);
			RSsrv_done();
			Rf_error("Unable to start HTTP server on port %d", http_port);
		}
		push_server(ss, srv);
	}

	if (https_port > 0) {
		int flags =  (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) | (ws_qap_oc ? SRV_QAP_OC : 0) | global_srv_flags;
		server_t *srv = create_HTTP_server(https_port, SRV_TLS | flags |
										   (ws_upgrade ? HTTP_WS_UPGRADE : 0) |
										   (http_raw_body ? HTTP_RAW_BODY : 0));
		if (!srv) {
			release_server_stack(ss);
			RSsrv_done();
			Rf_error("Unable to start HTTPS server on port %d", https_port);
		}
		push_server(ss, srv);
	}

	if (enable_ws_text || enable_ws_qap) {
		server_t *srv;
		if (ws_port < 1 && wss_port < 1 && !ws_upgrade) {
			release_server_stack(ss);
			RSsrv_done();
			Rf_error("Invalid or missing websockets port");
		}
		if (ws_port > 0) {
			srv = create_WS_server(ws_port, (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) | (ws_qap_oc ? SRV_QAP_OC : 0) | global_srv_flags);
			if (!srv) {
				release_server_stack(ss);
				RSsrv_done();
				Rf_error("Unable to start WebSockets server on port %d", ws_port);
			}
			push_server(ss, srv);
		}
		if (wss_port > 0) {
			srv = create_WS_server(wss_port, (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) | (ws_qap_oc ? SRV_QAP_OC : 0) | WS_TLS | global_srv_flags);
			if (!srv) {
				release_server_stack(ss);
				RSsrv_done();
				Rf_error("Unable to start TLS/WebSockets server on port %d", wss_port);
			}
			push_server(ss, srv);
		}
	}

	if (!server_stack_size(ss)) {
		Rf_warning("No server protocol is enabled, nothing to do");
		release_server_stack(ss);
		RSsrv_done();
		return ScalarLogical(FALSE);
	}
	
	setup_signal_handlers();

	Rprintf("-- running Rserve in this R session (pid=%d), %d server(s) --\n(This session will block until Rserve is shut down)\n", getpid(), server_stack_size(ss));
	active = 1;

	serverLoop();
	
	restore_signal_handlers();

	release_server_stack(ss);
	
	RSsrv_done();

	return ScalarLogical(TRUE);
}

#endif

#endif

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
