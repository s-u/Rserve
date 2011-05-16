/*
 *  Rserv : R-server that allows to use embedded R via TCP/IP
 *  Copyright (C) 2002-9 Simon Urbanek
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

   THREADED    - results in threaded version of this server, i.e. each
                 new connection is run is a separate thread. Beware:
				 this approach is not recommended since R does not support
				 real multithreading yet

   FORKED      - each connection is forked to a new process. This is the
                 recommended way to use this server. The advantage is (beside
				 the fact that this works ;)) that each client has a separate
				 namespace since the processes are independent
				 (default for unix platforms)

   SWAPEND     - define if the platform has byte order inverse to Intel (like PPC)

   RSERV_DEBUG - if defined various verbose output is produced

   NOFULL   - dumps show first 100 bytes only
              (removed in 0.3-3 and replaced by dumpLimit variable)

   DAEMON      - if defined the server daemonizes (unix only)

   CONFIG_FILE - location of the config file (default /etc/Rserv.conf)

   FORCE_V0100 - if this macro is defined then Rserve reports version 0100 and
                 CMD_eval doesn't send data type header (DT_SEXP+length). This
				 was a buggy behavior in versions up to 0.1-9. This feature is
				 provided only for compatibility with old clients and should be
				 avoided. Update the clients instead, if possible.
				 (Warning: since 0.3 this feature is untested and not likely
				 to work!)

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

#define USE_RINTERNALS
#define SOCK_ERRORS
#define LISTENQ 16
#define MAIN

/* this is the type used to calculate pointer distances */
/* note: we may want to use size_t or something more compatible */
typedef unsigned long rlen_t;

#ifdef ULONG_MAX
#define rlen_max ULONG_MAX
#else
#ifdef __LP64__
#define rlen_max 0xffffffffffffffffL 
#else
#define rlen_max 0xffffffffL
#endif /* __LP64__ */
#endif /* ULONG_MAX */

/* some OSes don't like too large chunks to be sent/received,
   so we imit the socket I/O sizes by this constant.
   It should be a 31-bit value for compatibility.
*/
#define max_sio_chunk 134217728

#if defined NODAEMON && defined DAEMON
#undef DAEMON
#endif

/* MacOS X hack. gcc on any (non-windows) platform is treated as unix */
#if defined __GNUC__ && !defined unix && !defined Win32
#define unix
#endif

/* FORKED is default for unix platforms */
#if defined unix && !defined THREADED && !defined COOPERATIVE && !defined FORKED
#define FORKED
#endif

#ifndef CONFIG_FILE
#ifdef unix
#define CONFIG_FILE "/etc/Rserv.conf"
#else
#define CONFIG_FILE "Rserv.cfg"
#endif
#endif

/* we have no configure for Win32 so we have to take care of socklen_t */
#ifdef Win32
typedef int socklen_t;
#define CAN_TCP_NODELAY
#include <windows.h>
#include <io.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sisocks.h>
#include <string.h>
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
#ifdef THREADED
#include <sbthread.h>
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
#ifdef Win32 /* Windows doesn't have Rinterface */
extern __declspec(dllimport) int R_SignalHandlers;
#else
#include <Rinterface.h>
#endif
#endif
#if R_VERSION < 0x2010
#include "Parse.h"
#else
#include <R_ext/Parse.h>
#endif
#include "Rsrv.h"
#ifdef HAVE_CRYPT_H
#include <crypt.h>
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

#define MAX_CTRL_DATA (1024*1024) /* max. length of data for control commands - larger data will be ignored */

int dumpLimit=128;

static int port = default_Rsrv_port;
static int active = 1; /* 1=server loop is active, 0=shutdown */
static int UCIX   = 1; /* unique connection index */

static char *localSocketName = 0; /* if set listen on this local (unix) socket instead of TCP/IP */
static int localSocketMode = 0;   /* if set, chmod is used on the socket when created */

static int allowIO=1;  /* 1=allow I/O commands, 0=don't */

static char **top_argv;
static int top_argc;

static char *workdir="/tmp/Rserv";
static char *pwdfile=0;

static SOCKET csock=-1;

static int parentPID=-1;

int is_child = 0;       /* 0 for parent (master), 1 for children */
int parent_pipe = -1;   /* pipe to the master process or -1 if not available */
int can_control = 0;    /* control commands will be rejected unless this flag is set */
int child_control = 0;  /* enable/disable the ability of children to send commands to the master process */

rlen_t maxSendBufSize = 0; /* max. sendbuf for auto-resize. 0=no limit */

int Rsrv_interactive = 1; /* default for R_Interactive flag */

#ifdef unix
static int umask_value = 0;
#endif

static char **allowed_ips = 0;

static const char *rserve_ver_id = "$Id$";

static char rserve_rev[16]; /* this is generated from rserve_ver_id by main */

#ifdef THREADED
static int localUCIX;
#else
#define localUCIX UCIX
#endif

/* string encoding handling */
#if (R_VERSION < R_Version(2,8,0)) || (defined DISABLE_ENCODING)
#define mkRChar(X) mkChar(X)
#define CHAR_FE(X) CHAR(X)
#else
#define USE_ENCODING 1
static cetype_t string_encoding = CE_NATIVE;  /* default is native */
#define mkRChar(X) mkCharCE((X), string_encoding)
#define CHAR_FE(X) charsxp_to_current(X)
static const char *charsxp_to_current(SEXP s) {
	if (Rf_getCharCE(s) == string_encoding) return CHAR(s);
	return Rf_reEnc(CHAR(s), getCharCE(s), string_encoding, 0);
}
#endif

/* this is the representation of NAs in strings. We chose 0xff since that should never occur in UTF-8 strings. If 0xff occurs in the beginning of a string anyway, it will be doubled to avoid misrepresentation. */
static const unsigned char NaStringRepresentation[2] = { 255, 0 };

static int set_string_encoding(const char *enc, int verbose) {
#ifdef USE_ENCODING
	if (!strcmp(enc, "native")) string_encoding = CE_NATIVE;
	else if (!strcmp(enc, "latin1")) string_encoding = CE_LATIN1;
	else if (!strcmp(enc, "utf8")) string_encoding = CE_UTF8;
	else {
		if (verbose)
			fprintf(stderr, "WARNING: invalid encoding value '%s' - muse be one of 'native', 'latin1' or 'utf8'.\n", enc);
		return 0;
	}
	return 1;
#else
	if (verbose)
		fprintf(stderr, "WARNING: 'encoding' defined but this Rserve has no encoding support.\n");
	return 0;
#endif
}

/* "smart" atoi - accepts 0x for hex and 0 for octal */
static int satoi(const char *str) {
	if (!str) return 0;
	if (str[0]=='0') {
		if (str[1]=='x')
			return strtol(str, 0, 16);
		if (str[1]>='0' && str[1]<='9')
			return strtol(str, 0, 8);
	}
	return atoi(str);
}

#ifdef RSERV_DEBUG
static void printDump(void *b, int len) {
    int i=0;
    if (len<1) { printf("DUMP FAILED (len=%d)\n",len); };
    printf("DUMP [%d]:",len);
    while(i<len) {
		printf(" %02x",((unsigned char*)b)[i++]);
		if(dumpLimit && i>dumpLimit) { printf(" ..."); break; };
    }
    printf("\n");
}
#endif

static void sendResp(int s, int rsp) {
    struct phdr ph;
    memset(&ph, 0, sizeof(ph));
    ph.cmd = itop(rsp | CMD_RESP);
#ifdef RSERV_DEBUG
    printf("OUT.sendResp(void data)\n");
    printDump(&ph, sizeof(ph));
#endif
    send(s, (char*)&ph, sizeof(ph), 0);
}

#if 0 /* UNUSED ?? */
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
#endif

#define attrFixup if (hasAttr) buf = storeSEXP(buf, ATTRIB(x), 0);
#define dist(A,B) (((rlen_t)(((char*)B)-((char*)A))) - 4L)
#define align(A) (((A) + 3L) & (rlen_max ^ 3L))

static rlen_t getStorageSize(SEXP x) {
    int t = TYPEOF(x);
    rlen_t tl = LENGTH(x); /* although LENGTH can only be 32-bit use rlen_t to avoid downcasting */
    rlen_t len = 4;
    
#ifdef RSERV_DEBUG
    printf("getStorageSize(%p,type=%d,len=%ld) ", (void*)x, t, tl);
#endif
    if (t != CHARSXP && TYPEOF(ATTRIB(x)) == LISTSXP) {
		rlen_t alen = getStorageSize(ATTRIB(x));
		len += alen;
    }
    switch (t) {
    case LISTSXP:
    case LANGSXP:
		{
			SEXP l = x;
			rlen_t tags = 0, n = 0;
			while (l != R_NilValue) {
				len  += getStorageSize(CAR(x));
				tags += getStorageSize(TAG(x));
				n++;
				l = CDR(l);
			}
			if (tags > 4L * n) len += tags; /* use tagged list */
		}
		break;
    case CLOSXP:
		len+=getStorageSize(FORMALS(x));
		len+=getStorageSize(BODY(x));
		break;
	case CPLXSXP:
		len += tl * 16L; break;
    case REALSXP:
		len += tl * 8L; break;
    case INTSXP:
		len += tl * 4L; break;
    case LGLSXP:
	case RAWSXP:
		if (tl > 1)
			len += 4L + align(tl);
		else
			len += 4L;	
		break;
		
    case SYMSXP:
    case CHARSXP:
		{
			const char *ct = ((t==CHARSXP) ? CHAR_FE(x) : CHAR_FE(PRINTNAME(x)));
			if (!ct)
				len += 4L;
			else {
				rlen_t sl = strlen(ct) + 1L;				
				len += align(sl);
			}
		}
		break;
    case STRSXP:
		{
			unsigned int i = 0;
			while (i < tl) {
				len += getStorageSize(STRING_ELT(x, i));
				i++;
			}
		}
		break;
    case EXPRSXP:
    case VECSXP:
		{
			unsigned int i = 0;
			while(i < tl) {
				len += getStorageSize(VECTOR_ELT(x,i));
				i++;
			}
		}
		break;
	case S4SXP:
		/* S4 really has the payload in attributes, so it doesn't occupy anything */
		break;
    default:
		len += 4L; /* unknown types are simply stored as int */
    }
    if (len > 0xfffff0) /* large types must be stored in the new format */
		len += 4L;
#ifdef RSERV_DEBUG
    printf("= %lu\n", len);
#endif
    return len;
}

/* if storage_size is > 0 then it it used instad of a call to getStorageSize() */
static unsigned int* storeSEXP(unsigned int* buf, SEXP x, rlen_t storage_size) {
    int t = TYPEOF(x);
    int hasAttr = 0;
    int isLarge = 0;
    unsigned int *preBuf = buf;
    rlen_t txlen;

    if (!x) { /* null pointer will be treated as XT_NULL */
		*buf = itop(XT_NULL); buf++; goto didit;
    }
    
    if (t != CHARSXP && TYPEOF(ATTRIB(x)) == LISTSXP)
		hasAttr = XT_HAS_ATTR;
    
    if (t == NILSXP) {
		*buf = itop(XT_NULL | hasAttr);
		buf++;
		attrFixup;
		goto didit;
    } 
    
    /* check storage size */
    txlen = storage_size ? storage_size : getStorageSize(x);
    if (txlen > 0xfffff0) { /* if the entry is too big, use large format */
		isLarge = 1;
		buf++;
    }
    
    if (t==LISTSXP || t==LANGSXP) {
		SEXP l = x;
		rlen_t tags = 0;
		while (l != R_NilValue) {
			if (TAG(l) != R_NilValue) tags++;
			l = CDR(l);
		}
		/* note that we are using the fact that XT_LANG_xx=XT_LIST_xx+2 */
		*buf = itop((((t == LISTSXP) ? 0 : 2) + (tags ? XT_LIST_TAG : XT_LIST_NOTAG)) | hasAttr);
		buf++;
		attrFixup;
		l = x;
		while (l != R_NilValue) {			
			buf = storeSEXP(buf, CAR(l), 0);
			if (tags)
				buf = storeSEXP(buf, TAG(l), 0);
			l = CDR(l);
		}
		goto didit;
    }
    
    if (t==CLOSXP) { /* closures (send FORMALS and BODY) */
		*buf=itop(XT_CLOS|hasAttr);
		buf++;
		attrFixup;
		buf=storeSEXP(buf, FORMALS(x), 0);
		buf=storeSEXP(buf, BODY(x), 0);
		goto didit;
    }
    
    if (t==REALSXP) {
		R_len_t i = 0;
		*buf=itop(XT_ARRAY_DOUBLE|hasAttr);
		buf++;
		attrFixup;
		while(i < LENGTH(x)) {
			fixdcpy(buf, REAL(x) + i);
			buf += 2; /* sizeof(double)=2*sizeof(int) */
			i++;
		}
		goto didit;
    }

    if (t==CPLXSXP) {
		R_len_t i = 0;
		*buf = itop(XT_ARRAY_CPLX|hasAttr);
		buf++;
		attrFixup;
		while(i < LENGTH(x)) {
			fixdcpy(buf, &(COMPLEX(x)[i].r));
			buf += 2; /* sizeof(double)=2*sizeof(int) */
			fixdcpy(buf, &(COMPLEX(x)[i].i));
			buf += 2; /* sizeof(double)=2*sizeof(int) */
			i++;
		}
		goto didit;
    }

	if (t==RAWSXP) {
		R_len_t ll = LENGTH(x);
		*buf = itop(XT_RAW | hasAttr);
		buf++;
		attrFixup;
		*buf = itop(ll); buf++;
		if (ll) memcpy(buf, RAW(x), ll);
		ll += 3; ll /= 4;
		buf += ll;
		goto didit;
	}
		
    if (t==LGLSXP) {
		R_len_t ll = LENGTH(x), i = 0;
		int *lgl = LOGICAL(x);
		*buf = itop(XT_ARRAY_BOOL | hasAttr);
		buf++;
		attrFixup;
		*buf = itop(ll); buf++;
		while(i < ll) { /* logical values are stored as bytes of values 0/1/2 */
			int bv = lgl[i];
			*((unsigned char*)buf) = (bv == 0) ? 0 : (bv==1) ? 1 : 2;
			buf = (unsigned int*)(((unsigned char*)buf) + 1);
			i++;
		}
		/* pad by 0xff to a multiple of 4 */
		while (i & 3) {
			*((unsigned char*)buf) = 0xff;
			i++;
			buf=(unsigned int*)(((unsigned char*)buf) + 1);
		}
		goto didit;
    }
    
	if (t == STRSXP) {
		char *st;
		R_len_t nx = LENGTH(x), i;
		*buf = itop(XT_ARRAY_STR|hasAttr);
		buf++;
		attrFixup;
		/* leading int n; is not needed due to the choice of padding */
		st = (char *)buf;
		for (i = 0; i < nx; i++) {
			const char *cv = CHAR_FE(STRING_ELT(x, i));
			rlen_t l = strlen(cv);
			if (STRING_ELT(x, i) == R_NaString) {
				cv = (const char*) NaStringRepresentation;
				l = 1;
			} else if ((unsigned char) cv[0] == NaStringRepresentation[0]) /* we will double the leading 0xff to avoid abiguity between NA and "\0xff" */
				(st++)[0] = (char) NaStringRepresentation[0];
			strcpy(st, cv);
			st += l + 1;
		}
		/* pad with '\01' to make sure we can determine the number of elements */
		while ((st - (char*)buf) & 3) *(st++) = 1;
		buf = (unsigned int*)st;
		goto didit;
	}

    if (t==EXPRSXP || t==VECSXP) {
		R_len_t i = 0, n = LENGTH(x);
		*buf = itop(((t == EXPRSXP) ? XT_VECTOR_EXP : XT_VECTOR) | hasAttr);
		buf++;
		attrFixup;
		while(i < n) {
			buf = storeSEXP(buf, VECTOR_ELT(x, i), 0);
			i++;
		}
		goto didit;
    }
	
    if (t==INTSXP) {
		R_len_t i = 0, n = LENGTH(x);
		int *iptr = INTEGER(x);
		*buf = itop(XT_ARRAY_INT | hasAttr);
		buf++;
		attrFixup;
		while(i < n) {
			*buf = itop(iptr[i]);
			buf++;
			i++;
		}
		goto didit;
    }

    if (t==S4SXP) {
		*buf=itop(XT_S4|hasAttr);
		buf++;
		attrFixup;
		goto didit;		
	}
	
    if (t==CHARSXP||t==SYMSXP) {
		rlen_t sl;
		const char *val;
		if (t == CHARSXP) {
			*buf = itop(XT_STR | hasAttr);
			val = CHAR_FE(x);
		} else {
			*buf = itop(XT_SYMNAME | hasAttr);
			val = CHAR_FE(PRINTNAME(x));
		}
		buf++;
		attrFixup;
		strcpy((char*)buf, val);
		sl = strlen((char*)buf); sl++;
		while (sl & 3) { /* pad by 0 to a length divisible by 4 (since 0.1-10) */
			buf[sl] = 0; sl++;
		}
		buf = (unsigned int*)(((char*)buf) + sl);
		goto didit;
    }
	
    *buf = itop(XT_UNKNOWN | hasAttr);
    buf++;
    attrFixup;
    *buf = itop(TYPEOF(x));
    buf++;
    
 didit:
    if (isLarge) {
		txlen = dist(preBuf, buf) - 4L;
		preBuf[0] = itop(SET_PAR(PAR_TYPE(((unsigned char*) preBuf)[4] | XT_LARGE), txlen & 0xffffff));
		preBuf[1] = itop(txlen >> 24);
    } else
		*preBuf = itop(SET_PAR(PAR_TYPE(ptoi(*preBuf)), dist(preBuf, buf)));

#ifdef RSERV_DEBUG
	printf("stored %p at %p, %lu bytes\n", (void*)x, (void*)preBuf, (unsigned long) dist(preBuf, buf));
#endif

    return buf;
}

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

/* decode_toSEXP is used to decode SEXPs from binary form and create
   corresponding objects in R. UPC is a pointer to a counter of
   UNPROTECT calls which will be necessary after we're done.
   The buffer position is advanced to the point where the SEXP ends
   (more precisely it points to the next stored SEXP). */
static SEXP decode_to_SEXP(unsigned int **buf, int *UPC)
{
    unsigned int *b = *buf, *pab = *buf;
    char *c, *cc;
    SEXP val = 0, vatt = 0;
    int ty = PAR_TYPE(ptoi(*b));
    rlen_t ln = PAR_LEN(ptoi(*b));
    R_len_t i, l;
    
    if (IS_LARGE(ty)) {
		ty ^= XT_LARGE;
		b++;
		ln |= ((rlen_t) (unsigned int) ptoi(*b)) << 24;
    }
#ifdef RSERV_DEBUG
    printf("decode: type=%d, len=%ld\n", ty, (long)ln);
#endif
    b++;
    pab = b; /* pre-attr b */

	if (ty & XT_HAS_ATTR) {
#ifdef RSERV_DEBUG
		printf(" - has attributes\n");
#endif
		*buf = b;
		vatt = decode_to_SEXP(buf, UPC);
		b = *buf;
		ty = ty ^ XT_HAS_ATTR;
#ifdef RSERV_DEBUG
		printf(" - returned from attributes(@%p)\n", (void*)*buf);
#endif
		ln -= (((char*)b) - ((char*)pab)); /* adjust length */
	}

	/* b = beginning of the SEXP data (after attrs)
	   pab = beginning before attrs (=just behind the heaer)
	   ln = length of th SEX payload (w/o attr) */
    switch(ty) {
	case XT_NULL:
		val = R_NilValue;
		*buf = b;
		break;

    case XT_INT:
    case XT_ARRAY_INT:
		l = ln / 4;
		PROTECT(val = allocVector(INTSXP, l));
		(*UPC)++;
		i = 0;
		while (i < l) {
			INTEGER(val)[i] = ptoi(*b); i++; b++;
		}
		*buf = b;
		break;

    case XT_ARRAY_BOOL:
		{
			int vl = ptoi(*(b++));
			char *cb = (char*) b;
			PROTECT(val = allocVector(LGLSXP, vl));
			(*UPC)++;
			i = 0;
			while (i < vl) {
				LOGICAL(val)[i] = cb[i];
				i++;
			}
			while ((i & 3) != 0) i++;
			b = (unsigned int*) (cb + i);
		}
		*buf = b;
		break;

    case XT_DOUBLE:
    case XT_ARRAY_DOUBLE:
		l = ln / 8;
		PROTECT(val = allocVector(REALSXP, l)); (*UPC)++;
		i = 0;
		while (i < l) {
			fixdcpy(REAL(val) + i, b);
			b += 2;
			i++;
		}
		*buf = b;
		break;

    case XT_ARRAY_CPLX:
		l = ln / 16;
		PROTECT(val = allocVector(CPLXSXP, l));
		(*UPC)++;
		i = 0;
		while (i < l) {
			fixdcpy(&(COMPLEX(val)[i].r),b); b+=2;
			fixdcpy(&(COMPLEX(val)[i].i),b); b+=2;
			i++;
		}
		*buf = b;
		break;

    case XT_ARRAY_STR:
		{
			/* count the number of elements */
			char *sen = (c = (char*)(b)) + ln;
			i = 0;
			while (c < sen) {
				if (!*c) i++;
				c++;
			}
			
			PROTECT(val = allocVector(STRSXP, i));
			(*UPC)++;
			i = 0; cc = c = (char*)b;
			while (c < sen) {
				SEXP sx;
				if (!*c) {
					if ((unsigned char)cc[0] == NaStringRepresentation[0]) {
						if ((unsigned char)cc[1] == NaStringRepresentation[1])
							sx = R_NaString;
						else
							sx = mkRChar(cc + 1);
					} else sx = mkRChar(cc);
					SET_STRING_ELT(val, i, sx);
					i++;
					cc = c + 1;
				}
				c++;
			}
		}
		*buf = (unsigned int*)((char*)b + ln);
		break;

	case XT_RAW:
		i = ptoi(*b);
		PROTECT(val = allocVector(RAWSXP, i)); (*UPC)++;
		memcpy(RAW(val), (b + 1), i);
		*buf = (unsigned int*)((char*)b + ln);
		break;

	case XT_VECTOR:
	case XT_VECTOR_EXP:
		{
			unsigned char *ie = (unsigned char*) b + ln;
			R_len_t n = 0;
			SEXP lh = R_NilValue;
			SEXP vr = allocVector(VECSXP, 1);
			*buf = b;
			PROTECT(vr);
			while ((unsigned char*)*buf < ie) {
				int my_upc = 0; /* unprotect all objects on the way since we're staying locked-in */
				SEXP v = decode_to_SEXP(buf, &my_upc);
				lh = CONS(v, lh);
				SET_VECTOR_ELT(vr, 0, lh); /* this is our way of staying protected .. maybe not optimal .. */
				if (my_upc) UNPROTECT(my_upc);
				n++;
			}
#ifdef RSERV_DEBUG
			printf(" vector (%s), %d elements\n", (ty==XT_VECTOR)?"generic":((ty==XT_VECTOR_EXP)?"expression":"string"), n);
#endif
			val = allocVector((ty==XT_VECTOR) ? VECSXP : ((ty == XT_VECTOR_EXP) ? EXPRSXP : STRSXP), n);
			PROTECT(val);
			while (n > 0) {
				n--;
				SET_VECTOR_ELT(val, n, CAR(lh));
				lh = CDR(lh);
			}
#ifdef RSERV_DEBUG
			printf(" end of vector %lx/%lx\n", (long) *buf, (long) ie);
#endif
			UNPROTECT(2); /* val and vr */
			PROTECT(val);
			(*UPC)++;
			break;
		}

	case XT_STR:
	case XT_SYMNAME:
		/* i=ptoi(*b);
		   b++; */
#ifdef RSERV_DEBUG
		printf(" string/symbol(%d) '%s'\n", ty, (char*)b);
#endif
		{
			char *c = (char*) b;
			if (ty == XT_STR) {
				val = mkRChar(c);
				PROTECT(val);
				(*UPC)++;
			} else
				val = install(c);
		}
		*buf = (unsigned int*)((char*)b + ln);
		break;

	case XT_LIST_NOTAG:
	case XT_LIST_TAG:
	case XT_LANG_NOTAG:
	case XT_LANG_TAG:
		{
			SEXP vnext = R_NilValue, vtail = 0;
			unsigned char *ie = (unsigned char*) b + ln;
			val = R_NilValue;
			*buf = b;
			while ((unsigned char*)*buf < ie) {
				int my_upc = 0;
#ifdef RSERV_DEBUG
				printf(" el %08lx of %08lx\n", (unsigned long)*buf, (unsigned long) ie);
#endif
				SEXP el = decode_to_SEXP(buf, &my_upc);
				SEXP ea = 0;
				if (ty==XT_LANG_TAG || ty==XT_LIST_TAG) {
#ifdef RSERV_DEBUG
					printf(" tag %08lx of %08lx\n", (unsigned long)*buf, (unsigned long) ie);
#endif
					ea = decode_to_SEXP(buf, &my_upc);
				}
				if (ty==XT_LANG_TAG || ty==XT_LANG_NOTAG)
					vnext = LCONS(el, R_NilValue);
				else
					vnext = CONS(el, R_NilValue);
				if (my_upc) UNPROTECT(my_upc);
				PROTECT(vnext);
				if (ea) SET_TAG(vnext, ea);
				if (vtail) {
					SETCDR(vtail, vnext);
					UNPROTECT(1);
				} else {
					val = vnext;
					(*UPC)++;
				}
				vtail = vnext;				   
			}
			break;
		}
	default:
		error("unsupported type %d\n", ty);
		*buf = (unsigned int*)((char*)b + ln);
    }

	if (vatt) {
		/* if vatt contains "class" we have to set the object bit [we could use classgets(vec,kls) instead] */
		SEXP head = vatt;
		int has_class = 0;
		SET_ATTRIB(val, vatt);
		while (head != R_NilValue) {
			if (TAG(head) == R_ClassSymbol) {
				has_class = 1; break;
			}
			head = CDR(head);
		}
		if (has_class) /* if it has a class slot, we have to set the object bit */
			SET_OBJECT(val, 1);
#ifdef SET_S4_OBJECT
		/* FIXME: we have currently no way of knowing whether an object
		   derived from a non-S4 type is actually S4 object. Hence
		   we can only flag "pure" S4 objects */
		if (TYPEOF(val) == S4SXP)
			SET_S4_OBJECT(val);
#endif
	}
    return val;
}

/* if set Rserve doesn't accept other than local connections. */
static int localonly = 1;

/* server socket */
static SOCKET ss;

/* arguments structure passed to a working thread */
struct args {
    int s;
    int ss;
    SAIN sa;
    int ucix;
#ifdef unix
    struct sockaddr_un su;
#endif
};

/* send a response including the data part */
static void sendRespData(int s, int rsp, rlen_t len, void *buf) {
    struct phdr ph;
	rlen_t i = 0;
    memset(&ph, 0, sizeof(ph));
    ph.cmd = itop(rsp | CMD_RESP);	
    ph.len = itop(len);
#ifdef __LP64__
	ph.res = itop(len >> 32);
#endif
#ifdef RSERV_DEBUG
    printf("OUT.sendRespData\nHEAD ");
    printDump(&ph,sizeof(ph));
    printf("BODY ");
    printDump(buf,len);
#endif
    
    send(s, (char*)&ph, sizeof(ph), 0);
	
	while (i < len) {
		int rs = send(s, (char*)buf + i, (len - i > max_sio_chunk) ? max_sio_chunk : (len - i), 0);
		if (rs < 1)
			break;
		i += rs;
	}
}

/* initial ID string */
#ifdef FORCE_V0100
char *IDstring="Rsrv0100QAP1\r\n\r\n--------------\r\n";
#else
char *IDstring="Rsrv0103QAP1\r\n\r\n--------------\r\n";
#endif

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
#ifdef unix
static int new_gid = -1, new_uid = -1;
#endif

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

/* load config file */
static int loadConfig(char *fn)
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
			p = c;
			while(*p && *p != '\t' && *p != ' ' && *p != '=' && *p != ':')
				p++;
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
			if (!strcmp(c,"remote"))
				localonly = (*p == '1' || *p == 'y' || *p == 'e') ? 0 : 1;
			if (!strcmp(c,"port")) {
				if (*p) {
					int np = satoi(p);
					if (np > 0) port = np;
				}
			}
			if (!strcmp(c,"maxinbuf")) {
				if (*p) {
					long ns = atol(p);
					if (ns > 32) {
						maxInBuf = ns;
						maxInBuf *= 1024;
					}
				}
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
			}
			if (!strcmp(c,"maxsendbuf")) {
				if (*p) {
					long ns = atol(p);
					if (ns > 32) {
						maxSendBufSize = ns;
						maxSendBufSize *= 1024;
					}
				}
			}
#ifdef unix
			if (!strcmp(c, "su") && *p) {
				if (*p == 'n') su_time = SU_NOW;
				else if (*p == 's') su_time = SU_SERVER;
				else if (*p == 'c') su_time = SU_CLIENT;
				else fprintf(stderr, "su value invalid - must be 'now', 'server' or 'client'.\n");
			}
			if (!strcmp(c,"uid") && *p) {
				new_uid = satoi(p);
				if (su_time == SU_NOW && setuid(new_uid))
					fprintf(stderr, "setuid(%d): failed. no user switch performed.\n", new_uid);
			}
			if (!strcmp(c,"gid") && *p) {
				new_gid = satoi(p);
				if (su_time == SU_NOW && setgid(new_gid))
					fprintf(stderr, "setgid(%d): failed. no group switch performed.\n", new_gid);
			}
			if (!strcmp(c,"chroot") && *p) {
				if (chroot(p)) {
					perror("chroot");
					fprintf(stderr,"chroot(\"%s\"): failed.\n", p);
				}
			}
			if (!strcmp(c,"umask") && *p)
				umask_value=satoi(p);
#endif
			if (!strcmp(c,"allow") && *p) {
				char **l;
				if (!allowed_ips) {
					allowed_ips = (char**) malloc(sizeof(char*)*128);
					*allowed_ips = 0;
				}
				l = allowed_ips;
				while (*l) l++;
				if (l - allowed_ips >= 127)
					fprintf(stderr, "WARNING: Maximum of allowed IPs (127) exceeded, ignoring 'allow %s'\n", p);
					else {
						*l = strdup(p);
						l++;
						*l = 0;
					}
			}
			if (!strcmp(c, "control") && (p[0] == 'e' || p[0] == 'y' || p[1] == '1'))
				child_control = 1;
			if (!strcmp(c,"workdir"))
				workdir = (*p) ? strdup(p) : 0;
			if (!strcmp(c,"encoding") && *p)
				set_string_encoding(p, 1);
			if (!strcmp(c,"socket"))
				localSocketName = (*p) ? strdup(p) : 0;
			if (!strcmp(c,"sockmod") && *p)
					localSocketMode = satoi(p);
			if (!strcmp(c,"pwdfile"))
				pwdfile = (*p) ? strdup(p) : 0;
			if (!strcmp(c,"auth"))
				authReq=(*p=='1' || *p=='y' || *p=='r' || *p=='e') ? 1 : 0;
			if (!strcmp(c,"interactive"))
				Rsrv_interactive = (*p=='1' || *p=='y' || *p=='t' || *p=='e') ? 1 : 0;
			if (!strcmp(c,"plaintext"))
				usePlain=(*p=='1' || *p=='y' || *p=='e') ? 1 : 0;
			if (!strcmp(c,"fileio"))
				allowIO=(*p=='1' || *p=='y' || *p=='e') ? 1 : 0;
			if (!strcmp(c, "cachepwd"))
				cache_pwd = (*p == 'i') ? 2 : ((*p == '1' || *p == 'y' || *p == 'e') ? 1 : 0);
		}
    fclose(f);
#ifndef HAS_CRYPT
    if (!usePlain) {
		fprintf(stderr,"Warning: useplain=no, but this Rserve has no crypt support!\nSet useplain=yes or compile with crypt support (if your system supports crypt).\nFalling back to plain text password.\n");
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

#ifndef decl_sbthread
#define decl_sbthread void
#endif

/* pid of the last child (not really used ATM) */
static int lastChild;

#ifdef FORKED
static void sigHandler(int i) {
    if (i==SIGTERM || i==SIGHUP)
		active=0;
}

#ifdef RSERV_DEBUG
static void brkHandler(int i) {
    printf("\nCaught break signal, shutting down Rserve.\n");
    active=0;
    /* kill(getpid(), SIGUSR1); */
}
#endif
#endif

/* used for generating salt code (2x random from this array) */
const char *code64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWYXZabcdefghijklmnopqrstuvwxyz";

/** parses a string, stores the number of expressions in parts and the resulting statis in status.
    the returned SEXP may contain multiple expressions */ 
SEXP parseString(char *s, int *parts, ParseStatus *status) {
    int maxParts=1;
    char *c=s;
    SEXP cv, pr = R_NilValue;
    
    while (*c) {
		if (*c=='\n' || *c==';') maxParts++;
		c++;
    }
    
    PROTECT(cv=allocVector(STRSXP, 1));
    SET_STRING_ELT(cv, 0, mkRChar(s));  
    
    while (maxParts>0) {
		pr=RS_ParseVector(cv, maxParts, status);
		if (*status!=PARSE_INCOMPLETE && *status!=PARSE_EOF) break;
		maxParts--;
    }
    UNPROTECT(1);
    *parts=maxParts;
    
    return pr;
}

/** parse a string containing the specified number of expressions */
SEXP parseExps(char *s, int exps, ParseStatus *status) {
    SEXP cv, pr;
    
    PROTECT(cv=allocVector(STRSXP, 1));
    SET_STRING_ELT(cv, 0, mkRChar(s));  
    pr = RS_ParseVector(cv, 1, status);
    UNPROTECT(1);
    return pr;
}

void voidEval(char *cmd) {
    ParseStatus stat;
    int Rerror;
    int j=0;
    SEXP xp=parseString(cmd,&j,&stat);
    
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
		SEXP exp=R_NilValue;
#ifdef RSERV_DEBUG
		printf("R_tryEval(xp,R_GlobalEnv,&Rerror);\n");
#endif
		if (TYPEOF(xp)==EXPRSXP && LENGTH(xp)>0) {
			int bi=0;
			while (bi<LENGTH(xp)) {
				SEXP pxp=VECTOR_ELT(xp, bi);
				Rerror=0;
#ifdef RSERV_DEBUG
				printf("Calling R_tryEval for expression %d [type=%d] ...\n",bi+1,TYPEOF(pxp));
#endif
				exp=R_tryEval(pxp, R_GlobalEnv, &Rerror);
				bi++;
#ifdef RSERV_DEBUG
				printf("Expression %d, error code: %d\n",bi, Rerror);
				if (Rerror) printf(">> early error, aborting further evaluations\n");
#endif
				if (Rerror) break;
			}
		} else {
			Rerror=0;
			exp=R_tryEval(xp, R_GlobalEnv, &Rerror);
		}
		UNPROTECT(1);
    }
    return;
}


struct sockaddr_in session_peer_sa;
SOCKET session_socket;
unsigned char session_key[32];

/* detach session and setup everything such that in can be resumed at some point */
int detach_session(SOCKET s) {
    SAIN ssa;
	int port=32768;
	SOCKET ss=FCF("open socket",socket(AF_INET,SOCK_STREAM,0));
    int reuse=1; /* enable socket address reusage */
	socklen_t sl = sizeof(session_peer_sa);
	struct dsresp {
		int pt1;
		int port;
		int pt2;
		unsigned char key[32];
	} dsr;

	if (getpeername(s, (SA*) &session_peer_sa, &sl)) {
		sendResp(s,SET_STAT(RESP_ERR,ERR_detach_failed));
		return -1;
	}

    setsockopt(ss,SOL_SOCKET,SO_REUSEADDR,(const char*)&reuse,sizeof(reuse));

#ifdef Win32
	while ((port = (((int) rand()) & 0x7fff)+32768)>65000) {};
#else
	while ((port = (((int) random()) & 0x7fff)+32768)>65000) {};
#endif

	while (bind(ss,build_sin(&ssa,0,port),sizeof(ssa))) {
		if (errno!=EADDRINUSE) {
#ifdef RSERV_DEBUG
			printf("session: error in bind other than EADDRINUSE (0x%x)",  errno);
#endif
			closesocket(ss);
			sendResp(s,SET_STAT(RESP_ERR,ERR_detach_failed));
			return -1;
		}
		port++;
		if (port>65530) {
#ifdef RSERV_DEBUG
			printf("session: can't find available prot to listed on.\n");
#endif
			closesocket(ss);
			sendResp(s,SET_STAT(RESP_ERR,ERR_detach_failed));
			return -1;
		}
	}

    if (listen(ss,LISTENQ)) {
#ifdef RSERV_DEBUG
		printf("session: cannot listen.\n");
#endif
		closesocket(ss);
		sendResp(s,SET_STAT(RESP_ERR,ERR_detach_failed));
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
	
	sendRespData(s, RESP_OK, 3*sizeof(int)+32, &dsr);
	closesocket(s);
#ifdef RSERV_DEBUG
	printf("session: detached, closing connection.\n");
#endif
	session_socket=ss;
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
	int   inp;
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

/* working thread/function. the parameter is of the type struct args* */
decl_sbthread newConn(void *thp) {
    SOCKET s;
    struct args *a=(struct args*)thp;
    struct phdr ph;
    char *buf, *c,*cc,*c1,*c2;
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

#ifdef unix
    char wdname[512];
	int cinp[2];
#endif

#ifdef FORKED  

	long rseed = random();
    rseed ^= time(0);
	
	parent_pipe = -1;
	cinp[0] = -1;

	/* we use the input pipe only if child control is enabled. disabled pipe means no registration */
	if (child_control && pipe(cinp) != 0)
		cinp[0] = -1;

    if ((lastChild = fork()) != 0) { /* parent/master part */
		/* close the connection socket - the child has it already */
		closesocket(a->s);
		if (cinp[0] != -1) { /* if we have a valid pipe register the child */
			child_process_t *cp = (child_process_t*) malloc(sizeof(child_process_t));
			close(cinp[1]); /* close the write end which is what the child will be using */
#ifdef RSERV_DEBUG
			printf("child %d was spawned, registering input pipe\n", (int)lastChild);
#endif
			cp->inp = cinp[0];
			cp->pid = lastChild;
			cp->next = children;
			if (children) children->prev = cp;
			cp->prev = 0;
			children = cp;
		}
		free(a); /* release the args */
		return;
    }
	/* child part */
	is_child = 1;
	if (cinp[0] != -1) { /* if we have a vaild pipe to the parent set it up */
		parent_pipe = cinp[1];
		close(cinp[0]);
	}

    srandom(rseed);
    
    parentPID = getppid();
    closesocket(a->ss); /* close server socket */

#ifdef unix
	if (cache_pwd)
		load_pwd_cache();/* load pwd file into memory before su */
	if (su_time == SU_CLIENT) { /* if requested set gid/pid as client */
		if (new_gid != -1) setgid(new_gid);
		if (new_uid != -1) setuid(new_uid);
	}
#endif

#endif
    
    buf = (char*) malloc(inBuf + 8);
    sfbuf = (char*) malloc(sfbufSize);
    if (!buf || !sfbuf) {
		fprintf(stderr,"FATAL: cannot allocate initial buffers. closing client connection.\n");
		s = a->s;
		free(a);
		closesocket(s);
		return;
    }
    memset(buf, 0, inBuf + 8);

#ifdef unix
    if (workdir) {
		if (chdir(workdir))
			mkdir(workdir,0777);
		wdname[511]=0;
		snprintf(wdname,511,"%s/conn%d",workdir,a->ucix);
		mkdir(wdname,0777);
		chdir(wdname);
    }
#endif
	
    sendBufSize = sndBS;
    sendbuf = (char*) malloc(sendBufSize);
#ifdef RSERV_DEBUG
    printf("connection accepted.\n");
#endif
    s=a->s;
    free(a);
    
#ifndef THREADED /* in all but threaded environments we can keep the
					current socket globally for R-error handler */
    csock=s;
#endif
    
#ifdef CAN_TCP_NODELAY
    {
		int opt=1;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*) &opt, sizeof(opt));
    }
#endif
    
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
#ifdef RSERV_DEBUG
    printf("sending ID string.\n");
#endif
    send(s, (char*)buf, 32, 0);
	
	can_control = 0;
	if (!authReq && !pwdfile) /* control is allowed by default only if authentication is not required and passwd is not present. In all other cases it will be set during authentication. */
		can_control = 1;

    while((rn = recv(s, (char*)&ph, sizeof(ph), 0)) == sizeof(ph)) {
		size_t plen = 0;
		SEXP pp = R_NilValue; /* packet payload (as a raw vector) for special commands */
#ifdef RSERV_DEBUG
		printf("\nheader read result: %d\n", rn);
		if (rn > 0) printDump(&ph, rn);
#endif
		ph.len = ptoi(ph.len);
		ph.cmd = ptoi(ph.cmd);
		ph.dof = ptoi(ph.dof);
#ifdef __LP64__
		ph.res = ptoi(ph.res);
		plen = (unsigned int) ph.len;
		plen |= (((size_t) (unsigned int) ph.res) << 32);
#else
		plen = ph.len;
#endif
		process = 0;
		pars = 0;

		if ((ph.cmd & CMD_SPECIAL_MASK) == CMD_SPECIAL_MASK) {
			/* this is a very special case - we load the packet payload into a raw vector directly to prevent unnecessaru copying */
			pp = allocVector(RAWSXP, plen);
			char *pbuf = (char*) RAW(pp);
			size_t i = 0;
#ifdef RSERV_DEBUG
			printf("loading (raw) buffer (awaiting %d bytes)\n", (int)plen);
#endif
			while((rn = recv(s, pbuf + i, (plen - i > max_sio_chunk) ? max_sio_chunk : (plen - i), 0))) {
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
						sendResp(s,SET_STAT(RESP_ERR,ERR_out_of_mem));
						free(sendbuf); free(sfbuf);
						closesocket(s);
						return;
					}	    
				}
#ifdef RSERV_DEBUG
				printf("loading buffer (awaiting %ld bytes)\n",(long) plen);
#endif
				i = 0;
				while ((rn = recv(s, ((char*)buf) + i, (plen - i > max_sio_chunk) ? max_sio_chunk : (plen - i), 0))) {
					if (rn > 0) i += rn;
					if (i >= plen || rn < 1) break;
				}
				if (i < plen) break;
				memset(buf + plen, 0, 8);
		
				unaligned = 0;
#ifdef RSERV_DEBUG
				printf("parsing parameters (buf=%p, len=%ld)\n", buf, (long) plen);
				if (plen > 0) printDump(buf,plen);
#endif
				c = buf + ph.dof;
				while((c < buf + ph.dof + plen) && (phead = ptoi(*((unsigned int*)c)))) {
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
						sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
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
				printf("discarding buffer because too big (awaiting %ld bytes)\n", (long)plen);
				size_t i = plen, chk = (inBuf < max_sio_chunk) ? inBuf : max_sio_chunk;
				while((rn = recv(s, (char*)buf, (i < chk) ? i : chk, 0))) {
					if (rn > 0) i -= rn;
					if (i < 1 || rn < 1) break;
				}
				if (i > 0) break;
				/* if the pars are bigger than my buffer, send data_overflow response
				   (since 1.23/0.1-6; was inv_par before) */
				sendResp(s, SET_STAT(RESP_ERR, ERR_data_overflow));
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

		if (!authed && ph.cmd==CMD_login) {
			if (pars < 1 || parT[0] != DT_STRING) 
				sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				c = (char*)parP[0];
				cc = c;
				while(*cc && *cc != '\n') cc++;
				if (*cc) { *cc = 0; cc++; };
				c1 = cc;
				while(*c1) if(*c1 == '\n' || *c1 == '\r') *c1=0; else c1++;
				/* c=login, cc=pwd */
				authed = 1;
#ifdef RSERV_DEBUG
				printf("Authentication attempt (login='%s',pwd='%s',pwdfile='%s')\n",c, cc, pwdfile);
#endif
				if (pwdfile) {
					pwdf_t *pwf;
					int ctrl_flag = 0;
					authed = 0; /* if pwdfile exists, default is access denied */
					/* TODO: opening pwd file, parsing it and responding
					   might be a bad idea, since it allows DOS attacks as this
					   operation is fairly costly. We should actually cache
					   the user list and reload it only on HUP or something. */
					/* we abuse variables of other commands since we are
					   the first command ever used so we can trash them */
					pwf = pwd_open();
					if (pwf) {
						sfbuf[sfbufSize - 1] = 0;
						while(!pwd_eof(pwf))
							if (pwd_gets(sfbuf, sfbufSize - 1, pwf)) {
								c1 = sfbuf;
								while(*c1 && *c1 != ' ' && *c1 != '\t') c1++;
								if (*c1) {
									*c1 = 0;
									c1++;
									while(*c1 == ' ' || *c1 == '\t') c1++;
								}
								c2 = c1;
								while(*c2) if (*c2 == '\r' || *c2=='\n') *c2 = 0; else c2++;
								ctrl_flag = 0;
								if (*c == '@') { /* only users with @ prefix can use control commands */
									c++;
									ctrl_flag = 1;
								}
								if (*c == '*') { /* general authentication - useful to set control access but leave client access open */
									authed = 1;
#ifdef RSERV_DEBUG
									printf("Public authentication enabled (found * entry), allowing login without checking.\n");
#endif
									break;
								}
								if (!strcmp(sfbuf,c)) { /* login found */
#ifdef RSERV_DEBUG
									printf("Found login '%s', checking password.\n", c);
#endif
									if (usePlain && !strcmp(c1,cc)) {
										authed=1;
#ifdef RSERV_DEBUG
										puts(" - plain pasword matches.");
#endif
									} else {
#ifdef HAS_CRYPT
										c2=crypt(c1,salt+1);
#ifdef RSERV_DEBUG
										printf(" - checking crypted '%s' vs '%s'\n", c2, cc);
#endif
										if (!strcmp(c2,cc)) authed=1;
#endif
									}
#ifdef DEBUG_RSERV
									printf(" - authentication %s\n",(authed)?"succeeded":"failed");
#endif
								}
								if (authed) break;
							} /* if fgets */
						pwd_close(pwf);
					} /* if (pwf) */
					cf = 0;
					if (authed) {
						can_control = ctrl_flag;
						process=1;
						sendResp(s,RESP_OK);
					}
				}
			}
		}

		/* if not authed by now, close connection */
		if (authReq && !authed) {
			sendResp(s, SET_STAT(RESP_ERR, ERR_auth_failed));
			closesocket(s);
			free(sendbuf); free(sfbuf); free(buf);
			return;
		}

		if (ph.cmd==CMD_shutdown) { /* FIXME: now that we have control commands we may rethink this ... */
			sendResp(s,RESP_OK);
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
			printf("control command: %s [can control: %s, pipe: %d]\n", (ph.cmd == CMD_ctrlEval) ? "eval" : ((ph.cmd == CMD_ctrlSource) ? "source" : "shutdown"), can_control ? "yes" : "no", parent_pipe);
#endif
			if (!can_control) /* no right to do this */
				sendResp(s, SET_STAT(RESP_ERR, ERR_accessDenied));
			else {
				/* source and eval require a parameter */
				if ((ph.cmd == CMD_ctrlEval || ph.cmd == CMD_ctrlSource) && (pars < 1 || parT[0] != DT_STRING))
					sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
				else {
					if (parent_pipe == -1)
						sendResp(s, SET_STAT(RESP_ERR, ERR_ctrl_closed));
					else {
						long cmd[2] = { 0, 0 };
						if (ph.cmd == CMD_ctrlEval) { cmd[0] = CCTL_EVAL; cmd[1] = strlen(parP[0]) + 1; }
						else if (ph.cmd == CMD_ctrlSource) { cmd[0] = CCTL_SOURCE; cmd[1] = strlen(parP[0]) + 1; }
						else cmd[0] = CCTL_SHUTDOWN;
						if (write(parent_pipe, cmd, sizeof(cmd)) != sizeof(cmd)) {
#ifdef RSERV_DEBUG
							printf(" - send to parent pipe (cmd=%ld, len=%ld) failed, closing parent pipe\n", cmd[0], cmd[1]);
#endif
							close(parent_pipe);
							parent_pipe = -1;
							sendResp(s, SET_STAT(RESP_ERR, ERR_ctrl_closed));
						} else {
							if (cmd[1] && write(parent_pipe, parP[0], cmd[1]) != cmd[1]) {
#ifdef RSERV_DEBUG
								printf(" - send to parent pipe (cmd=%ld, len=%ld, sending data) failed, closing parent pipe\n", cmd[0], cmd[1]);
#endif
								close(parent_pipe);
								parent_pipe = 01;
								sendResp(s, SET_STAT(RESP_ERR, ERR_ctrl_closed));
							} else
								sendResp(s, RESP_OK);
						}
					}
				}
			}
		}

		if (ph.cmd == CMD_setEncoding) { /* set string encoding */
			process = 1;
			if (pars<1 || parT[0] != DT_STRING) 
				sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
			else {
				char *c = (char*) parP[0];
#ifdef RSERV_DEBUG
				printf(">>CMD_setEncoding '%s'.\n", c ? c : "<null>");
#endif
#ifdef USE_ENCODING
				if (c && set_string_encoding(c, 0))
					sendResp(s, RESP_OK);
				else
					sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
#else
				sendResp(s, SET_STAT(RESP_ERR, ERR_unsupportedCmd));
#endif
			}
		}

		if (ph.cmd == CMD_setBufferSize) {
			process = 1;
			/* FIXME: configuration allows 64-bit numbers but CMD_setBufferSize does not */
			if (pars < 1 || parT[0] != DT_INT) 
				sendResp(s,SET_STAT(RESP_ERR, ERR_inv_par));
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
						sendResp(s,SET_STAT(RESP_ERR, ERR_out_of_mem));
						free(buf); free(sfbuf);
						closesocket(s);
						return;
					}
					sendBufSize = ns;
				}
				sendResp(s, RESP_OK);
			}
		}

		if (ph.cmd==CMD_openFile||ph.cmd==CMD_createFile) {
			process=1;
			if (!allowIO) sendResp(s,SET_STAT(RESP_ERR,ERR_accessDenied));
			else {
				if (pars<1 || parT[0]!=DT_STRING) 
					sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
				else {
					c=(char*)(parP[0]);
					if (cf) fclose(cf);
#ifdef RSERV_DEBUG
					printf(">>CMD_open/createFile(%s)\n",c);
#endif
					cf=fopen(c,(ph.cmd==CMD_openFile)?"rb":"wb");
					if (!cf)
						sendResp(s,SET_STAT(RESP_ERR,ERR_IOerror));
					else
						sendResp(s,RESP_OK);
				}
			}
		}
	
		if (ph.cmd==CMD_removeFile) {
			process=1;
			if (!allowIO) sendResp(s,SET_STAT(RESP_ERR,ERR_accessDenied));
			else {
				if (pars<1 || parT[0]!=DT_STRING) 
					sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
				else {
					c=(char*)parP[0];
#ifdef RSERV_DEBUG
					printf(">>CMD_removeFile(%s)\n",c);
#endif
					if (remove(c))
						sendResp(s,SET_STAT(RESP_ERR,ERR_IOerror));
					else
						sendResp(s,RESP_OK);
				}
			}
		}
	
		if (ph.cmd==CMD_closeFile) {
			process=1;
			if (!allowIO) sendResp(s,SET_STAT(RESP_ERR,ERR_accessDenied));
			else {
				if (cf) fclose(cf);
#ifdef RSERV_DEBUG
				printf(">>CMD_closeFile\n");
#endif
				cf=0;
				sendResp(s,RESP_OK);
			}
		}
	
		if (ph.cmd==CMD_readFile) {
			process=1;
			if (!allowIO) sendResp(s,SET_STAT(RESP_ERR,ERR_accessDenied));
			else {
				if (!cf)
					sendResp(s,SET_STAT(RESP_ERR,ERR_notOpen));
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
						sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
					else {
						size_t i = fread(fbuf, 1, fbufl, cf);
						if (i > 0)
							sendRespData(s, RESP_OK, i, fbuf);
						else
							sendResp(s, RESP_OK);
						if (fbuf != sfbuf)
							free(fbuf);
					}
				}
			}
		}
	
		if (ph.cmd==CMD_writeFile) {
			process=1;
			if (!allowIO) sendResp(s,SET_STAT(RESP_ERR,ERR_accessDenied));
			else {
				if (!cf)
					sendResp(s,SET_STAT(RESP_ERR,ERR_notOpen));
				else {
					if (pars<1 || parT[0]!=DT_BYTESTREAM)
						sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
					else {
						size_t i = 0;
#ifdef RSERV_DEBUG
						printf(">>CMD_writeFile(%ld,...)\n", (long) parL[0]);
#endif
						c = (char*)parP[0];
						if (parL[0] > 0)
							i = fwrite(c, 1, parL[0], cf);
						if (i > 0 && i != parL[0])
							sendResp(s, SET_STAT(RESP_ERR, ERR_IOerror));
						else
							sendResp(s,RESP_OK);
					}
				}
			}
		}
	
		/*--- CMD_setSEXP / CMD_assignSEXP ---*/
	
		if (ph.cmd==CMD_setSEXP || ph.cmd==CMD_assignSEXP) {
			process=1;
			if (pars<2 || parT[0]!=DT_STRING) 
				sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
			else {
				SEXP val, sym=0;
				unsigned int *sptr;
				int parType=parT[1];
				int globalUPC=0;
				int boffs=0;
		
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
						sendResp(s,SET_STAT(RESP_ERR,stat));
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
					sendResp(s,RESP_OK);
					break;
				case DT_SEXP|DT_LARGE:
					boffs = 1; /* we're not using the size, so in fact we just
								advance the pointer and don't care about the length */
				case DT_SEXP:
					sptr = ((unsigned int*)parP[1]) + boffs;
					val = decode_to_SEXP(&sptr, &globalUPC);
					if (val == 0)
						sendResp(s,SET_STAT(RESP_ERR, ERR_inv_par));
					else {
#ifdef RSERV_DEBUG
						printf("  assigning SEXP: ");
						printSEXP(val);
#endif
						defineVar(sym ? sym : install(c), val, R_GlobalEnv);
						sendResp(s, RESP_OK);
					}
					if (globalUPC>0) UNPROTECT(globalUPC);
					break;
				default:
					sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
				}
			}
		}
	
		if (ph.cmd==CMD_detachSession) {
			process=1;
			if (!detach_session(s)) {
				s=resume_session();
				sendResp(s,RESP_OK);
			}
		}
		
		if (ph.cmd==CMD_serEval || ph.cmd==CMD_serEEval || ph.cmd == CMD_serAssign) {
			int Rerr = 0;
			SEXP us = R_tryEval(LCONS(install("unserialize"),CONS(pp,R_NilValue)), R_GlobalEnv, &Rerr);
			PROTECT(us);
			process = 1;
			if (Rerr == 0) {
				if (ph.cmd == CMD_serAssign) {
					if (TYPEOF(us) != VECSXP || LENGTH(us) < 2) {
						sendResp(s, SET_STAT(RESP_ERR, ERR_inv_par));
					} else {
						R_tryEval(LCONS(install("<-"),CONS(VECTOR_ELT(us, 0), CONS(VECTOR_ELT(us, 1), R_NilValue))), R_GlobalEnv, &Rerr);
						if (Rerr == 0)
							sendResp(s, RESP_OK);
						else
							sendResp(s, SET_STAT(RESP_ERR, Rerr));
					}
				} else {
					SEXP ev = R_tryEval(us, R_GlobalEnv, &Rerr);
					if (Rerr == 0 && ph.cmd == CMD_serEEval) /* one more round */
						ev = R_tryEval(ev, R_GlobalEnv, &Rerr);
					PROTECT(ev);
					if (Rerr == 0) {
						SEXP sr = R_tryEval(LCONS(install("serialize"),CONS(ev, CONS(R_NilValue, R_NilValue))), R_GlobalEnv, &Rerr);
						if (Rerr == 0 && TYPEOF(sr) == RAWSXP) {
							sendRespData(s, RESP_OK, LENGTH(sr), RAW(sr));
						} else if (Rerr == 0) Rerr = -2;
					}
					UNPROTECT(1);
				}
				UNPROTECT(1);
				if (Rerr) {
					sendResp(s, SET_STAT(RESP_ERR, Rerr));
				}
			}
		}

		if (ph.cmd==CMD_voidEval || ph.cmd==CMD_eval || ph.cmd==CMD_detachedVoidEval) {
			process=1;
			if (pars<1 || parT[0]!=DT_STRING) 
				sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
			else {
				int j = 0;
				c=(char*)parP[0];
#ifdef RSERV_DEBUG
				printf("parseString(\"%s\")\n",c);
#endif
				xp=parseString(c, &j, &stat);
				PROTECT(xp);
#ifdef RSERV_DEBUG
				printf("buffer parsed, stat=%d, parts=%d\n", stat, j);
				if (xp)
					printf("result type: %d, length: %d\n",TYPEOF(xp),LENGTH(xp));
				else
					printf("result is <null>\n");
#endif				
				if (stat==1 && ph.cmd==CMD_detachedVoidEval && detach_session(s))
					sendResp(s,SET_STAT(RESP_ERR,ERR_detach_failed));
				else if (stat!=1)
					sendResp(s,SET_STAT(RESP_ERR,stat));
				else {
#ifdef RSERV_DEBUG
					printf("R_tryEval(xp,R_GlobalEnv,&Rerror);\n");
#endif
					if (ph.cmd==CMD_detachedVoidEval)
						s=-1;
					exp=R_NilValue;
					if (TYPEOF(xp)==EXPRSXP && LENGTH(xp)>0) {
						int bi=0;
						while (bi<LENGTH(xp)) {
							SEXP pxp=VECTOR_ELT(xp, bi);
							Rerror=0;
#ifdef RSERV_DEBUG
							printf("Calling R_tryEval for expression %d [type=%d] ...\n",bi+1,TYPEOF(pxp));
#endif
							exp=R_tryEval(pxp, R_GlobalEnv, &Rerror);
							bi++;
#ifdef RSERV_DEBUG
							printf("Expression %d, error code: %d\n",bi, Rerror);
							if (Rerror) printf(">> early error, aborting further evaluations\n");
#endif
							if (Rerror) break;
						}
					} else {
						Rerror=0;
						exp=R_tryEval(xp, R_GlobalEnv, &Rerror);
					}
					PROTECT(exp);
#ifdef RSERV_DEBUG
					printf("expression(s) evaluated (Rerror=%d).\n",Rerror);
					if (!Rerror) printSEXP(exp);
#endif
					if (ph.cmd==CMD_detachedVoidEval && s==-1)
						s=resume_session();
					if (Rerror) {
						sendResp(s,SET_STAT(RESP_ERR,(Rerror<0)?Rerror:-Rerror));
					} else {
						if (ph.cmd==CMD_voidEval || ph.cmd==CMD_detachedVoidEval)
							sendResp(s,RESP_OK);
						else {
							char *sendhead = 0;
							int canProceed = 1;
							/* check buffer size vs REXP size to avoid dangerous overflows
							   todo: resize the buffer as necessary
							*/
							rlen_t rs = getStorageSize(exp);
							/* increase the buffer by 25% for safety */
							/* FIXME: there are issues with multi-byte strings that expand when
							   converted. They should be convered by this margin but it is an ugly hack!! */
							rs += (rs >> 2);
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
									sendRespData(s,SET_STAT(RESP_ERR,ERR_object_too_big), 4, &osz);
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
											sendResp(s,SET_STAT(RESP_ERR,ERR_out_of_mem));
											free(buf); free(sfbuf);
											closesocket(s);
											return;
										} else {
											unsigned int osz = (rs > 0xffffffff) ? 0xffffffff : rs;
											osz = itop(osz);
#ifdef RSERV_DEBUG
											printf("ERROR: object too big (sendBuf=%ld) and couldn't allocate big enough send buffer\n", sendBufSize);
#endif
											sendRespData(s,SET_STAT(RESP_ERR,ERR_object_too_big), 4, &osz);
										}
									} else canProceed = 1;
								}
							}
							if (canProceed) {
								/* if this is defined then the old (<=0.1-9) "broken" behavior is requested where no data type header is sent */
#ifdef FORCE_V0100 
								tail = (char*)storeSEXP((unsigned int*)sendbuf, exp, rs);
								sendhead = sendbuf;
#else
								/* first we have 4 bytes of a header saying this is an encoded SEXP, then comes the SEXP */
								char *sxh = sendbuf + 8;
								tail = (char*)storeSEXP((unsigned int*)sxh, exp, rs);

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
#endif
#ifdef RSERV_DEBUG
								printf("stored SEXP; length=%ld (incl. DT_SEXP header)\n",(long) (tail - sendhead));
#endif
								sendRespData(s, RESP_OK, tail - sendhead, sendhead);
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
										sendResp(s, SET_STAT(RESP_ERR, ERR_out_of_mem));
										free(buf); free(sfbuf);
										closesocket(s);
										return;		    
									}
								}
							}
						}
						UNPROTECT(1); /* exp */
					}
					UNPROTECT(1); /* xp */
				}
#ifdef RSERV_DEBUG
				printf("reply sent.\n");
#endif
			}
		}
    respSt:

		if (s == -1) { rn = 0; break; }

		if (!process)
			sendResp(s,SET_STAT(RESP_ERR,ERR_inv_cmd));
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
		sendResp(s, SET_STAT(RESP_ERR, ERR_conn_broken));
    closesocket(s);
    free(sendbuf); free(sfbuf); free(buf);
#ifdef unix
    if (workdir) {
		chdir(workdir);
		rmdir(wdname);
    }
#endif
    
#ifdef RSERV_DEBUG
    printf("done.\n");
#endif
#ifdef FORKED
    /* we should not return to the main loop, but terminate instead */
    exit(0);
#endif
}

void serverLoop() {
    SAIN ssa;
    socklen_t al;
    int reuse;
    struct args *sa;
    struct sockaddr_in lsa;
    
#ifdef unix
    struct sockaddr_un lusa;
    struct timeval timv;
    int selRet=0;
    fd_set readfds;
#endif
    
    lsa.sin_addr.s_addr=inet_addr("127.0.0.1");
    
#ifdef FORKED
    signal(SIGHUP,sigHandler);
    signal(SIGTERM,sigHandler);
#ifdef RSERV_DEBUG
    signal(SIGINT,brkHandler);
#endif
#endif
    
    initsocks();
    if (localSocketName) {
#ifndef unix
		fprintf(stderr,"Local sockets are not supported on non-unix systems.\n");
		return;
#else
		ss=FCF("open socket",socket(AF_LOCAL,SOCK_STREAM,0));
		memset(&lusa,0,sizeof(lusa));
		lusa.sun_family=AF_LOCAL;
		if (strlen(localSocketName)>sizeof(lusa.sun_path)-2) {
			fprintf(stderr,"Local socket name is too long for this system.\n");
			return;
		}
		strcpy(lusa.sun_path,localSocketName);
		remove(localSocketName); /* remove existing if possible */
#endif
	} else
		ss=FCF("open socket",socket(AF_INET,SOCK_STREAM,0));
    reuse=1; /* enable socket address reusage */
    setsockopt(ss,SOL_SOCKET,SO_REUSEADDR,(const char*)&reuse,sizeof(reuse));
#ifdef unix
    if (localSocketName) {
		FCF("bind",bind(ss,(SA*) &lusa, sizeof(lusa)));    
		if (localSocketMode)
			chmod(localSocketName, localSocketMode);
	} else
#endif
		FCF("bind",bind(ss,build_sin(&ssa,0,port),sizeof(ssa)));
    
    FCF("listen",listen(ss,LISTENQ));
    while(active) { /* main serving loop */
#ifdef unix
		int maxfd = ss;
#ifdef FORKED
		while (waitpid(-1,0,WNOHANG)>0);
#endif
		/* 500ms (used to be 10ms) - it shouldn't really matter since
		   it's ok for us to sleep -- the timeout will only influence
		   how often we collect terminated children and (maybe) how
		   quickly we react to shutdown */
		timv.tv_sec=0; timv.tv_usec=500000;
		FD_ZERO(&readfds);
		FD_SET(ss, &readfds);
		if (children) {
			child_process_t *cp = children;
			while (cp) {
				FD_SET(cp->inp, &readfds);
				if (cp->inp > maxfd) maxfd = cp->inp;
				cp = cp->next;
			}
		}
		selRet = select(maxfd + 1, &readfds, 0, 0, &timv);
		if (selRet > 0 && FD_ISSET(ss,&readfds)) {
#endif
			sa=(struct args*)malloc(sizeof(struct args));
			memset(sa,0,sizeof(struct args));
			al=sizeof(sa->sa);
#ifdef unix
			if (localSocketName) {
				al=sizeof(sa->su);
				sa->s=CF("accept",accept(ss,(SA*)&(sa->su),&al));
			} else
#endif
				sa->s=CF("accept",accept(ss,(SA*)&(sa->sa),&al));
			sa->ucix=UCIX++;
			sa->ss=ss;
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
			if (localonly && !localSocketName) {
				char **laddr=allowed_ips;
				int allowed=0;
				if (!laddr) { 
					allowed_ips = (char**) malloc(sizeof(char*)*2);
					allowed_ips[0] = strdup("127.0.0.1");
					allowed_ips[1] = 0;
					laddr=allowed_ips;
				}
				while (*laddr) if (sa->sa.sin_addr.s_addr==inet_addr(*(laddr++))) { allowed=1; break; };
				if (allowed) {
#ifdef THREADED
					sbthread_create(newConn,sa);
#else
				newConn(sa);
#ifdef FORKED
				/* when the child returns it means it's done (likely an error)
				   but it is forked, so the only right thing to do is to exit */
				if (is_child)
					exit(2);
#endif
#endif
				} else
					closesocket(sa->s);
			} else { /* ---> remote enabled */
#ifdef THREADED
				sbthread_create(newConn,sa); 
#else
				newConn(sa);
				if (is_child) /* same as above */
					exit(2);
			}
#endif
#ifdef unix
		} else if (selRet > 0 && children) { /* one of the children signalled */
			child_process_t *cp = children;
			while (cp) {
				if (FD_ISSET(cp->inp, &readfds)) {
					long cmd[2];
					int n = read(cp->inp, cmd, sizeof(cmd));
					if (n < sizeof(cmd)) { /* is anything less arrives, assume corruption and remove the child */
						child_process_t *ncp = cp->next;
#ifdef RSERV_DEBUG
						printf("pipe to child %d closed (n=%d), removing child\n", (int) cp->pid, n);
#endif
						close(cp->inp);
						/* remove the child from the list */
						if (cp->prev) cp->prev->next = ncp; else children = ncp;
						if (ncp) ncp->prev = cp->prev;
						free(cp);
						cp = ncp;
					} else { /* we got a valid command */
						/* FIXME: we should perform more rigorous checks on the protocol - we are currently ignoring anything bad */
						char cib[256];
						char *xb = 0;
#ifdef RSERV_DEBUG
						printf(" command from child %d: %ld data bytes: %ld\n", (int) cp->pid, cmd[0], cmd[1]);
#endif
						cib[0] = 0;
						cib[255] = 0;
						n = 0;
						if (cmd[1] > 0 && cmd[1] < 256)
							n = read(cp->inp, cib, cmd[1]);
						else if (cmd[1] > 0 && cmd[1] < MAX_CTRL_DATA) {
							xb = (char*) malloc(cmd[1] + 4);
							xb[0] = 0;
							if (xb)
								n = read(cp->inp, xb, cmd[1]);
							if (n > 0)
								xb[n] = 0;
						}
#ifdef RSERV_DEBUG
						printf(" - read %d bytes of %ld data from child %d\n", n, cmd[1], (int) cp->pid);
#endif
						if (n == cmd[1]) { /* perform commands only if we got all the data */
							if (cmd[0] == CCTL_EVAL) {
#ifdef RSERV_DEBUG
								printf(" - control calling voidEval(\"%s\")\n", xb ? xb : cib);
#endif
								voidEval(xb ? xb : cib);
							} else if (cmd[0] == CCTL_SOURCE) {
								int evalRes = 0;
								SEXP exp;
								SEXP sfn = PROTECT(allocVector(STRSXP, 1));
								SET_STRING_ELT(sfn, 0, mkRChar(xb ? xb : cib));
								exp = LCONS(install("source"), CONS(sfn, R_NilValue));
#ifdef RSERV_DEBUG
								printf(" - control calling source(\"%s\")\n", xb ? xb : cib);
#endif
								R_tryEval(exp, R_GlobalEnv, &evalRes);
#ifdef RSERV_DEBUG
								printf(" - result: %d\n", evalRes);
#endif
								UNPROTECT(1);								
							} else if (cmd[0] == CCTL_SHUTDOWN) {
#ifdef RSERV_DEBUG
								printf(" - shutdown via control, setting active to 0\n");
#endif
								active = 0;
							}
						}
						cp = cp->next;
					}
				} else
					cp = cp->next;
			}
		}
#endif
    }
}

extern int Rf_initEmbeddedR(int, char**);

/* main function - start Rserve */
int main(int argc, char **argv)
{
    int stat,i;    
	rserve_rev[0]=0;
	{ /* cut out the SVN revision from the Id string */
		const char *c = strstr(rserve_ver_id, ".c ");
		if (c) {
			const char *d = c + 3;
			c = d; while (*c && *c != ' ') c++;
			strncpy(rserve_rev, d, c - d);
		}
	}

#ifdef RSERV_DEBUG
    printf("Rserve %d.%d-%d (%s) (C)Copyright 2002-2011 Simon Urbanek\n%s\n\n",RSRV_VER>>16,(RSRV_VER>>8)&255,RSRV_VER&255, rserve_rev, rserve_ver_id);
#endif
    if (!isByteSexOk()) {
		printf("FATAL ERROR: This program was not correctly compiled - the endianess is wrong!\nUse -DSWAPEND when compiling on PPC or similar platforms.\n");
		return -100;
    }
    
    loadConfig(CONFIG_FILE);
    
    /** copy argv while removing Rserve specific parameters */
    top_argc=1;
    top_argv=(char**) malloc(sizeof(char*)*(argc+1));
    top_argv[0]=argv[0];
    i=1;
    while (i<argc) {
		int isRSP=0;
		if (argv[i] && *argv[i]=='-' && argv[i][1]=='-') {
			if (!strcmp(argv[i]+2,"RS-port")) {
				isRSP=1;
				if (i+1==argc)
					fprintf(stderr,"Missing port specification for --RS-port.\n");
				else {
					port=satoi(argv[++i]);
					if (port<1) {
						fprintf(stderr,"Invalid port number in --RS-port, using default port.\n");
						port=default_Rsrv_port;
					}
				}
			}
			if (!strcmp(argv[i]+2,"RS-dumplimit")) {
				isRSP=1;
				if (i+1==argc)
					fprintf(stderr,"Missing limit specification for --RS-dumplimit.\n");
				else
					dumpLimit=satoi(argv[++i]);
			}
			if (!strcmp(argv[i]+2,"RS-socket")) {
				isRSP=1;
				if (i+1==argc)
					fprintf(stderr,"Missing socket specification for --RS-socket.\n");
				else
					localSocketName=argv[++i];
			}
			if (!strcmp(argv[i]+2, "RS-encoding")) {
				isRSP = 1;
				if (i + 1 == argc)
					fprintf(stderr,"Missing socket specification for --RS-encoding.\n");
				else
					set_string_encoding(argv[++i], 1);
			}
			if (!strcmp(argv[i]+2,"RS-workdir")) {
				isRSP=1;
				if (i+1==argc)
					fprintf(stderr,"Missing directory specification for --RS-workdir.\n");
				else
					workdir=argv[++i];
			}
			if (!strcmp(argv[i]+2,"RS-conf")) {
				isRSP=1;
				if (i+1==argc)
					fprintf(stderr,"Missing config file specification for --RS-conf.\n");
				else
					loadConfig(argv[++i]);
			}
			if (!strcmp(argv[i]+2,"RS-settings")) {
				printf("Rserve v%d.%d-%d\n\nconfig file: %s\nworking root: %s\nport: %d\nlocal socket: %s\nauthorization required: %s\nplain text password: %s\npasswords file: %s\nallow I/O: %s\nallow remote access: %s\ncontrol commands: %s\ninteractive: %s\nmax.input buffer size: %ld kB\n\n",
					   RSRV_VER>>16, (RSRV_VER>>8)&255, RSRV_VER&255,
					   CONFIG_FILE, workdir, port, localSocketName ? localSocketName : "[none, TCP/IP used]",
					   authReq ? "yes" : "no", usePlain ? "allowed" : "not allowed", pwdfile ? pwdfile : "[none]",
					   allowIO ? "yes" : "no", localonly ? "no" : "yes",
					   child_control ? "yes" : "no", Rsrv_interactive ? "yes" : "no", maxInBuf / 1024L);
				return 0;	       
			}
			if (!strcmp(argv[i]+2,"version")) {
				printf("Rserve v%d.%d-%d (%s)\n",RSRV_VER>>16,(RSRV_VER>>8)&255,RSRV_VER&255,rserve_rev);
			}
			if (!strcmp(argv[i]+2,"help")) {
				printf("Usage: R CMD Rserve [<options>]\n\nOptions: --help  this help screen\n --version  prints Rserve version (also passed to R)\n --RS-port <port> listen on the specified TCP port\n --RS-socket <socket> use specified local (unix) socket instead of TCP/IP.\n --RS-workdir <path> use specified working directory root for connections.\n --RS-encoding <enc> set default server string encoding to <enc>.\n --RS-conf <file> load additional config file.\n --RS-settings  dumps current settings of the Rserve\n\nAll other options are passed to the R engine.\n\n");
#ifdef RSERV_DEBUG
				printf("debugging flag:\n --RS-dumplimit <number>  sets limit of items/bytes to dump in debugging output. set to 0 for unlimited\n\n");
#endif
				return 0;
			}
		}
		if (!isRSP)
			top_argv[top_argc++]=argv[i];
		i++;
    }

#if R_VERSION >= R_Version(2,5,0)
	R_SignalHandlers = 0; /* disable signal handlers */
#endif

    stat=Rf_initEmbeddedR(top_argc,top_argv);
    if (stat<0) {
		printf("Failed to initialize embedded R! (stat=%d)\n",stat);
		return -1;
    }
#ifndef WIN32
	/* windows uses this in init, unix doesn't so we set it here */
	R_Interactive = Rsrv_interactive;
#endif

    if (src_list) { /* do any sourcing if necessary */
		struct source_entry *se=src_list;
#ifdef RSERV_DEBUG
		printf("Executing source/eval commands from the config file.\n");
#endif
		while (se) {
#ifdef RSERV_DEBUG
			printf("voidEval(\"%s\")\n", se->line);
#endif
			voidEval(se->line);
			se=se->next;
		}
#ifdef RSERV_DEBUG
		printf("Done with initial commands.\n");
#endif
    }
	
#ifdef unix
	/* if server su is enabled, do it now */
	if (su_time == SU_SERVER) {
		if (new_gid != -1) setgid(new_gid);
		if (new_uid != -1) setuid(new_uid);
	}
#endif
	
#if defined RSERV_DEBUG || defined Win32
    printf("Rserve: Ok, ready to answer queries.\n");
#endif      
    
#if defined DAEMON && defined unix
    /* ok, we're in unix, so let's daemonize properly */
    if (fork()!=0) {
		puts("Rserv started in daemon mode.");
		exit(0);
    }
    
    setsid();
    chdir("/");
#endif
#ifdef unix
    umask(umask_value);
#endif
    
    serverLoop();
#ifdef unix
    if (localSocketName)
		remove(localSocketName);
#endif
    
#ifdef RSERV_DEBUG
    printf("\nServer terminated normally.\n");
#endif
    return 0;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
