/*
 *  Rserv : R-server that allows to use embedded R via TCP/IP
 *          currently based on R-1.5.1 API (tested up to R-devel 1.7.0)
 *  Copyright (C) 2002,3 Simon Urbanek
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

   DAEMON      - if defined the server daemonizes (unix only)

   CONFIG_FILE - location of the config file (default /etc/Rserv.conf)
*/

/* config file entries: [default]
  ----------------------
   workdir <path> [depends on the CONFIG_FILE define]
   pwdfile <file> [none=disabled]
   remote enable|disable [disable]
   auth required|disable [disable]
   plaintext enable|disable [disable] (strongly discouraged to enable)
   fileio enable|disable [enable]

   A note about security: Anyone with access to R has access to the shell
   via "system" command, so you should consider following rules:
   - NEVER EVER run Rserv as root - this compromises the box totally
   - use "remote disable" whenever you don't need remote access.
   - if you need remote access use "auth required" and "plaintext disable"
     consider also that anyone with the access can decipher other's passwords
     if he knows how to. the authentication prevents hackers from the net
     to break into Rserv, but it doesn't (and cannot) protect from
     inside attacks (since R has no security measures).
     You should also use a special, restricted user for running Rserv
     as a public server, so noone can try to hack the box it runs on.
   - don't enable plaintext unless you really have to. Passing passwords
     in plain text over the net is not wise and not necessary since both
     Rserv and JRclient provide encrypted passwords with server-side
     challenge (thus safe from sniffing).
*/

#define USE_RINTERNALS
#define SOCK_ERRORS
#define LISTENQ 16

#if defined __GNUC__ && !defined unix && !defined Win32 /* MacOS X hack. gcc on any platform is treated as unix */
#define unix
#endif

/* FORKED is default for unix platforms */
#if defined unix && !defined THREADED && !defined COOPERATIVE && !defined FORKED
#define FORKED
#endif

/* AF_LOCAL is the POSIX version of AF_UNIX - we need this e.g. for AIX */
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

#ifndef CONFIG_FILE
#ifdef unix
#define CONFIG_FILE "/etc/Rserv.conf"
#else
#define CONFIG_FILE "Rserv.cfg"
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sisocks.h>
#include <string.h>
#ifdef unix
#include <sys/time.h>
#include <unistd.h>
#include <sys/un.h> /* needed for unix sockets */
#endif
#ifdef THREADED
#include <sbthread.h>
#endif
#ifdef FORKED
#include <sys/wait.h>
#endif
#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>
#include <IOStuff.h>
#include <Parse.h>
#include "Rsrv.h"
#ifdef HAVE_CRYPT_H
#include <crypt.h>
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

int port = default_Rsrv_port;
int active = 1; /* 1=server loop is active, 0=shutdown */
int UCIX   = 1; /* unique connection index */

char *localSocketName = 0; /* if set listen on this local (unix) socket instead of TCP/IP */

int allowIO=1;  /* 1=allow I/O commands, 0=don't */

char **top_argv;
int top_argc;

char *workdir="/tmp/Rserv";
char *pwdfile=0;

SOCKET csock=-1;

int parentPID=-1;

#ifdef THREADED
int localUCIX;
#else
#define localUCIX UCIX
#endif

#ifdef RSERV_DEBUG
void printDump(void *b, int len) {
  int i=0;
  if (len<1) { printf("DUMP FAILED (len=%d)\n",len); };
  printf("DUMP [%d]:",len);
  while(i<len) {
    printf(" %02x",((unsigned char*)b)[i++]);
#ifdef NOFULL
    if(i>100) { printf(" ..."); break; };
#endif
  };
  printf("\n");
};
#endif

void sendResp(int s, int rsp) {
  struct phdr ph;
  memset(&ph,0,sizeof(ph));
  ph.cmd=itop(rsp|CMD_RESP);
#ifdef RSERV_DEBUG
  printf("OUT.sendResp(void data)\n");
  printDump(&ph,sizeof(ph));
#endif
  send(s,&ph,sizeof(ph),0);
};

char *getParseName(int n) {
  switch(n) {
  case PARSE_NULL: return "null";
  case PARSE_OK: return "ok";
  case PARSE_INCOMPLETE: return "incomplete";
  case PARSE_ERROR: return "error";
  case PARSE_EOF: return "EOF";
  };
  return "<unknown>";
};

#define attrFixup if (hasAttr) buf=storeSEXP(buf,ATTRIB(x));
#define dist(A,B) (((int)(((char*)B)-((char*)A)))-4)

int* storeSEXP(int* buf, SEXP x) {
  int t=TYPEOF(x);
  int i;
  char c;
  int hasAttr=0;
  int *preBuf=buf;

  if (!x) { /* null pointer will be treated as XT_NULL */
    *buf=itop(XT_NULL); buf++; goto didit;
  }

  if (TYPEOF(ATTRIB(x))>0) hasAttr=XT_HAS_ATTR;

  if (t==NILSXP) {
    *buf=itop(XT_NULL|hasAttr);
    buf++;
    attrFixup;
    goto didit;
  } 
  
  if (t==LISTSXP) {
    *buf=itop(XT_LIST|hasAttr);
    buf++;
    attrFixup;
    buf=storeSEXP(buf,CAR(x));
    buf=storeSEXP(buf,CDR(x));    
    buf=storeSEXP(buf,TAG(x));  /* since 1.22 (0.1-5) we store TAG as well */
    goto didit;
  };

  if (t==LANGSXP) { /* LANG are simply special lists */
    *buf=itop(XT_LANG|hasAttr);
    buf++;
    attrFixup;
    /* before 1.22 (0.1-5) contents was ignored */
    buf=storeSEXP(buf,CAR(x));
    buf=storeSEXP(buf,CDR(x));
    buf=storeSEXP(buf,TAG(x));  /* since 1.22 (0.1-5) we store TAG as well */
    goto didit;
  };

  if (t==CLOSXP) { /* closures (send FORMALS and BODY) */
    *buf=itop(XT_CLOS|hasAttr);
    buf++;
    attrFixup;
    buf=storeSEXP(buf,FORMALS(x));
    buf=storeSEXP(buf,BODY(x));
    goto didit;
  }

  if (t==REALSXP) {
    if (LENGTH(x)>1) {
      *buf=itop(XT_ARRAY_DOUBLE|hasAttr);
      buf++;
      attrFixup;
      i=0;
      while(i<LENGTH(x)) {
	((double*)buf)[i]=dtop(REAL(x)[i]);
	i++;
      };
      buf=(int*)(((double*)buf)+LENGTH(x));
    } else {
      *buf=itop(XT_DOUBLE|hasAttr);
      buf++;
      attrFixup;
      *((double*)buf)=dtop(*REAL(x));
      buf=(int*)(((double*)buf)+1);
    };
    goto didit;
  };

  if (t==LGLSXP) {
    *buf=itop(((LENGTH(x)>1)?XT_ARRAY_BOOL:XT_BOOL)|hasAttr);
    buf++;
    attrFixup;
    i=0;
    while(i<LENGTH(x)) { /* logical values are stored as bytes of values 0/1/2 */
      int bv=(int)VECTOR_ELT(x,i);
      *((unsigned char*)buf)=(bv==0)?0:(bv==1)?1:2;
      buf=(int*)(((unsigned char*)buf)+1);
      i++;
    };
    goto didit;
  };

  if (t==EXPRSXP || t==VECSXP || t==STRSXP) {
    if (t==STRSXP && LENGTH(x)==1) {
      buf=storeSEXP(buf,VECTOR_ELT(x,0));
      goto skipall; /* need to skip fixup since we didn't store anything */
    } else {
      *buf=itop(XT_VECTOR|hasAttr);
      buf++;
      attrFixup;
      i=0;
      while(i<LENGTH(x)) {
        buf=storeSEXP(buf,VECTOR_ELT(x,i));
        i++;
      };
    };
    goto didit;
  };

  if (t==INTSXP) {
    *buf=itop(XT_ARRAY_INT|hasAttr);
    buf++;
    attrFixup;
    i=0;
    while(i<LENGTH(x)) {
      *buf=itop(INTEGER(x)[i]);
      buf++;
      i++;
    };
    goto didit;
  };

  if (t==CHARSXP) {
    *buf=itop(XT_STR|hasAttr);
    buf++;
    attrFixup;
    strcpy((char*)buf,(char*)STRING_PTR(x));
    buf=(int*)(((char*)buf)+strlen((char*)buf)+1);
    goto didit;
  };

  if (t==SYMSXP) {
    *buf=itop(XT_SYM|hasAttr);
    buf++;
    attrFixup;
    buf=storeSEXP(buf,PRINTNAME(x));
    goto didit;
  };

  *buf=itop(XT_UNKNOWN|hasAttr);
  buf++;
  attrFixup;
  *buf=itop(TYPEOF(x));
  buf++;
  
 didit:
  *preBuf=itop(SET_PAR(PAR_TYPE(ptoi(*preBuf)),dist(preBuf,buf)));

 skipall:
  return buf;
};

void printSEXP(SEXP e) /* merely for debugging purposes
						  in fact Rserve binary transport supports
						  more types than this function. */
{
  int t=TYPEOF(e);
  int i;
  char c;

  if (t==NILSXP) {
    printf("NULL value\n");
    return;
  };
  if (t==LANGSXP) {
    printf("language construct\n");
    return;
  };
  if (t==REALSXP) {
    if (LENGTH(e)>1) {
      printf("Vector of real variables: ");
      i=0;
      while(i<LENGTH(e)) {
	printf("%f",REAL(e)[i]);
	if (i<LENGTH(e)-1) printf(", ");
	i++;
      };
      putchar('\n');
    } else
      printf("Real variable %f\n",*REAL(e));
    return;
  };
  if (t==EXPRSXP) {
    printf("Vector of %d expressions:\n",LENGTH(e));
    i=0;
    while(i<LENGTH(e)) {
      printSEXP(VECTOR_ELT(e,i));
      i++;
    };
    return;
  };
  if (t==INTSXP) {
    printf("Vector of %d integers:\n",LENGTH(e));
    i=0;
    while(i<LENGTH(e)) {
      printf("%d",INTEGER(e)[i]);
      if (i<LENGTH(e)-1) printf(", ");
      i++;
    };
    putchar('\n');
    return;
  };
  if (t==VECSXP) {
    printf("Vector of %d fields:\n",LENGTH(e));
    i=0;
    while(i<LENGTH(e)) {
      printSEXP(VECTOR_ELT(e,i));
      i++;
    };
    return;
  };
  if (t==STRSXP) {
    i=0;
    printf("String vector of length %d:\n",LENGTH(e));
    while(i<LENGTH(e)) {
      printSEXP(VECTOR_ELT(e,i)); i++;
    };
    return;
  };
  if (t==CHARSXP) {
    printf("scalar string: \"%s\"\n",STRING_PTR(e));
    return;
  };
  if (t==SYMSXP) {
    printf("Symbol, name: "); printSEXP(PRINTNAME(e));
    return;
  };
  printf("Unknown type: %d\n",t);
};

void printBufInfo(IoBuffer *b) {
  printf("read-off: %d, write-off: %d\n",b->read_offset,b->write_offset);
};


/* decode_toSEXP is used to decode SEXPs from binary form and create
   corresponding objects in R. UPC is a pointer to a counter of
   UNPROTECT calls which will be necessary after we're done.
   The buffer position is advanced to the point where the SEXP ends
   (more precisely it points to the next stored SEXP). */
SEXP decode_to_SEXP(int **buf, int *UPC)
{
  int *b=*buf;
  char *c,*cc;
  SEXP val=0;
  int ty=PAR_TYPE(ptoi(*b));
  int ln=PAR_LEN(ptoi(*b));
  int i,j,k,l;
  
#ifdef RSERV_DEBUG
  printf("decode: type=%x, len=%d\n",ty,ln);
#endif
  b++;

  switch(ty) {
  case XT_INT:
  case XT_ARRAY_INT:
    l=ln/4;
    PROTECT(val=NEW_INTEGER(l));
    *UPC++;
    i=0;
    while (i<l) {
      INTEGER(val)[i]=ptoi(*b); i++; b++;
    }
    *buf=b;
    break;
  case XT_DOUBLE:
  case XT_ARRAY_DOUBLE:
    l=ln/8;
    PROTECT(val=NEW_NUMERIC(l)); *UPC++;
    i=0;
    while (i<l) {
      NUMERIC_POINTER(val)[i]=ptod(*((double*)b));
      i++; b+=2;
    }
    *buf=b;
    break;
  case XT_STR:
  case XT_ARRAY_STR:
    i=j=0;
    c=(char*)(b+1);
    while(i<ln) {
      if (!*c) j++;
      c++;
      i++; 
    };
    PROTECT(val=NEW_STRING(j)); *UPC++;
    i=j=0; cc=c;
    while(i<ln) {
      if (!*c) {
	VECTOR_ELT(val,j)=mkChar(cc);
	j++; cc=c+1;
      }
      c++; i++;
    }
    *buf=(int*)cc;
    break;
  }
  return val;
}

/* if set Rserve doesn't accept other than local connections. */
int localonly=1;

/* server socket */
SOCKET ss;

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
void sendRespData(int s, int rsp, int len, void *buf) {
  struct phdr ph;
  memset(&ph,0,sizeof(ph));
  ph.cmd=itop(rsp|CMD_RESP);
  ph.len=itop(len);
#ifdef RSERV_DEBUG
  printf("OUT.sendRespData\nHEAD ");
  printDump(&ph,sizeof(ph));
  printf("BODY ");
  printDump(buf,len);
#endif
    
  send(s,&ph,sizeof(ph),0);
  send(s,buf,len,0);
};

/* initial ID string */
char *IDstring="Rsrv0100QAP1\r\n\r\n--------------\r\n";

/* require authentication flag (default: no) */
int authReq=0;
/* use plain password flag (default: no) */
int usePlain=0;

/* max. size of the input buffer (per connection) */
int maxInBuf=16*(1024*1024); /* default is 16MB maximum */

/* load config file */
int loadConfig(char *fn)
{
  FILE *f;
  char buf[512];
  char *c,*p,*c1;

  f=fopen(fn,"r");
  if (!f) return -1;
  buf[511]=0;
  while(!feof(f))
    if (fgets(buf,511,f)) {
      c=buf;
      while(*c==' '||*c=='\t') c++;
      p=c;
      while(*p && *p!='\t' && *p!=' ' && *p!='=' && *p!=':') p++;
      if (*p) {
	*p=0;
	p++;
	while(*p && (*p=='\t' || *p==' ')) p++;
      }
      c1=p;
      while(*c1) if(*c1=='\n'||*c1=='\r') *c1=0; else c1++;
      if (!strcmp(c,"remote"))
	localonly=(*p=='1' || *p=='y' || *p=='e')?0:1;
      if (!strcmp(c,"port")) {
	if (*p) {
	  int np=atoi(p);
	  if (np>0) port=np;
	}
      }
      if (!strcmp(c,"maxinbuf")) {
	if (*p) {
	  int ns=atoi(p);
	  if (ns>32)
	    maxInBuf=ns*1024;
	}
      }
      if (!strcmp(c,"workdir")) {
	if (*p) {
	  workdir=(char*)malloc(strlen(p)+1);
	  strcpy(workdir,p);
	} else workdir=0;
      }
      if (!strcmp(c,"socket")) {
	if (*p) {
	  localSocketName=(char*)malloc(strlen(p)+1);
	  strcpy(localSocketName,p);
	} else localSocketName=0;
      }
      if (!strcmp(c,"pwdfile")) {
	if (*p) {
	  pwdfile=(char*)malloc(strlen(p)+1);
	  strcpy(pwdfile,p);
	} else pwdfile=0;
      }
      if (!strcmp(c,"auth"))
	authReq=(*p=='1' || *p=='y' || *p=='r' || *p=='e')?1:0;
      if (!strcmp(c,"plaintext"))
	usePlain=(*p=='1' || *p=='y' || *p=='e')?1:0;
      if (!strcmp(c,"fileio"))
	allowIO=(*p=='1' || *p=='y' || *p=='e')?1:0;
    };
  fclose(f);
#ifndef HAS_CRYPT
  if (!usePlain) {
    fprintf(stderr,"Warning: useplain=yes, but this Rserve has no crypt support!\nCompile with crypt support and make sure your system supports crypt.\nFalling back to plain text password.\n");
    usePlain=1;
  }
#endif
}

/* size of the input buffer (default 512kB)
   was 2k before 1.23, but since 1.22 we support CMD_assign/set and hence
   the incoming packets can be substantially bigger.

   since 1.29 we support input buffer resizing,
   therefore we start with a small buffer and allocate more if necessary
*/

int inBuf=32768; /* 32kB should be ok unless CMD_assign sends large data */

/* static buffer size used for file transfer.
   The user is still free to allocate its own size  */
#define sfbufSize 32768 /* static file buffer size */

#ifndef decl_sbthread
#define decl_sbthread void
#endif

/* pid of the last child (not really used ATM) */
int lastChild;

#ifdef FORKED
void sigHandler(int i) {
  if (i==SIGTERM || i==SIGHUP)
    active=0;
}
#endif

/* used for generating salt code (2x random from this array) */
const char *code64="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYXZ01";

/* working thread/function. the parameter is of the type struct args* */
decl_sbthread newConn(void *thp) {
  SOCKET s;
  struct args *a=(struct args*)thp;
  struct phdr ph;
  char *buf, *c,*cc,*c1,*c2;
  int *par[16];
  int pars;
  int i,j,k,n;
  int process;
  int stat;
  char *sendbuf;
  int sendBufSize;
  char *tail;
  char *fbuf;
  char *sfbuf;
  int fbufl;
  int Rerror;
  char wdname[512];
  int authed=0;
  char salt[5];
  
  IoBuffer *iob;
  SEXP xp,exp;
  FILE *cf=0;

#ifdef FORKED  
  if ((lastChild=fork())!=0) return;
  parentPID=getppid();
  closesocket(a->ss); /* close server socket */
#endif

  buf=(char*) malloc(inBuf+8);
  sfbuf=(char*) malloc(sfbufSize);
  if (!buf || !sfbuf) {
    fprintf(stderr,"FATAL: cannot allocate initial buffers. closing client connection.\n");
    s=a->s;
    free(a);
    closesocket(s);
    return;
  }
  memset(buf,0,inBuf+8);

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

  iob=(IoBuffer*)malloc(sizeof(*iob));
  sendBufSize=sndBS;
  sendbuf=(char*)malloc(sendBufSize);
#ifdef RSERV_DEBUG
  printf("connection accepted.\n");
#endif
  s=a->s;
  free(a);

#ifndef THREADED /* in all but threaded environments we can keep the
		    current socket globally for R-error handler */
  csock=s;
#endif

  strcpy(buf,IDstring);
  if (authReq) {
    memcpy(buf+16,"ARuc",4);
    salt[0]='K';
    salt[1]=code64[rand()&63];
    salt[2]=code64[rand()&63];
    salt[3]=' '; salt[4]=0;
    memcpy(buf+20,salt,4);
    if (usePlain) memcpy(buf+24,"ARpt",4);
  };
  send(s,buf,32,0);
  while((n=recv(s,&ph,sizeof(ph),0))==sizeof(ph)) {
#ifdef RSERV_DEBUG
    printf("\nheader read result: %d\n",n);
    if (n>0) printDump(&ph,n);
#endif
    ph.len=ptoi(ph.len);
    ph.cmd=ptoi(ph.cmd);
    ph.dof=ptoi(ph.dof);
    process=0;
    pars=0;
    if (ph.len>0) {
      if (ph.len<maxInBuf) {
	if (ph.len>=inBuf) {
#ifdef RSERV_DEBUG
	  printf("resizing input buffer (was %d, need %d) to %d\n",inBuf,ph.len,((ph.len|0x1fff)+1));
#endif
	  free(buf); /* the buffer is just a scratchpad, so we don't need to use realloc */
	  buf=(char*)malloc(inBuf=((ph.len|0x1fff)+1)); /* use 8kB granularity */
	  if (!buf) {
#ifdef RSERV_DEBUG
	    fprintf(stderr,"FATAL: out of memory while resizing buffer to %d,\n",inBuf);
#endif
	    sendResp(s,SET_STAT(RESP_ERR,ERR_out_of_mem));
	    free(sendbuf); free(iob); free(sfbuf);
	    closesocket(s);
	    return;
	  }	    
	}
#ifdef RSERV_DEBUG
	printf("loading buffer (awaiting %d bytes)\n",ph.len);
#endif
	i=0;
	while(n=recv(s,buf+i,ph.len-i,0)) {
	  if (n>0) i+=n;
	  if (i>=ph.len || n<1) break;
	};
	if (i<ph.len) break;
	memset(buf+ph.len,0,8);
	
#ifdef RSERV_DEBUG
	printf("parsing parameters\n");
	if (ph.len>0) printDump(buf,ph.len);
#endif
	c=buf+ph.dof;
	while((c<buf+ph.dof+ph.len) && (i=ptoi(*((int*)c)))) {
#ifdef RSERV_DEBUG
	  printf("PAR[%d]: %08x (PAR_LEN=%d, PAR_TYPE=%d)\n",pars,i,PAR_LEN(i),PAR_TYPE(i));
#endif
	  par[pars]=(int*)c;
	  pars++;
	  c+=PAR_LEN(i)+4; /* par length plus par head (4 bytes) */
	  if (pars>15) break;
	}; /* we don't parse more than 16 parameters */
      } else {
	printf("discarding buffer because too big (awaiting %d bytes)\n",ph.len);
	i=ph.len;
	while(n=recv(s,buf,i>inBuf?inBuf:i,0)) {
	  if (n>0) i-=n;
	  if (i<1 || n<1) break;
	};
	if (i>0) break;
	/* if the pars are bigger than my buffer, send data_overflow response
	   (since 1.23/0.1-6; was inv_par before) */
	sendResp(s,SET_STAT(RESP_ERR,ERR_data_overflow));
	process=1; ph.cmd=0;
      };
    };

    /** IMPORTANT! The pointers in par[..] point to RAW data, i.e. you have
        to use ptoi(..) in order to get the real integer value. */

#ifdef RSERV_DEBUG
    printf("CMD=%08x, pars=%d\n",ph.cmd,pars);
#endif

    if (!authed && ph.cmd==CMD_login) {
      if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_STRING) 
	sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
      else {
	c=(char*)(par[0]+1);
	cc=c;
	while(*cc && *cc!='\n') cc++;
	if (*cc) { *cc=0; cc++; };
	c1=cc;
	while(*c1) if(*c1=='\n'||*c1=='\r') *c1=0; else c1++;
	/* c=login, cc=pwd */
	authed=1;
	if (pwdfile) {
	  authed=0; /* if pwdfile exists, default is access denied */
	  /* TODO: opening pwd file, parsing it and responding
	     might be a bad idea, since it allows DOS attacks as this
	     operation is fairly costly. We should actually cache
	     the user list and reload it only on HUP or something */
	  /* we abuse variables of other commands since we are
	     the first command ever used so we can trash them */
	  cf=fopen(pwdfile,"r");
	  if (cf) {
	    sfbuf[sfbufSize-1]=0;
	    while(!feof(cf))
	      if (fgets(sfbuf,sfbufSize-1,cf)) {
		c1=sfbuf;
		while(*c1 && *c1!=' ' && *c1!='\t') c1++;
		if (*c1) {
		  *c1=0;
		  c1++;
		  while(*c1==' ' || *c1=='\t') c1++;
		};
		c2=c1;
		while(*c2) if (*c2=='\r'||*c2=='\n') *c2=0; else c2++;
		if (!strcmp(sfbuf,c)) { /* login found */
		  if (usePlain && !strcmp(c1,cc))
		    authed=1;
		  else {
#ifdef HAS_CRYPT
		    c2=crypt(c1,salt+1);
		    if (!strcmp(c2,cc)) authed=1;
#endif
		  };
		};
		if (authed) break;
	      }; /* if fgets */
	    fclose(cf);
	  } /* if (cf) */
	  cf=0;
	  if (authed) {
	    process=1;
	    sendResp(s,RESP_OK);
	  }
	}
      }
    };
    /* if not authed by now, close connection */
    if (authReq && !authed) {
      sendResp(s,SET_STAT(RESP_ERR,ERR_auth_failed));
      closesocket(s);
      free(sendbuf); free(iob); free(sfbuf); free(buf);
      return;
    };      

    if (ph.cmd==CMD_shutdown) {
      sendResp(s,RESP_OK);
#ifdef RSERV_DEBUG
      printf("initiating clean shutdown.\n");
#endif
      active=0;
      closesocket(s);
      free(sendbuf); free(iob); free(sfbuf); free(buf);
#ifdef FORKED
      if (parentPID>0) kill(parentPID,SIGTERM);
      exit(0);
#endif
      return;
    };

    if (ph.cmd==CMD_setBufferSize) {
      process=1;
      if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_INT) 
	sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
      else {
	int ns=ptoi(par[0][1]);
#ifdef RSERV_DEBUG
	printf(">>CMD_setSendBuf to %d bytes.\n",ns);
#endif
	if (ns>0) { /* 0 means don't touch the buffer size */
	  if (ns<32768) ns=32768; /* we enforce a minimum of 32kB */
	  free(sendbuf);
	  sendbuf=(char*)malloc(sendBufSize);
	  if (!sendbuf) {
#ifdef RSERV_DEBUG
	    fprintf(stderr,"FATAL: out of memory while resizing send buffer to %d,\n",sendBufSize);
#endif
	    sendResp(s,SET_STAT(RESP_ERR,ERR_out_of_mem));
	    free(buf); free(iob); free(sfbuf);
	    closesocket(s);
	    return;
	  }
	}
	sendResp(s,RESP_OK);
      }
    }

    if (ph.cmd==CMD_openFile||ph.cmd==CMD_createFile) {
      process=1;
      if (!allowIO) sendResp(s,SET_STAT(RESP_ERR,ERR_accessDenied));
      else {
	if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_STRING) 
	  sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	else {
	  c=(char*)(par[0]+1);
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
	if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_STRING) 
	  sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	else {
	  c=(char*)(par[0]+1);
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
	printf(">>CMD_closeFile\n",c);
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
	  fbufl=sfbufSize; fbuf=sfbuf;
	  if (pars==1 && PAR_TYPE(ptoi(*par[0]))==DT_INT)
	    fbufl=ptoi(par[0][1]);
#ifdef RSERV_DEBUG
	  printf(">>CMD_readFile(%d)\n",fbufl);
#endif
	  if (fbufl<0) fbufl=sfbufSize;
	  if (fbufl>sfbufSize)
	    fbuf=(char*)malloc(fbufl);
	  if (!fbuf) /* well, logically not clean, but in practice true */
	    sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	  else {
	    i=fread(fbuf,1,fbufl,cf);
	    if (i>0)
	      sendRespData(s,RESP_OK,i,fbuf);
	    else
	      sendResp(s,RESP_OK);
	    if (fbuf!=sfbuf)
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
	  if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_BYTESTREAM)
	    sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	  else {
#ifdef RSERV_DEBUG
	    printf(">>CMD_writeFile(%d,...)\n",PAR_LEN(ptoi(*par[0])));
#endif
	    i=0;
	    c=(char*)(par[0]+1);
	    if (PAR_LEN(ptoi(*par[0]))>0)
	      i=fwrite(c,1,PAR_LEN(ptoi(*par[0])),cf);
	    if (i>0 && i!=PAR_LEN(ptoi(*par[0])))
	      sendResp(s,SET_STAT(RESP_ERR,ERR_IOerror));
	    else
	      sendResp(s,RESP_OK);
	  }
	}
      }
    }

    if (ph.cmd==CMD_setSEXP || ph.cmd==CMD_assignSEXP) {
      process=1;
      if (pars<2 || PAR_TYPE(ptoi(*par[0]))!=DT_STRING) 
	sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
      else {
	SEXP val, sym=0;
	int *sptr;
	int parType=PAR_TYPE(ptoi(*par[1]));
	int globalUPC=0;

	c=(char*)(par[0]+1); /* name of the symbol */
#ifdef RSERV_DEBUG
	printf(">>CMD_set/assignREXP (%s, REXP)\n",c);
#endif

	if (ph.cmd==CMD_assignSEXP) {
	  R_IoBufferInit(iob);
	  R_IoBufferPuts(c,iob);
	  sym=R_Parse1Buffer(iob,1,&stat);
	  if (stat!=1) {
#ifdef RSERV_DEBUG
	    printf(">>CMD_assignREXP-failed to parse \"%s\", stat=%d\n",c,stat);
#endif
	    sendResp(s,SET_STAT(RESP_ERR,stat));
	    goto respSt;
	  };
	}

	switch (parType) {
	case DT_STRING:
#ifdef RSERV_DEBUG
	  printf("  assigning string \"%s\"\n",((char*)(par[1]+1)));
#endif
	  PROTECT(val = allocVector(STRSXP,1));
	  SET_STRING_ELT(val,0,mkChar((char*)(par[1]+1)));
	  defineVar((sym)?sym:install(c),val,R_GlobalEnv);
	  UNPROTECT(1);
	  sendResp(s,RESP_OK);
	  break;
	case DT_SEXP:
	  sptr=par[1]+1;
	  val=decode_to_SEXP(&sptr,&globalUPC);
	  if (val==0)
	    sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	  else {
#ifdef RSERV_DEBUG
	    printf("  assigning SEXP: ");
	    printSEXP(val);
#endif
	    defineVar((sym)?sym:install(c),val,R_GlobalEnv);
	    UNPROTECT(globalUPC);
	    sendResp(s,RESP_OK);
	  }
	  break;
	default:
	  sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	}
      }
    }

    if (ph.cmd==CMD_voidEval || ph.cmd==CMD_eval) {
      process=1;
      if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_STRING) 
	sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
      else {
	c=(char*)(par[0]+1);
	i=j=0; /* count the lines to pass the right parameter to parse
		  the string should contain a trainig \n !! */
	while(c[i]) if(c[i++]=='\n') j++;
#ifdef RSERV_DEBUG	
	printf("R_IoBufferPuts(\"%s\",iob)\n",c);
#endif
	/* R_IoBufferWriteReset(iob);
	   R_IoBufferReadReset(iob); */
	R_IoBufferInit(iob);
	R_IoBufferPuts(c,iob);
#ifdef RSERV_DEBUG
	printf("R_Parse1Buffer(iob,%d,&stat)\n",j);
#endif
	xp=R_Parse1Buffer(iob,j,&stat);
#ifdef RSERV_DEBUG
	printf("buffer parsed, stat=%d\n",stat);
#endif
	if (stat!=1)
	  sendResp(s,SET_STAT(RESP_ERR,stat));
        else {	 
#ifdef RSERV_DEBUG
          printf("R_tryEval(xp,R_GlobalEnv,&Rerror);\n");
#endif
	  Rerror=0;
	  PROTECT(xp);
	  exp=R_tryEval(xp,R_GlobalEnv,&Rerror);
	  PROTECT(exp);
#ifdef RSERV_DEBUG
	  printf("buffer evaluated (Rerror=%d).\n",Rerror);
	  if (!Rerror) printSEXP(exp);
#endif
	  if (Rerror) {
	    sendResp(s,SET_STAT(RESP_ERR,(Rerror<0)?Rerror:-Rerror));
	  } else {
	    if (ph.cmd==CMD_voidEval)
	      sendResp(s,RESP_OK);
	    else {
	      tail=(char*)storeSEXP((int*)sendbuf,exp);
#ifdef RSERV_DEBUG
	      printf("stored SEXP; length=%d\n",tail-sendbuf);
#endif
	      sendRespData(s,RESP_OK,tail-sendbuf,sendbuf);
	    };
	  };
	  UNPROTECT(2);
	};
#ifdef RSERV_DEBUG
        printf("reply sent.\n");
#endif
      };
    };
  respSt:

    if (!process)
      sendResp(s,SET_STAT(RESP_ERR,ERR_inv_cmd));
  };
#ifdef RSERV_DEBUG
  if (n==0)
    printf("Connection closed by peer.\n");
  else
    printf("malformed packet. closing socket to prevent garbage.\n",n);
#endif
  if (n>0)
    sendResp(s,SET_STAT(RESP_ERR,ERR_conn_broken));
  closesocket(s);
  free(sendbuf); free(iob); free(sfbuf); free(buf);
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
};

void serverLoop() {
  SAIN ssa;
  unsigned long al;
  int reuse;
  int selRet=0;
  struct args *sa;
  struct sockaddr_in lsa;

#ifdef unix
  struct sockaddr_un lusa;
  struct timeval timv;
  fd_set readfds;
#endif

  lsa.sin_addr.s_addr=inet_addr("127.0.0.1");

#ifdef FORKED
  signal(SIGHUP,sigHandler);
  signal(SIGTERM,sigHandler);
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
  setsockopt(ss,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
#ifdef unix
  if (localSocketName)
    FCF("bind",bind(ss,(SA*) &lusa, sizeof(lusa)));    
  else
#endif
    FCF("bind",bind(ss,build_sin(&ssa,0,port),sizeof(ssa)));

  FCF("listen",listen(ss,LISTENQ));
  while(active) { /* main serving loop */
#ifdef FORKED
    while (waitpid(-1,0,WNOHANG)>0);
#endif
#ifdef unix
    timv.tv_sec=0; timv.tv_usec=10000;
    FD_ZERO(&readfds); FD_SET(ss,&readfds);
    selRet=select(ss+1,&readfds,0,0,&timv);
    if (selRet>0 && FD_ISSET(ss,&readfds)) {
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
      if (localonly && !localSocketName) {
	if (sa->sa.sin_addr.s_addr==lsa.sin_addr.s_addr)
#ifdef THREADED
	  sbthread_create(newConn,sa);
#else
	newConn(sa);
#endif
      else
        closesocket(sa->s);
      } else
#ifdef THREADED
	sbthread_create(newConn,sa); 
#else
      newConn(sa);
#endif
#ifdef unix
    };
#endif
  };
};

/* main function - start Rserve */
int main(int argc, char **argv)
{
  IoBuffer b;
  int stat,i;
  SEXP r,s;
  SEXP env;
  char c;

#ifdef RSERV_DEBUG
  printf("Rserve (C)Copyright 2002,3 Simon Urbanek\n\n");
#endif
  if (!isByteSexOk()) {
    printf("FATAL ERROR: This program was not correctly compiled - the endianess is wrong!\nUse -DSWAPEND when compiling on PPC or similar platforms.\n");
    return -100;
  };

  loadConfig(CONFIG_FILE);
#ifdef RSERV_DEBUG
  printf("Loaded config file %s\n",CONFIG_FILE);
#endif

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
	  port=atoi(argv[++i]);
	  if (port<1) {
	    fprintf(stderr,"Invalid port number in --RS-port, using default port.\n");
	    port=default_Rsrv_port;
	  }
	}
      }
      if (!strcmp(argv[i]+2,"RS-socket")) {
	isRSP=1;
	if (i+1==argc)
	  fprintf(stderr,"Missing socket specification for --RS-socket.\n");
	else
	  localSocketName=argv[++i];
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
	printf("Rserve v%d.%d-%d\n\nconfig file: %s\nworking root: %s\nport: %d\nlocal socket: %s\nauthorization required: %s\nplain text password: %s\npasswords file: %s\nallow I/O: %s\nmax.input buffer size: %d kB\n\n",
	       RSRV_VER>>16,(RSRV_VER>>8)&255,RSRV_VER&255,
	       CONFIG_FILE,workdir,port,localSocketName?localSocketName:"[none, TCP/IP used]",
	       authReq?"yes":"no",usePlain?"allowed":"not allowed",pwdfile?pwdfile:"[none]",allowIO?"yes":"no",
	       maxInBuf/1024);
	return 0;	       
      }
      if (!strcmp(argv[i]+2,"version")) {
	printf("Rserve v%d.%d-%d\n",RSRV_VER>>16,(RSRV_VER>>8)&255,RSRV_VER&255);
      }
      if (!strcmp(argv[i]+2,"help")) {
	printf("Usage: R CMD Rserve [<options>]\n\nOptions: --help  this help screen\n --version  prints Rserve version (also passed to R)\n --RS-port <port> listen on the specified TCP port\n --RS-socket <socket> use specified local (unix) socket instead of TCP/IP.\n --RS-workdir <path> use specified working directory root for connections.\n --RS-conf <file> load additional config file.\n --RS-settings  dumps current settings of the Rserve\n\nAll other options are passed to the R engine.\n\n");
	return 0;
      }
    }
    if (!isRSP)
      top_argv[top_argc++]=argv[i];
    i++;
  };

  stat=Rf_initEmbeddedR(top_argc,top_argv);
  if (stat<0) {
    printf("Failed to initialize embedded R! (stat=%d)\n",stat);
    return -1;
  };

  R_IoBufferInit(&b);
  /*
  R_IoBufferPuts("data(iris)\n",&b);
  r=R_Parse1Buffer(&b,1,&stat);r=Rf_eval(r,R_GlobalEnv);
  */
  R_IoBufferPuts("\"Rserv: INVALID INPUT\"\n",&b);
  r=R_Parse1Buffer(&b,1,&stat);r=Rf_eval(r,R_GlobalEnv);
#if defined RSERV_DEBUG || defined Win32
  printf("Rserve: Ok, ready to answer queries.\n");
#endif      

#if defined DAEMON && defined unix
  /* ok, we're in unix, so let's daemonize properly */
  if (fork()!=0) {
    puts("Rserv started in daemon mode.");
    exit(0);
  };
  
  setsid();
  chdir("/");
  umask(0);
#endif

  serverLoop();
#ifdef unix
  if (localSocketName)
    remove(localSocketName);
#endif

#ifdef RSERV_DEBUG
  printf("Server treminated normally.\n");
#endif
};
