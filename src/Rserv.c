/*
 *  Rserv : R-server that allows to use embedded R via TCP/IP
 *          currently based on R-1.5.1 API
 *  Copyright (C) 2002 Simon Urbanek
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

/* external defines: (for unix platfoms: FORKED is highly recommended!)

   THREADED   - results in threaded version of this server, i.e. each
                new connection is run is a separate thread. Beware:
		this approach is not recommended since R does not support
		real multithreading yet
   FORKED     - each connection is forked to a new process. This is the
                recommended way to use this server. The advantage is (beside
		the fact that this works ;)) that each client has a separate
		namespace since the processes are independent
   - if none of the above is specified then cooperative serving is used
     (which is currently the only way available in Windows - if embedding R
     worked in that setup)

   SWAPEND  - define if the platform has byte order inverse to Intel (like PPC)
*/

#define USE_RINTERNALS
#define SOCK_ERRORS
#define USE_SNPRINTF
#define LISTENQ 16

#include <stdio.h>
#include <sisocks.h>
#include <string.h>
#ifdef THREADED
#include <sbthread.h>
#endif
#ifdef FORKED
#include <sys/wait.h>
#endif
#include <R.h>
#include <Rinternals.h>
#include <IOStuff.h>
#include <Parse.h>
#include "Rsrv.h"

/* send buffer size (default 2MB) */
#define sndBS (2048*1024)

int port = default_Rsrv_port;
int active = 1;

char **top_argv;
int top_argc;

SOCKET csock=-1;

#ifdef DEBUG
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
#ifdef DEBUG
  printf("OUT.sendResp(void data)\n");
  printDump(&ph,sizeof(ph));
#endif
  send(s,&ph,sizeof(ph),0);
};

void jump_now()
{
  /* on error - close connection and get outa here */
  if (csock!=-1) {
    sendResp(csock,SET_STAT(RESP_ERR,ERR_Rerror));
    closesocket(csock);
  };
  exit(0);
  
  //extern void Rf_resetStack(int topLevel);
  //fprintf(stderr, "Handling R error locally\n");
  //Rf_resetStack(1);
  //elog(ERROR, "Error in R");
}

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

struct tenc {
  int ptr;
  int *id[256];
  int ty[256];
  int *buf;
};

#define attrFixup if (hasAttr) buf=storeSEXP(buf,ATTRIB(x));
#define dist(A,B) (((int)(((char*)B)-((char*)A)))-4)

int* storeSEXP(int* buf, SEXP x) {
  int t=TYPEOF(x);
  int i;
  char c;
  int hasAttr=0;
  int *preBuf=buf;

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
    goto didit;
  };

  if (t==LANGSXP) {
    *buf=itop(XT_LANG|hasAttr);
    buf++;
    attrFixup;
    goto didit;
  };

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
    while(i<LENGTH(x)) {
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
  *buf=TYPEOF(x);
  buf++;
  
 didit:
  *preBuf=itop(SET_PAR(PAR_TYPE(ptoi(*preBuf)),dist(preBuf,buf)));

 skipall:
  return buf;
};

void printSEXP(SEXP e) { 
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

int localonly=1;

SOCKET ss;

/* arguments structure passed to a working thread */
struct args {
  int s;
  SAIN sa;
};

void sendRespData(int s, int rsp, int len, void *buf) {
  struct phdr ph;
  memset(&ph,0,sizeof(ph));
  ph.cmd=itop(rsp|CMD_RESP);
  ph.len=itop(len);
#ifdef DEBUG
  printf("OUT.sendRespData\nHEAD ");
  printDump(&ph,sizeof(ph));
  printf("BODY ");
  printDump(buf,len);
#endif
    
  send(s,&ph,sizeof(ph),0);
  send(s,buf,len,0);
};

char *IDstring="Rsrv0100QAP1\r\n\r\n--------------\r\n";

#define inBuf 2048

#ifndef decl_sbthread
#define decl_sbthread void
#endif

decl_sbthread newConn(void *thp) {
  SOCKET s;
  struct args *a=(struct args*)thp;
  struct phdr ph;
  char buf[inBuf+8], *c;
  int *par[16];
  int pars;
  int i,j,k,n;
  int process;
  int stat;
  char *sendbuf;
  char *tail;
  
  IoBuffer *iob;
  SEXP xp,exp;

  memset(buf,0,inBuf+8);
#ifdef FORKED  
  if (fork()!=0) return;
#endif

  iob=(IoBuffer*)malloc(sizeof(*iob));
  sendbuf=(char*)malloc(sndBS);
#ifdef DEBUG
  printf("connection accepted.\n");
#endif
  s=a->s;
  free(a);

#ifndef THREADED /* in all but threaded environments we can keep the
		    current socket globally for R-error handler */
  csock=s;
#endif

  send(s,IDstring,32,0);
  while((n=recv(s,&ph,sizeof(ph),0))==sizeof(ph)) {
#ifdef DEBUG
    printf("header read result: %d\n",n);
    if (n>0) printDump(&ph,n);
#endif
    ph.len=ptoi(ph.len);
    ph.cmd=ptoi(ph.cmd);
    ph.dof=ptoi(ph.dof);
    process=0;
    pars=0;
    if (ph.len>0) {
      if (ph.len<inBuf) {
#ifdef DEBUG
	printf("loading buffer (awaiting %d bytes)\n",ph.len);
#endif
	i=0;
	while(n=recv(s,buf+i,ph.len-i,0)) {
	  if (n>0) i+=n;
	  if (i>=ph.len || n<1) break;
	};
	if (i<ph.len) break;
	memset(buf+ph.len,0,8);
	
#ifdef DEBUG
	printf("parsing parameters\n");
#endif
	c=buf+ph.dof;
	while((c<buf+ph.dof+ph.len) && (i=ptoi(*((int*)c)))) {
#ifdef DEBUG
	  printf("PAR[%d]: %08x (PAR_LEN=%d, PAR_TYPE=%d)\n",pars,i,PAR_LEN(i),PAR_TYPE(i));
#endif
	  par[pars]=(int*)c;
	  pars++;
	  c+=PAR_LEN(i)+4; /* par length plut par head (4 bytes) */
	  if (pars>15) break;
	}; /* we don't parse more than 16 parameters */
#ifdef DEBUG
	i=0;
	while(i<ph.len) printf("%02x ",buf[i++]);
	puts("");
#endif
      } else {
	printf("discarding buffer because too big (awaiting %d bytes)\n",ph.len);
	i=ph.len;
	while(n=recv(s,buf,i>inBuf?inBuf:i,0)) {
	  if (n>0) i-=n;
	  if (i<1 || n<1) break;
	};
	if (i>0) break;
	/* if the pars are bigger than my buffer, send inv_par response */
	sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
	process=1; ph.cmd=0;
      };
    };

    /** IMPORTANT! The pointers in par[..] point to RAW data, i.e. you have
        to use ptoi(..) in order to get the real integer value. */

#ifdef DEBUG
    printf("CMD=%08x, pars=%d\n",ph.cmd,pars);
#endif

    if (ph.cmd==CMD_shutdown) {
      sendResp(s,RESP_OK);
      printf("clean shutdown.\n");
      active=0;
      closesocket(s);
      free(sendbuf); free(iob);
      return;
    };

    if (ph.cmd==CMD_voidEval || ph.cmd==CMD_eval) {
      process=1;
      if (pars<1 || PAR_TYPE(ptoi(*par[0]))!=DT_STRING) 
	sendResp(s,SET_STAT(RESP_ERR,ERR_inv_par));
      else {
	c=(char*)(par[0]+1);
	i=j=0; /* count the lines to pass the right parameter to parse
		  the string should contain a trainig \n !! */
	while(c[i]) if(c[i++]=='\n') j++;
	printf("R_IoBufferPuts(\"%s\",iob)\n",c);
	/* R_IoBufferWriteReset(iob);
	   R_IoBufferReadReset(iob); */
	R_IoBufferInit(iob);
	R_IoBufferPuts(c,iob);
	printf("R_Parse1Buffer(iob,%d,&stat)\n",j);
	xp=R_Parse1Buffer(iob,j,&stat);
	printf("buffer parsed, stat=%d\n",stat);
	if (stat!=1)
	  sendResp(s,SET_STAT(RESP_ERR,stat));
        else {	 
          printf("Rf_eval(xp,R_GlobalEnv);\n");
	  exp=Rf_eval(xp,R_GlobalEnv);
	  printf("buffer evaluated.\n");
	  printSEXP(exp);
	  if (ph.cmd==CMD_voidEval)
	    sendResp(s,RESP_OK);
	  else {
	    tail=(char*)storeSEXP((int*)sendbuf,exp);
	    printf("stored SEXP; length=%d\n",tail-sendbuf);
	    sendRespData(s,RESP_OK,tail-sendbuf,sendbuf);
	  };
	};
#ifdef DEBUG
        printf("reply sent.\n");
#endif
      };
    };

    if (!process)
      sendResp(s,SET_STAT(RESP_ERR,ERR_inv_cmd));
  };
  if (n==0)
    printf("Connection closed by peer.\n");
  else
    printf("malformed packet. closing socket to prevent garbage.\n",n);
  if (n>0)
    sendResp(s,SET_STAT(RESP_ERR,ERR_conn_broken));
  closesocket(s);
  free(sendbuf); free(iob);
  printf("done.\n");
};

void serverLoop() {
  SAIN ssa;
  int al;
  int reuse;
  struct args *sa;
  struct sockaddr_in lsa;

  lsa.sin_addr.s_addr=inet_addr("127.0.0.1");

  initsocks();
  ss=FCF("open socket",socket(AF_INET,SOCK_STREAM,0));
  reuse=1; /* enable socket address reusage */
  setsockopt(ss,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
  FCF("bind",bind(ss,build_sin(&ssa,0,port),sizeof(ssa)));
  FCF("listen",listen(ss,LISTENQ));
  while(active) { /* main serving loop */
#ifdef FORKED
    while (waitpid(-1,0,WNOHANG)>0);
#endif
    sa=(struct args*)malloc(sizeof(struct args));
    memset(sa,0,sizeof(struct args));
    al=sizeof(sa->sa);
    sa->s=CF("accept",accept(ss,(SA*)&(sa->sa),&al));
    if (localonly) {
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
  };
};

int main(int argc, char **argv)
{
  IoBuffer b;
  int stat;
  SEXP r,s;
  SEXP env;
  char c;

  top_argc=argc; top_argv=argv;

  stat=Rf_initEmbeddedR(top_argc,top_argv);
  if (stat) {
    printf("Failed to initialize embedded R! (stat=%d)\n",stat);
    return -1;
  };

  R_IoBufferInit(&b);
  R_IoBufferPuts("data(iris)\n",&b);
  r=R_Parse1Buffer(&b,1,&stat);r=Rf_eval(r,R_GlobalEnv);
  R_IoBufferPuts("\"Rserv: INVALID INPUT\"\n",&b);
  r=R_Parse1Buffer(&b,1,&stat);r=Rf_eval(r,R_GlobalEnv);
      
  serverLoop();
};
