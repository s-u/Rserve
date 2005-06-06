/*
 *  Rsrv.h : constants and macros for Rsrv client/server architecture
 *  Copyright (C) 2002-5 Simon Urbanek
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
   MAIN - should be defined in just one file that will contain the fn definitions and variables
 */

#ifndef __RSRV_H__
#define __RSRV_H__

#include "config.h"

#define RSRV_VER 0x000317 /* Rserve v0.3-17 */

#define default_Rsrv_port 6311

/* Rserv communication is done over any reliable connection-oriented
   protocol (usually TCP/IP). After connection is established, server
   sends 32bytes of ID-string defining the capabilities of the server.
   each attribute of the ID-string is 4 bytes long and is meant to be user-
   readable (i.e. use no special characters), and it's a good idea to make
   "\r\n\r\n" the last attribute

   the ID string must be of the form:

   [0] "Rsrv" - R-server ID signature
   [4] "0100" - version of the R server
   [8] "QAP1" - protocol used for communication (here Quad Attributes Packets v1)
   [12] any additional attributes follow. \r\n<space> and '-' are ignored.

   optional attributes
   (in any order; it is legitimate to put dummy attributes, like "----" or
    "    " between attributes):

   "R151" - version of R (here 1.5.1)
   "ARpt" - authorization required (here "pt"=plain text, "uc"=unix crypt)
            connection will be closed
            if the first packet is not CMD_login.
	    if more AR.. methods are specified, then client is free to
	    use the one he supports (usually the most secure)
   "K***" - key if encoded authentification is challenged (*** is the key)
            for unix crypt the first two letters of the key are the salt
	    required by the server */

/* QAP1 transport protocol header structure

   all int and double entries throughout the transfer are in
   Intel-endianess format: int=0x12345678 -> char[4]=(0x78,0x56,x34,0x12)
   functions/macros for converting from native to protocol format 
   are available below

   Please note also that all values muse be quad-aligned, i.e. the length
   must be divisible by 4. This is automatically assured for int/double etc.,
   but care must be taken when using strings and byte streams.

 */

struct phdr { /* always 16 bytes */
  int cmd; /* command */
  int len; /* length of the packet minus header (ergo -16) */
  int dof; /* data offset behind header (ergo usually 0) */
  int res; /* reserved - but must be sent so the minimal packet has 16 bytes */
};

/* each entry in the data section (aka parameter list) is preceded by 4 bytes:
   1 byte : parameter type
   3 bytes: length
   parameter list may be terminated by 0/0/0/0 but doesn't have to since "len"
   field specifies the packet length sufficiently (hint: best method for parsing is
   to allocate len+4 bytes, set the last 4 bytes to 0 and trverse list of parameters
   until (int)0 occurs
   
   since 0102:
   if the 7-th bit (0x40) in parameter type is set then the length is encoded
   in 7 bytes enlarging the header by 4 bytes. 
 */

/* macros for handling the first int - split/combine (24-bit version only!) */
#define PAR_TYPE(X) ((X)&255)
#define PAR_LEN(X) ((X)>>8)
#define PAR_LENGTH PAR_LEN
#define SET_PAR(TY,LEN) ((((LEN)&0xffffff)<<8)|((TY)&255))

#define CMD_STAT(X) (((X)>>24)&127) /* returns the stat code of the response */
#define SET_STAT(X,s) ((X)|(((s)&127)<<24)) /* sets the stat code */

#define CMD_RESP 0x10000  /* all responses have this flag set */

#define RESP_OK (CMD_RESP|0x0001) /* command succeeded; returned parameters depend
				     on the command issued */
#define RESP_ERR (CMD_RESP|0x0002) /* command failed, check stats code
				      attached string may describe the error */

/* stat codes; 0-0x3f are reserved for program specific codes - e.g. for R
   connection they correspond to the stat of Parse command.
   the following codes are returned by the Rserv itself

   codes <0 denote Rerror as provided by R_tryEval
 */
#define ERR_auth_failed      0x41 /* auth.failed or auth.requested but no
				     login came. in case of authentification
				     failure due to name/pwd mismatch,
				     server may send CMD_accessDenied instead
				  */
#define ERR_conn_broken      0x42 /* connection closed or broken packet killed it */
#define ERR_inv_cmd          0x43 /* unsupported/invalid command */
#define ERR_inv_par          0x44 /* some parameters are invalid */
#define ERR_Rerror           0x45 /* R-error occured, usually followed by
				     connection shutdown */
#define ERR_IOerror          0x46 /* I/O error */
#define ERR_notOpen          0x47 /* attempt to perform fileRead/Write 
				     on closed file */
#define ERR_accessDenied     0x48 /* this answer is also valid on
				     CMD_login; otherwise it's sent
				     if the server deosn;t allow the user
				     to issue the specified command.
				     (e.g. some server admins may block
				     file I/O operations for some users) */
#define ERR_unsupportedCmd   0x49 /* unsupported command */
#define ERR_unknownCmd       0x4a /* unknown command - the difference
				     between unsupported and unknown is that
				     unsupported commands are known to the
				     server but for some reasons (e.g.
				     platform dependent) it's not supported.
				     unknown commands are simply not recognized
				     by the server at all. */
/* The following ERR_.. exist since 1.23/0.1-6 */
#define ERR_data_overflow    0x4b /* incoming packet is too big.
				     currently there is a limit as of the
				     size of an incoming packet. */
#define ERR_object_too_big   0x4c /* the requested object is too big
				     to be transported in that way.
				     If received after CMD_eval then
				     the evaluation itself was successful.
				     optional parameter is the size of the object
				  */
/* since 1.29/0.1-9 */
#define ERR_out_of_mem       0x4d /* out of memory. the connection is usually
				     closed after this error was sent */

/* availiable commands */

#define CMD_login        0x001 /* "name\npwd" : - */
#define CMD_voidEval     0x002 /* string : - */
#define CMD_eval         0x003 /* string : encoded SEXP */
#define CMD_shutdown     0x004 /* [admin-pwd] : - */
/* file I/O routines. server may answe */
#define CMD_openFile     0x010 /* fn : - */
#define CMD_createFile   0x011 /* fn : - */
#define CMD_closeFile    0x012 /* - : - */
#define CMD_readFile     0x013 /* [int size] : data... ; if size not present,
				  server is free to choose any value - usually
				  it uses the size of its static buffer */
#define CMD_writeFile    0x014 /* data : - */
#define CMD_removeFile   0x015 /* fn : - */

/* object manipulation */
#define CMD_setSEXP      0x020 /* string(name), REXP : - */
#define CMD_assignSEXP   0x021 /* string(name), REXP : - ; same as setSEXP
				  except that the name is parsed */
/* 'internal' commands (since 0.1-9) */
#define CMD_setBufferSize 0x081  /* [int sendBufSize] 
				  this commad allow clients to request
				  bigger buffer sizes if large data is to be
				  transported from Rserve to the client.
				  (incoming buffer is resized automatically)
				 */

/* data types for the transport protocol (QAP1)
   do NOT confuse with XT_.. values. */

#define DT_INT        1  /* int */
#define DT_CHAR       2  /* char */
#define DT_DOUBLE     3  /* double */
#define DT_STRING     4  /* 0 terminted string */
#define DT_BYTESTREAM 5  /* stream of bytes (unlike DT_STRING may contain 0) */
#define DT_SEXP       10 /* encoded SEXP */
#define DT_ARRAY      11 /* array of objects (i.e. first 4 bytes specify how many
			    subsequent objects are part of the array; 0 is legitimate) */
#define DT_LARGE      64 /* new in 0102: if this flag is set then the length of the object
			    is coded as 56-bit integer enlarging the header by 4 bytes */

/* XpressionTypes
   REXP - R expressions are packed in the same way as command parameters
   transport format of the encoded Xpressions:
   [0] int type/len (1 byte type, 3 bytes len - same as SET_PAR)
   [4] REXP attr (if bit 8 in type is set)
   [4/8] data .. */

#define XT_NULL          0 /* data: [0] */
#define XT_INT           1 /* data: [4]int */
#define XT_DOUBLE        2 /* data: [8]double */
#define XT_STR           3 /* data: [n]char null-term. strg. */
#define XT_LANG          4 /* data: same as XT_LIST */
#define XT_SYM           5 /* data: [n]char symbol name */
#define XT_BOOL          6 /* data: [1]byte boolean
			      (1=TRUE, 0=FALSE, 2=NA) */
#define XT_VECTOR        16 /* data: [?]REXP */
#define XT_LIST          17 /* X head, X vals, X tag (since 0.1-5) */
#define XT_CLOS          18 /* X formals, X body  (closure; since 0.1-5) */

#define XT_ARRAY_INT     32 /* data: [n*4]int,int,.. */
#define XT_ARRAY_DOUBLE  33 /* data: [n*8]double,double,.. */
#define XT_ARRAY_STR     34 /* data: [?]string,string,.. */
#define XT_ARRAY_BOOL_UA 35 /* data: [n]byte,byte,..  (unaligned! NOT supported anymore) */
#define XT_ARRAY_BOOL    36 /* data: int(n),byte,byte,... */
#define XT_UNKNOWN       48 /* data: [4]int - SEXP type (as from TYPEOF(x)) */

#define XT_LARGE         64 /* new in 0102: if this flag is set then the length of the object
			       is coded as 56-bit integer enlarging the header by 4 bytes */
#define XT_HAS_ATTR      128 /* flag; if set, the following REXP is the
				attribute */
/* the use of attributes and vectors results in recursive storage of REXPs */

#define BOOL_TRUE  1
#define BOOL_FALSE 0
#define BOOL_NA    2

#define GET_XT(X) ((X)&63)
#define GET_DT(X) ((X)&63)
#define HAS_ATTR(X) (((X)&XT_HAS_ATTR)>0)
#define IS_LARGE(X) (((X)&XT_LARGE)>0)

#if defined sun && ! defined ALIGN_DOUBLES
#define ALIGN_DOUBLES
#endif

/* functions/macros to convert native endianess of int/double for transport
   currently ony PPC style and Intel style are supported */

/* FIXME: all the mess below needs more efficient implementation - the current one is so messy to work around alignment problems on some platforms like Sun and HP 9000 */

#ifdef SWAPEND  /* swap endianness - for PPC and co. */
#ifdef MAIN
unsigned int itop(unsigned int i) { char b[4]; b[0]=((char*)&i)[3]; b[3]=((char*)&i)[0]; b[1]=((char*)&i)[2]; b[2]=((char*)&i)[1]; return *((unsigned int*)b); };
double dtop(double i) { char b[8]; b[0]=((char*)&i)[7]; b[1]=((char*)&i)[6]; b[2]=((char*)&i)[5]; b[3]=((char*)&i)[4]; b[7]=((char*)&i)[0]; b[6]=((char*)&i)[1]; b[5]=((char*)&i)[2]; b[4]=((char*)&i)[3]; return *((double*)b); };
void fixdcpy(void *t,void *s) { int i=0; while (i<8) { ((char*)t)[7-i]=((char*)s)[i]; i++; } };
#else
extern unsigned int itop(unsigned int i);
extern double dtop(double i);
extern void fixdcpy(void *t,void *s);
#endif
#define ptoi(X) itop(X) /* itop*itop=id */
#define ptod(X) dtop(X)
#else
#define itop(X) (X)
#define ptoi(X) (X)
#define dtop(X) (X)
#define ptod(X) (X)
#define fixdcpy(T,S) ((double*)(T))[0]=((double*)(S))[0];
#endif

#ifndef HAVE_CONFIG_H
/* this tiny function can be used to make sure that the endianess
   is correct (it is not included if the package was configured with
   autoconf since then it should be fine anyway) */
#ifdef MAIN
int isByteSexOk() {
  int i;
  i=itop(0x12345678);
  return (*((char*)&i)==0x78);
}
#else
extern int isByteSexOk();
#endif

#else
#define isByteSexOk 1
#endif

#endif
