#ifndef WEBSOCKETS_H__
#define WEBSOCKETS_H__

#include "RSserver.h"

#define WS_PROT_QAP   0x01
#define WS_PROT_TEXT  0x02
/* NOTE: this is not the same as SRV_TLS! It is annoying, but WS needs to 
   chain TLS futher down, if SRC_TLS is set then QAP will be tunneled
   through TLS but we need to wrap WS around it first */
#define WS_TLS        0x08 
/* WARNING: HTTP uses 0x10 and 0x20 */

#define WS_PROT_ALL   (WS_PROT_QAP | WS_PROT_TEXT)

server_t *create_WS_server(int port, int protocols);

/* upgrade HTTP connection to WS - assumes that the HTTP server has parsed the request already
   only WS 13+ handshake is supported by this function */
void WS13_upgrade(args_t *arg, const char *key, const char *protocol, const char *version);

/* flags used in args_t.flags */
#define F_INFRAME 0x010
#define F_MASK    0x020
#define F_IN_BIN  0x040
#define F_OUT_BIN 0x080

#define SET_F_FT(X, FT) X = (((X) & 0xfff) | (((FT) & 15) << 12))
#define GET_F_FT(X) (((X) >> 12) & 15)

#define GET_MASK_ID(X) ((X) & 3)
#define SET_F_MASK(X, M) X = (((X) & 0xfffc) | F_MASK | ((M) & 3))


#endif
