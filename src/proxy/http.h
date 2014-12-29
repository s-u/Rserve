#ifndef HTTP_H__
#define HTTP_H__

#include "RSserver.h"

#define HTTP_WS_UPGRADE 0x10
#define HTTP_RAW_BODY   0x20 /* if set, no attempts are made to decode the request body of known types */

server_t *create_HTTP_server(int port, int flags);

#endif
