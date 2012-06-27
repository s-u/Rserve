#ifndef HTTP_H__
#define HTTP_H__

#include "RSserver.h"

#define HTTP_WS_UPGRADE 0x10

server_t *create_HTTP_server(int port, int flags);

#endif
