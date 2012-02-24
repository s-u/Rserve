#ifndef WEBSOCKETS_H__
#define WEBSOCKETS_H__

#include "RSserver.h"

#define WS_PROT_QAP   0x01
#define WS_PROT_TEXT  0x02

#define WS_PROT_ALL   (WS_PROT_QAP | WS_PROT_TEXT)

server_t *create_WS_server(int port, int protocols);

#endif
