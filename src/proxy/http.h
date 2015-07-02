#ifndef HTTP_H__
#define HTTP_H__

#ifdef NO_WEBSOCKETS
#include "server.h"
#else
#include "websockets.h"
#endif

typedef struct {
    char  *url;
    char  *body;
    size_t body_len;
    char  *query;
    char  *headers;
    double date;
} http_request_t;

#define PAYLOAD_VERBATIM 0
#define PAYLOAD_FILE     1
#define PAYLOAD_TEMPFILE 2

typedef struct {
    char *err;
    char *payload;
    size_t payload_len;
    int payload_type;
    char *content_type;
    char *headers;
    double date;
    int code;
} http_result_t;
	
typedef void (*http_handler_fn_t)(http_request_t *req, http_result_t *res);

#define HTTP_WS_UPGRADE 0x10
#define HTTP_RAW_BODY   0x20 /* if set, no attempts are made to decode the request body of known types */

#ifdef NO_WEBSOCKETS
server_t *create_HTTP_server(int port, int flags, http_handler_fn_t handler, void *dummy);
#else
server_t *create_HTTP_server(int port, int flags, http_handler_fn_t handler, ws_connected_fn_t ws_connected);
#endif

#endif
