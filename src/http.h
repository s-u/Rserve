#ifndef HTTP_H__
#define HTTP_H__

#include "RSserver.h"

#define HTTP_WS_UPGRADE 0x10
#define HTTP_RAW_BODY   0x20 /* if set, no attempts are made to decode the request body of known types */

/* static handler flags */
#define HSF_STOP          1 /* stop if prefix matches */
#define HSF_PRECOMPRESSED 2 /* use pre-compressed .gz files */

server_t *create_HTTP_server(int port, int flags);

/* return 0 on error or a pointer to the handler otherwise (we use an opaque pointer for now) */
void *http_add_static_handler(const char *prefix, const char* path, const char *index, int flags);
/* takes a handler pointer - will free it if successful */
void http_rm_static_handler(void *hs);
/* remove all handlers */
void http_rm_all_static_handlers(void);

#endif
