#include "http.h"

/* handlers return 0 if they choose to not handle the request.
   If a handler doesn't choose to handle the request it is not allowed
   to modify req/res.
   If path is present it is the full path to the resource.
*/
typedef int (*content_handler_fn_t)(http_request_t *req, http_result_t *res, const char *path);

typedef struct content_handler content_handler_t;

/* add a new handler function (at the end) and return the corresponding handler.
   May return NULL if the handler cannot be allocated. */
content_handler_t *add_content_handler(content_handler_fn_t fn);

/* call registered handlers sequentially. Returns the handler
   that took the request (if any) or NULL otherwise. */
content_handler_t *call_content_handlers(http_request_t *req, http_result_t *res, const char *path);

/* release all handlers */
void free_content_handlers();
