#include "chandler.h"

struct content_handler {
    struct content_handler *next;
    content_handler_fn_t process_request;
};

static content_handler_t *handlers;

content_handler_t *add_content_handler(content_handler_fn_t fn) {
    content_handler_t *h = malloc(sizeof(content_handler_t)), *tail;
    if (!h) return 0;
    h->next = 0;
    h->process_request = fn;
    if (!handlers)
        return (handlers = h);
    tail = handlers;
    while (tail->next) tail = tail->next;
    return (tail->next = h);
}

content_handler_t *call_content_handlers(http_request_t *req, http_result_t *res, const char *path) {
    content_handler_t *h = handlers;
    while (h) {
        if (h->process_request(req, res, path)) return h;
        h = h->next;
    }
    return h;
}

void free_content_handlers() {
    while (handlers) {
        content_handler_t *n = handlers->next;
        free(handlers);
        handlers = n;
    }
}
