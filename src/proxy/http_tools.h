#ifndef HTTP_TOOLS_H__
#define HTTP_TOOLS_H__

#include "http.h"

/* from date.c */
char  *posix2http(double);
double http2posix(const char*);

const char *get_header(http_request_t *req, const char *name);

#endif
