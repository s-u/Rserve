/* error I/O that uses either stderr or REprintf depending on the build */
#ifndef RSERR_H__
#define RSERR_H__

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static void RSEprintf(const char *format, ...) {
    va_list(ap);
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

#endif
