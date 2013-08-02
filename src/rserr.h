/* error I/O that uses either stderr or REprintf depending on the build */
#ifndef RSERR_H__
#define RSERR_H__

#ifndef NO_CONFIG_H
#include "config.h"
#endif

#if defined STANDALONE_RSERVE && defined RSERVE_PKG
#undef RSERVE_PKG
#endif

#include <stdio.h>
#include <stdarg.h>

#ifndef STANDALONE_RSERVE
#include <R_ext/Print.h>  /* for REvprintf */
#endif

static void RSEprintf(const char *format, ...) {
    va_list(ap);
    va_start(ap, format);
#ifdef STANDALONE_RSERVE
    vfprintf(stderr, format, ap);
#else
    REvprintf(format, ap);
#endif
    va_end(ap);
}

#endif
