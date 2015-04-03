#ifndef BSD_CMPT_H__
#define BSD_CMPT_H__

/* Implementation of BSD-specific pieces used in the proxy that are missing
   on other platforms. Curretnly we only used it on OS X but we should add
   a cfg check for other BSD variants.
*/

#include <string.h>

#ifdef __APPLE__
#define MTIME(X) (X).st_mtimespec.tv_sec
#else
#define MTIME(X) (X).st_mtime

/* not part of Linux/POSIX so implement it ... */
static const char *strnstr(const char *haystack, const char *needle, size_t len) {
    const char *eohs = haystack + len;
    size_t nl = strlen(needle);
    while (eohs - haystack >= nl &&
           (haystack = memchr(haystack, needle[0], eohs - haystack)))
        if (!memcmp(haystack, needle, nl)) return haystack; else haystack++;
    return 0;
}
#endif

#endif
