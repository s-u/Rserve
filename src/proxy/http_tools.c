#include "http_tools.h"

#include <string.h>

/* returns a pointer to the beginning of a value for a given header
   field or NULL if not present. */
const char *get_header(http_request_t *req, const char *name) {
    const char *c = req->headers, *e;
    int name_len = strlen(name);
    if (!c) return 0;
    while (*c && (e = strchr(c, '\n'))) {
	const char *v = strchr(c, ':');
	if (v && (v < e) && (v - c == name_len)) {
	    int i;
	    for (i = 0; i < name_len; i++)
		if ((name[i] & 0xdf) != (c[i] & 0xdf))
		    break;
	    if (i == name_len) {
		v++;
		while (*v == '\t' || *v == ' ')
		    v++;
		return v;
	    }
	}
	while (*e == '\n' || *e == '\t') e++;
	c = e;
    }
    return 0;
}
