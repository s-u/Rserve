#ifndef OC_H__
#define OC_H__

#include <Rinternals.h>

SEXP oc_resolve(const char *ref);
char *oc_register(SEXP what, char *dst, int len, const char *name);

#endif
