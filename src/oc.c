#include <stdlib.h>

#include "oc.h"
#include "sha1.h"

#ifndef NO_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_TLS
#include <openssl/rand.h>
#endif

#ifndef HAVE_SRANDOMDEV
/* the fall-back is to use time and pid so we need those extra headers */
#include <time.h>
#include <unistd.h>
#endif

static SEXP oc_env;

SEXP oc_resolve(const char *ref) {
    SEXP val;
    if (!oc_env) return R_NilValue;
    val = findVarInFrame(oc_env, install(ref));
    if (val == R_UnboundValue) val = R_NilValue;
    return val;
}

/* this is where we generate tokens. The current apporach is to generate good random
   168-bits and encode them using slightly modified base-64 encoding into a string.
   If we can't get good random bits, we generate more pseudo-random bytes and run
   SHA1 on it.
   The result is almost a valid identifier except that it can start with a number. */
static int rand_inited;

static const char b64map[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.";

/* currently we use 21 bytes = 168 bits --> 28 bytes encoded */
#define MAX_OC_TOKEN_LEN 31

static void oc_new(char *dst) {
    int have_hash = 0, i;
    unsigned char hash[21];

#ifdef HAVE_TLS
    if (RAND_bytes(hash, 21) || RAND_pseudo_bytes(hash, 21))
	have_hash = 1;
#endif

    if (!have_hash) { /* should only be used if TLS is not available or it fails */
	unsigned char rbuf[64];
	if (!rand_inited) {
#ifdef HAVE_SRANDOMDEV
	    srandomdev();
#else
#ifdef Win32		
		srand(time(NULL) ^ (getpid() << 12));
#else
		/* fall back -- mix of time and pid is the best we can do ... */
	    srandom(time(NULL) ^ (getpid() << 12));
#endif
#endif
	    rand_inited = 1;
	}	
#ifdef Win32
	for (i = 0; i < sizeof(rbuf); i++) rbuf[i] = rand();
#else
	for (i = 0; i < sizeof(rbuf); i++) rbuf[i] = random();
#endif
	/* we use random -> SHA1 .. is it an overkill? */
	sha1hash((const char*)rbuf, sizeof(rbuf) - 1, hash);
	/* the last byte is the hold-out byte -- just because SHA gives only 160 bits */
	hash[20] = rbuf[sizeof(rbuf) - 1];
    }
    for (i = 0; i < 21; i += 3) {
	*(dst++) = b64map[hash[i] & 63];
	*(dst++) = b64map[((hash[i] >> 6) | (hash[i + 1] << 2)) & 63];
	*(dst++) = b64map[((hash[i + 1] >> 4) | (hash[i + 2] << 4)) & 63];
	*(dst++) = b64map[hash[i + 2] >> 2];
    }
    *dst = 0;
}

char *oc_register(SEXP what, char *dst, int len, const char *name) {
    SEXP x;
    if (len <= MAX_OC_TOKEN_LEN) return NULL;
    if (!oc_env) {
	SEXP env = eval(PROTECT(lang3(install("new.env"), ScalarLogical(TRUE), R_EmptyEnv)), R_GlobalEnv);
	UNPROTECT(1);
	if (TYPEOF(env) != ENVSXP) return NULL;
	oc_env = env;
	R_PreserveObject(oc_env);
    }
    x = PROTECT(CONS(what, R_NilValue));
    if (name) SET_TAG(x, install(name));
    oc_new(dst);
    Rf_defineVar(install(dst), x, oc_env);
    UNPROTECT(1);
    return dst;
}

/* --- R-side API --- */

/* NOTE: if you change the signature, you *have* to change the registration
   and declaration in standalone.c !! */
SEXP Rserve_oc_register(SEXP what, SEXP sName) {
    const char *name = 0;
    char token[MAX_OC_TOKEN_LEN + 1];
    SEXP res;
    if (TYPEOF(sName) == STRSXP && LENGTH(sName) > 0)
	name = CHAR(STRING_ELT(sName, 0));
    if (!oc_register(what, token, sizeof(token), name))
	Rf_error("Cannot create OC reference registry");
    res = PROTECT(mkString(token));
    setAttrib(res, R_ClassSymbol, mkString("OCref"));
    UNPROTECT(1);
    return res;
}

SEXP Rserve_oc_resolve(SEXP what) {
    SEXP res;
    if (!inherits(what, "OCref") || TYPEOF(what) != STRSXP || LENGTH(what) != 1)
	Rf_error("invalid OCref");
    return CAR(oc_resolve(CHAR(STRING_ELT(what, 0))));
}
