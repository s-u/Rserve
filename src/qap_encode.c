#include <stdlib.h>
#include <string.h>

#include "qap_encode.h"
#include <Rversion.h>

/* compatibility re-mapping */
#define getStorageSize QAP_getStorageSize
#define storeSEXP      QAP_storeSEXP

/* FIXME: we should move this to some common place ... */
/* string encoding handling */
#if (R_VERSION < R_Version(2,8,0)) || (defined DISABLE_ENCODING)
#define mkRChar(X) mkChar(X)
#define CHAR_FE(X) CHAR(X)
#else
#define USE_ENCODING 1
extern cetype_t string_encoding;
#define mkRChar(X) mkCharCE((X), string_encoding)
#define CHAR_FE(X) charsxp_to_current(X)
static const char *charsxp_to_current(SEXP s) {
	if (Rf_getCharCE(s) == string_encoding) return CHAR(s);
	return Rf_reEnc(CHAR(s), getCharCE(s), string_encoding, 0);
}
#endif

/* this is the representation of NAs in strings. We chose 0xff since that should never occur in UTF-8 strings. If 0xff occurs in the beginning of a string anyway, it will be doubled to avoid misrepresentation. */
static const unsigned char NaStringRepresentation[2] = { 255, 0 };

#define attrFixup if (hasAttr) buf = storeSEXP(buf, ATTRIB(x), 0);
#define dist(A,B) (((rlen_t)(((char*)B)-((char*)A))) - 4L)
#define align(A) (((A) + 3L) & (rlen_max ^ 3L))

rlen_t getStorageSize(SEXP x) {
    int t = TYPEOF(x);
    rlen_t tl = LENGTH(x); /* although LENGTH can only be 32-bit use rlen_t to avoid downcasting */
    rlen_t len = 4;
    
#ifdef RSERV_DEBUG
    printf("getStorageSize(%p,type=%d,len=%ld) ", (void*)x, t, tl);
#endif
    if (t != CHARSXP && TYPEOF(ATTRIB(x)) == LISTSXP) {
		rlen_t alen = getStorageSize(ATTRIB(x));
		len += alen;
    }
    switch (t) {
    case LISTSXP:
    case LANGSXP:
		{
			SEXP l = x;
			rlen_t tags = 0, n = 0;
			while (l != R_NilValue) {
				len  += getStorageSize(CAR(l));
				tags += getStorageSize(TAG(l));
				n++;
				l = CDR(l);
			}
			if (tags > 4L * n) len += tags; /* use tagged list */
		}
		break;
    case CLOSXP:
		len+=getStorageSize(FORMALS(x));
		len+=getStorageSize(BODY(x));
		break;
	case CPLXSXP:
		len += tl * 16L; break;
    case REALSXP:
		len += tl * 8L; break;
    case INTSXP:
		len += tl * 4L; break;
    case LGLSXP:
	case RAWSXP:
		if (tl > 1)
			len += 4L + align(tl);
		else
			len += 4L;	
		break;
		
    case SYMSXP:
    case CHARSXP:
		{
			const char *ct = ((t==CHARSXP) ? CHAR_FE(x) : CHAR_FE(PRINTNAME(x)));
			if (!ct)
				len += 4L;
			else {
				rlen_t sl = strlen(ct) + 1L;				
				len += align(sl);
			}
		}
		break;
    case STRSXP:
		{
			unsigned int i = 0;
			while (i < tl) {
				len += getStorageSize(STRING_ELT(x, i));
				i++;
			}
		}
		break;
    case EXPRSXP:
    case VECSXP:
		{
			unsigned int i = 0;
			while(i < tl) {
				len += getStorageSize(VECTOR_ELT(x,i));
				i++;
			}
		}
		break;
	case S4SXP:
		/* S4 really has the payload in attributes, so it doesn't occupy anything */
		break;
    default:
		len += 4L; /* unknown types are simply stored as int */
    }
    if (len > 0xfffff0) /* large types must be stored in the new format */
		len += 4L;
#ifdef RSERV_DEBUG
    printf("= %lu\n", len);
#endif
    return len;
}

/* if storage_size is > 0 then it it used instad of a call to getStorageSize() */
unsigned int* storeSEXP(unsigned int* buf, SEXP x, rlen_t storage_size) {
    int t = TYPEOF(x);
    int hasAttr = 0;
    int isLarge = 0;
    unsigned int *preBuf = buf;
    rlen_t txlen;

    if (!x) { /* null pointer will be treated as XT_NULL */
		*buf = itop(XT_NULL); buf++; goto didit;
    }
    
    if (t != CHARSXP && TYPEOF(ATTRIB(x)) == LISTSXP)
		hasAttr = XT_HAS_ATTR;
    
    if (t == NILSXP) {
		*buf = itop(XT_NULL | hasAttr);
		buf++;
		attrFixup;
		goto didit;
    } 
    
    /* check storage size */
    if (!storage_size) storage_size = getStorageSize(x);
    txlen = storage_size;
    if (txlen > 0xfffff0) { /* if the entry is too big, use large format */
		isLarge = 1;
		buf++;
    }
    
    if (t==LISTSXP || t==LANGSXP) {
		SEXP l = x;
		rlen_t tags = 0;
		while (l != R_NilValue) {
			if (TAG(l) != R_NilValue) tags++;
			l = CDR(l);
		}
		/* note that we are using the fact that XT_LANG_xx=XT_LIST_xx+2 */
		*buf = itop((((t == LISTSXP) ? 0 : 2) + (tags ? XT_LIST_TAG : XT_LIST_NOTAG)) | hasAttr);
		buf++;
		attrFixup;
		l = x;
		while (l != R_NilValue) {			
			buf = storeSEXP(buf, CAR(l), 0);
			if (tags)
				buf = storeSEXP(buf, TAG(l), 0);
			l = CDR(l);
		}
		goto didit;
    }
    
    if (t==CLOSXP) { /* closures (send FORMALS and BODY) */
		*buf=itop(XT_CLOS|hasAttr);
		buf++;
		attrFixup;
		buf=storeSEXP(buf, FORMALS(x), 0);
		buf=storeSEXP(buf, BODY(x), 0);
		goto didit;
    }
    
    if (t==REALSXP) {
		*buf=itop(XT_ARRAY_DOUBLE|hasAttr);
		buf++;
		attrFixup;
#ifdef NATIVE_COPY
		memcpy(buf, REAL(x), sizeof(double) * LENGTH(x));
		buf += LENGTH(x) * sizeof(double) / sizeof(*buf);
#else
		{
		    R_len_t i = 0;
		    while(i < LENGTH(x)) {
			fixdcpy(buf, REAL(x) + i);
			buf += 2; /* sizeof(double)=2*sizeof(int) */
			i++;
		    }
		}
#endif
		goto didit;
    }

    if (t==CPLXSXP) {
		*buf = itop(XT_ARRAY_CPLX|hasAttr);
		buf++;
		attrFixup;
#ifdef NATIVE_COPY
		memcpy(buf, COMPLEX(x), LENGTH(x) * sizeof(*COMPLEX(x)));
		buf += LENGTH(x) * sizeof(*COMPLEX(x)) / sizeof(*buf);
#else
		{
		    R_len_t i = 0;
		    while(i < LENGTH(x)) {
			fixdcpy(buf, &(COMPLEX(x)[i].r));
			buf += 2; /* sizeof(double)=2*sizeof(int) */
			fixdcpy(buf, &(COMPLEX(x)[i].i));
			buf += 2; /* sizeof(double)=2*sizeof(int) */
			i++;
		    }
		}
#endif
		goto didit;
    }

	if (t==RAWSXP) {
		R_len_t ll = LENGTH(x);
		*buf = itop(XT_RAW | hasAttr);
		buf++;
		attrFixup;
		*buf = itop(ll); buf++;
		if (ll) memcpy(buf, RAW(x), ll);
		ll += 3; ll /= 4;
		buf += ll;
		goto didit;
	}
		
    if (t==LGLSXP) {
		R_len_t ll = LENGTH(x), i = 0;
		int *lgl = LOGICAL(x);
		*buf = itop(XT_ARRAY_BOOL | hasAttr);
		buf++;
		attrFixup;
		*buf = itop(ll); buf++;
		while(i < ll) { /* logical values are stored as bytes of values 0/1/2 */
			int bv = lgl[i];
			*((unsigned char*)buf) = (bv == 0) ? 0 : (bv==1) ? 1 : 2;
			buf = (unsigned int*)(((unsigned char*)buf) + 1);
			i++;
		}
		/* pad by 0xff to a multiple of 4 */
		while (i & 3) {
			*((unsigned char*)buf) = 0xff;
			i++;
			buf=(unsigned int*)(((unsigned char*)buf) + 1);
		}
		goto didit;
    }
    
	if (t == STRSXP) {
		char *st;
		R_len_t nx = LENGTH(x), i;
		*buf = itop(XT_ARRAY_STR|hasAttr);
		buf++;
		attrFixup;
		/* leading int n; is not needed due to the choice of padding */
		st = (char *)buf;
		for (i = 0; i < nx; i++) {
			const char *cv = CHAR_FE(STRING_ELT(x, i));
			rlen_t l = strlen(cv);
			if (STRING_ELT(x, i) == R_NaString) {
				cv = (const char*) NaStringRepresentation;
				l = 1;
			} else if ((unsigned char) cv[0] == NaStringRepresentation[0]) /* we will double the leading 0xff to avoid abiguity between NA and "\0xff" */
				(st++)[0] = (char) NaStringRepresentation[0];
			strcpy(st, cv);
			st += l + 1;
		}
		/* pad with '\01' to make sure we can determine the number of elements */
		while ((st - (char*)buf) & 3) *(st++) = 1;
		buf = (unsigned int*)st;
		goto didit;
	}

    if (t==EXPRSXP || t==VECSXP) {
		R_len_t i = 0, n = LENGTH(x);
		*buf = itop(((t == EXPRSXP) ? XT_VECTOR_EXP : XT_VECTOR) | hasAttr);
		buf++;
		attrFixup;
		while(i < n) {
			buf = storeSEXP(buf, VECTOR_ELT(x, i), 0);
			i++;
		}
		goto didit;
    }
	
    if (t==INTSXP) {
		R_len_t n = LENGTH(x);
		int *iptr = INTEGER(x);
		*buf = itop(XT_ARRAY_INT | hasAttr);
		buf++;
		attrFixup;
#ifdef NATIVE_COPY
		memcpy(buf, iptr, n * sizeof(int));
		buf += n;
#else
		{
		    R_len_t i = 0;
		    while(i < n) {
			*buf = itop(iptr[i]);
			buf++;
			i++;
		    }
		}
#endif
		goto didit;
    }

    if (t==S4SXP) {
		*buf=itop(XT_S4|hasAttr);
		buf++;
		attrFixup;
		goto didit;		
	}
	
    if (t==CHARSXP||t==SYMSXP) {
		rlen_t sl;
		const char *val;
		if (t == CHARSXP) {
			*buf = itop(XT_STR | hasAttr);
			val = CHAR_FE(x);
		} else {
			*buf = itop(XT_SYMNAME | hasAttr);
			val = CHAR_FE(PRINTNAME(x));
		}
		buf++;
		attrFixup;
		strcpy((char*)buf, val);
		sl = strlen((char*)buf); sl++;
		while (sl & 3) /* pad by 0 to a length divisible by 4 (since 0.1-10) */
			((char*)buf)[sl++] = 0;
		buf = (unsigned int*)(((char*)buf) + sl);
		goto didit;
    }
	
    *buf = itop(XT_UNKNOWN | hasAttr);
    buf++;
    attrFixup;
    *buf = itop(TYPEOF(x));
    buf++;
    
 didit:
    if (isLarge) {
		txlen = dist(preBuf, buf) - 4L;
		preBuf[0] = itop(SET_PAR(PAR_TYPE(((unsigned char*) preBuf)[4] | XT_LARGE), txlen & 0xffffff));
		preBuf[1] = itop(txlen >> 24);
    } else
		*preBuf = itop(SET_PAR(PAR_TYPE(ptoi(*preBuf)), dist(preBuf, buf)));

#ifdef RSERV_DEBUG
	printf("stored %p at %p, %lu bytes\n", (void*)x, (void*)preBuf, (unsigned long) dist(preBuf, buf));
#endif

    if (dist(preBuf, buf) > storage_size) {
#ifdef RSERVE_PKG
      REprintf("**ERROR: underestimated storage %ld / %ld SEXP type %d\n", (long) dist(preBuf, buf), (long) storage_size, TYPEOF(x));
#else
      fprintf(stderr, "**ERROR: underestimated storage %ld / %ld SEXP type %d\n", (long) dist(preBuf, buf), (long) storage_size, TYPEOF(x));
#endif
      /* R_inspect(x)  // can't use this since it's hidden in R */
    }

    return buf;
}
