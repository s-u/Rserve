#include "qap_decode.h"

#include <Rversion.h>
#include <string.h>

#define decode_to_SEXP QAP_decode 

/* string encoding handling */
#if (R_VERSION < R_Version(2,8,0)) || (defined DISABLE_ENCODING)
#define mkRChar(X) mkChar(X)
#else
#define USE_ENCODING 1
extern cetype_t string_encoding;
#define mkRChar(X) mkCharCE((X), string_encoding)
#endif

/* this is the representation of NAs in strings. We chose 0xff since that should never occur in UTF-8 strings. If 0xff occurs in the beginning of a string anyway, it will be doubled to avoid misrepresentation. */
static const unsigned char NaStringRepresentation[2] = { 255, 0 };

/* decode_toSEXP is used to decode SEXPs from binary form and create
   corresponding objects in R. UPC is a pointer to a counter of
   UNPROTECT calls which will be necessary after we're done.
   The buffer position is advanced to the point where the SEXP ends
   (more precisely it points to the next stored SEXP). */
SEXP decode_to_SEXP(unsigned int **buf)
{
    unsigned int *b = *buf, *pab = *buf;
    char *c, *cc;
    SEXP val = 0, vatt = 0;
    int ty = PAR_TYPE(ptoi(*b));
    rlen_t ln = PAR_LEN(ptoi(*b));
    R_len_t i, l;
    
    if (IS_LARGE(ty)) {
	ty ^= XT_LARGE;
	b++;
	ln |= ((rlen_t) (unsigned int) ptoi(*b)) << 24;
    }
#ifdef RSERV_DEBUG
    printf("decode: type=%d, len=%ld\n", ty, (long)ln);
#endif
    b++;
    pab = b; /* pre-attr b */

    if (ty & XT_HAS_ATTR) {
#ifdef RSERV_DEBUG
	printf(" - has attributes\n");
#endif
	*buf = b;
	vatt = PROTECT(decode_to_SEXP(buf));
	b = *buf;
	ty = ty ^ XT_HAS_ATTR;
#ifdef RSERV_DEBUG
	printf(" - returned from attributes(@%p)\n", (void*)*buf);
#endif
	ln -= (((char*)b) - ((char*)pab)); /* adjust length */
    }

    /* b = beginning of the SEXP data (after attrs)
       pab = beginning before attrs (=just behind the heaer)
       ln = length of th SEX payload (w/o attr) */
    switch(ty) {
    case XT_NULL:
	val = R_NilValue;
	*buf = b;
	break;
	
    case XT_INT:
    case XT_ARRAY_INT:
	l = ln / 4;
	val = allocVector(INTSXP, l);
#ifdef NATIVE_COPY
	memcpy(INTEGER(val), b, l * sizeof(int));
	b += l;
#else
	i = 0;
	while (i < l) {
	    INTEGER(val)[i] = ptoi(*b); i++; b++;
	}
#endif
	*buf = b;
	break;

    case XT_ARRAY_BOOL:
	{
	    int vl = ptoi(*(b++));
	    char *cb = (char*) b;
	    val = allocVector(LGLSXP, vl);
	    i = 0;
	    while (i < vl) {
		LOGICAL(val)[i] = (cb[i] == 1) ? TRUE : ((cb[i] == 0) ? FALSE : NA_LOGICAL);
		i++;
	    }
	    while ((i & 3) != 0) i++;
	    b = (unsigned int*) (cb + i);
	}
	*buf = b;
	break;

    case XT_DOUBLE:
    case XT_ARRAY_DOUBLE:
	l = ln / 8;
	val = allocVector(REALSXP, l);
#ifdef NATIVE_COPY
	memcpy(REAL(val), b, sizeof(double) * l);
	b += l * 2;
#else
	i = 0;
	while (i < l) {
	    fixdcpy(REAL(val) + i, b);
	    b += 2;
	    i++;
	}
#endif
	*buf = b;
	break;
	
    case XT_ARRAY_CPLX:
	l = ln / 16;
	val = allocVector(CPLXSXP, l);
#ifdef NATIVE_COPY
	memcpy(COMPLEX(val), b, sizeof(*COMPLEX(val)) * l);
	b += l * 4;
#else
	i = 0;
	while (i < l) {
	    fixdcpy(&(COMPLEX(val)[i].r),b); b+=2;
	    fixdcpy(&(COMPLEX(val)[i].i),b); b+=2;
	    i++;
	}
#endif
	*buf = b;
	break;

    case XT_ARRAY_STR:
	{
	    /* count the number of elements */
	    char *sen = (c = (char*)(b)) + ln;
	    i = 0;
	    while (c < sen) {
		if (!*c) i++;
		c++;
	    }

	    /* protect so we can alloc CHARSXPs */
	    val = PROTECT(allocVector(STRSXP, i));
	    i = 0; cc = c = (char*)b;
	    while (c < sen) {
		SEXP sx;
		if (!*c) {
		    if ((unsigned char)cc[0] == NaStringRepresentation[0]) {
			if ((unsigned char)cc[1] == NaStringRepresentation[1])
			    sx = R_NaString;
			else
			    sx = mkRChar(cc + 1);
		    } else sx = mkRChar(cc);
		    SET_STRING_ELT(val, i, sx);
		    i++;
		    cc = c + 1;
		}
		c++;
	    }
	    UNPROTECT(1);
	}
	*buf = (unsigned int*)((char*)b + ln);
	break;
	
    case XT_RAW:
	i = ptoi(*b);
	val = allocVector(RAWSXP, i);
	memcpy(RAW(val), (b + 1), i);
	*buf = (unsigned int*)((char*)b + ln);
	break;
	
    case XT_VECTOR:
    case XT_VECTOR_EXP:
	{
	    unsigned char *ie = (unsigned char*) b + ln;
	    R_len_t n = 0;
	    SEXP lh = R_NilValue;
	    SEXP vr = allocVector(VECSXP, 1);
	    *buf = b;
	    PROTECT(vr);
	    while ((unsigned char*)*buf < ie) {
		SEXP v = decode_to_SEXP(buf);
		lh = CONS(v, lh);
		SET_VECTOR_ELT(vr, 0, lh); /* this is our way of staying protected .. maybe not optimal .. */
		n++;
	    }
#ifdef RSERV_DEBUG
	    printf(" vector (%s), %d elements\n", (ty == XT_VECTOR) ? "generic" : ((ty == XT_VECTOR_EXP) ? "expression" : "string"), n);
#endif
	    val = PROTECT(allocVector((ty==XT_VECTOR) ? VECSXP : ((ty == XT_VECTOR_EXP) ? EXPRSXP : STRSXP), n));
	    while (n > 0) {
		n--;
		SET_VECTOR_ELT(val, n, CAR(lh));
		lh = CDR(lh);
	    }
#ifdef RSERV_DEBUG
	    printf(" end of vector %lx/%lx\n", (long) *buf, (long) ie);
#endif
	    UNPROTECT(2); /* val and vr */
	    break;
	}

    case XT_STR:
    case XT_SYMNAME:
		/* i=ptoi(*b);
		   b++; */
#ifdef RSERV_DEBUG
		printf(" string/symbol(%d) '%s'\n", ty, (char*)b);
#endif
		{
		    char *c = (char*) b;
		    if (ty == XT_STR) {
			val = mkRChar(c);
		    } else
			val = install(c);
		}
		*buf = (unsigned int*)((char*)b + ln);
		break;

    case XT_S4:
	val = Rf_allocS4Object();
	break;
	
    case XT_LIST_NOTAG:
    case XT_LIST_TAG:
    case XT_LANG_NOTAG:
    case XT_LANG_TAG:
	{
	    SEXP vnext = R_NilValue, vtail = 0;
	    unsigned char *ie = (unsigned char*) b + ln;
	    val = R_NilValue;
	    *buf = b;
	    while ((unsigned char*)*buf < ie) {
#ifdef RSERV_DEBUG
		printf(" el %08lx of %08lx\n", (unsigned long)*buf, (unsigned long) ie);
#endif
		SEXP el = PROTECT(decode_to_SEXP(buf));
		SEXP ea = R_NilValue;
		if (ty == XT_LANG_TAG || ty==XT_LIST_TAG) {
#ifdef RSERV_DEBUG
		    printf(" tag %08lx of %08lx\n", (unsigned long)*buf, (unsigned long) ie);
#endif
		    ea = decode_to_SEXP(buf);
		    if (ea != R_NilValue) PROTECT(ea);
		}
		if (ty == XT_LANG_TAG || ty == XT_LANG_NOTAG)
		    vnext = LCONS(el, R_NilValue);
		else
		    vnext = CONS(el, R_NilValue);
		PROTECT(vnext);
		if (ea != R_NilValue)
		    SET_TAG(vnext, ea);
		if (vtail) {
		    SETCDR(vtail, vnext);
		    UNPROTECT((ea == R_NilValue) ? 2 : 3);
		} else {
		    UNPROTECT((ea == R_NilValue) ? 2 : 3);
		    val = vnext;
		    PROTECT(val); /* protect the root */
		}
		vtail = vnext;				   
	    }
	    if (vtail) UNPROTECT(1);
	    break;
	}
	default:
	    REprintf("Rserve SEXP parsing: unsupported type %d\n", ty);
	    val = R_NilValue;
	    *buf = (unsigned int*)((char*)b + ln);
    }
    
    if (vatt) {
	/* if vatt contains "class" we have to set the object bit [we could use classgets(vec,kls) instead] */
	SEXP head = vatt;
	int has_class = 0;
	PROTECT(val);
	SET_ATTRIB(val, vatt);
	while (head != R_NilValue) {
	    if (TAG(head) == R_ClassSymbol) {
		has_class = 1; break;
	    }
	    head = CDR(head);
	}
	if (has_class) /* if it has a class slot, we have to set the object bit */
	    SET_OBJECT(val, 1);
#ifdef SET_S4_OBJECT
	/* FIXME: we have currently no way of knowing whether an object
	   derived from a non-S4 type is actually S4 object. Hence
	   we can only flag "pure" S4 objects */
	if (TYPEOF(val) == S4SXP)
	    SET_S4_OBJECT(val);
#endif
	UNPROTECT(2); /* vatt + val */
    }
    /* NOTE: val is NOT protected - this guarantees that recursion doesn't fill up the stack */
    return val;
}

