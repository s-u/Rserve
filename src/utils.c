#define USE_RINTERNALS 1
#include <Rversion.h>
#include <Rinternals.h>
#include <R_ext/Parse.h>

/* string encoding handling */
#if (R_VERSION < R_Version(2,8,0)) || (defined DISABLE_ENCODING)
#define mkRChar(X) mkChar(X)
#else
#define USE_ENCODING 1
/* in Rserv.c */
extern cetype_t string_encoding;  /* default is native */
#define mkRChar(X) mkCharCE((X), string_encoding)
#endif

extern Rboolean R_Visible;

/* this is really convoluted - we want to be guaranteed to not leave the call
   on one hand, but on the other hand R_ToplevelExec() removes the context
   which also removes the traceback. So the trick is to use R_ExecWithCleanup()
   to add another layer where we stash the traceback before R_ToplevelExec()
   blows it away. It woudl be really just one extra line in R sources, but
   what can you do ... */

typedef struct rs_eval {
    SEXP what, rho, ctx_obj, last, traceback;
    int exp;
} rs_eval_t;

static SEXP Rserve_eval_do(void *arg) {
    rs_eval_t *e = (rs_eval_t*) arg;
    SEXP what = e->what, rho = e->rho, x;
    int i, n;

    if (TYPEOF(what) == EXPRSXP) {
        n = LENGTH(what);
        for (i = 0; i < n; i++) {
            e->exp = i;
            x = eval(VECTOR_ELT(what, i), rho);
            if (i == n - 1) {
                R_PreserveObject(x);
                e->last = x;
            }
            if (R_Visible)
                PrintValue(x);
        }
    } else {
        e->exp = -1;
        x = eval(what, rho);
        R_PreserveObject(x);
        /* intentionally we don't print if it is not an expression vector */
        e->last = x;
    }
    return R_NilValue;
}

/* it's really stupid becasue R has R_GetTraceback() but we have to
   jump through eval() just because it's hidden so we can't access it ... */
static SEXP R_GetTraceback(int skip) {
    SEXP d_int = install(".Internal"), tb = install("traceback"), sSkip = PROTECT(ScalarInteger(skip));
    SEXP what = PROTECT(lang2(d_int, lang2(tb, sSkip)));
    SEXP res = eval(what, R_GlobalEnv);
    UNPROTECT(2);
    return res;    
}

static void Rserve_eval_cleanup(void *arg) {
    rs_eval_t *e = (rs_eval_t*) arg;
    SEXP tb = R_GetTraceback(0);
    if (tb && tb != R_NilValue)
        R_PreserveObject((e->traceback = tb));
}

static void Rserve_eval_(void *arg) {
    R_ExecWithCleanup(Rserve_eval_do, arg, Rserve_eval_cleanup, arg);
}

static SEXP RS_current_context;
static int  RS_current_context_is_protected;

SEXP Rserve_get_context() {
    return RS_current_context ? RS_current_context : R_NilValue;
}

SEXP Rserve_set_context(SEXP sObj) {
    if (!sObj)
        sObj = R_NilValue;
    if (RS_current_context == sObj) return sObj;
    if (RS_current_context != R_NilValue && RS_current_context_is_protected)
        R_ReleaseObject(RS_current_context);
    RS_current_context = sObj;
    RS_current_context_is_protected = 0;
    if (RS_current_context != R_NilValue) {
        R_PreserveObject(RS_current_context);
        RS_current_context_is_protected = 1;
    }
    return RS_current_context;
}

SEXP Rserve_eval(SEXP what, SEXP rho, SEXP retLast, SEXP retExp, SEXP ctxObj) {
    int need_last = asInteger(retLast), exp_value = asInteger(retExp);
    rs_eval_t e = { what, rho, 0, 0, 0, 0 };
    SEXP saved_context = RS_current_context;
    int  saved_context_is_protected = RS_current_context_is_protected;
    if (ctxObj != R_NilValue) {
        RS_current_context = ctxObj; /* this is transient so no protection */
        RS_current_context_is_protected = 0;
    }
    e.ctx_obj = RS_current_context;
    if (!R_ToplevelExec(Rserve_eval_, &e)) {
        RS_current_context = saved_context;
        RS_current_context_is_protected = saved_context_is_protected;
        SEXP res = PROTECT(mkNamed(VECSXP, (const char*[]) { "error", "traceback", "expression", "context", "" }));
        SET_VECTOR_ELT(res, 1, e.traceback ? e.traceback : R_NilValue);
        const char *errmsg = R_curErrorBuf();
        SET_VECTOR_ELT(res, 0, errmsg ? mkString(errmsg) : R_NilValue);
        if (exp_value)
            SET_VECTOR_ELT(res, 2, (e.exp == -1) ? what : VECTOR_ELT(what, e.exp));
        else
            SET_VECTOR_ELT(res, 2, ScalarInteger(e.exp < 0 ? NA_INTEGER : (e.exp + 1)));
        SET_VECTOR_ELT(res, 3, e.ctx_obj ? e.ctx_obj : R_NilValue);
        setAttrib(res, R_ClassSymbol, mkString("Rserve-eval-error"));
        UNPROTECT(1);
        return res;
    }
    RS_current_context = saved_context;
    RS_current_context_is_protected = saved_context_is_protected;

    if (need_last) {
        if (e.last) {
            R_ReleaseObject(e.last);
            return e.last;
        }
        return R_NilValue;
    }
    return ScalarLogical(TRUE);
}
