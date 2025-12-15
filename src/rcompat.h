/* R compatibilty macros - working around re-mapped API points */
#ifndef RCOMPAT_H__
#define RCOMPAT_H__

#include <Rversion.h>

#if (R_VERSION >= R_Version(2,0,0))
/* EXTPTR */
#ifdef  EXTPTR_PTR
#undef  EXTPTR_PTR
#endif
#define EXTPTR_PTR(X) R_ExternalPtrAddr(X)
#ifdef  EXTPTR_PROT
#undef  EXTPTR_PROT
#endif
#define EXTPTR_PROT(X) R_ExternalPtrProtected(X)
#ifdef  EXTPTR_TAG
#undef  EXTPTR_TAG
#endif
#define EXTPTR_TAG(X) R_ExternalPtrTag(X)
/* CLOSXP */
#ifdef  BODY_EXPR
#undef  BODY_EXPR
#endif
#define BODY_EXPR(X) R_ClosureExpr(X)
#endif

#if (R_VERSION >= R_Version(4,5,0))
/* CLOSXP - new API in 4.5.0 */
#ifdef BODY
#undef BODY
#endif
#define BODY(X) R_ClosureBody(X)
#ifdef FORMALS
#undef FORMALS
#endif
#define FORMALS(X) R_ClosureFormals(X)
#ifdef CLOENV
#undef CLOENV
#endif
#define CLOENV(X) R_ClosureEnv(X)
#endif /* R 4.5.0 */

#endif /* RCOMPAT_H__ */
