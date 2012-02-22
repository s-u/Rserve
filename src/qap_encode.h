#ifndef QAP_ENCODE_H__
#define QAP_ENCODE_H__

#ifndef USE_RINTERNALS
#define USE_RINTERNALS 1
#include <Rinternals.h>
#endif

#include "Rsrv.h"

rlen_t QAP_getStorageSize(SEXP x);
unsigned int* QAP_storeSEXP(unsigned int* buf, SEXP x, rlen_t storage_size);

#endif
