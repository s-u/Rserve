#ifndef QAP_DECODE_H__
#define QAP_DECODE_H__

#ifndef USE_RINTERNALS
#define USE_RINTERNALS 1
#include <Rinternals.h>
#endif

#include "Rsrv.h"

SEXP QAP_decode(unsigned int **buf);

#endif
