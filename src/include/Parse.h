/* This is a fall-back for R versions that don't have R_ext/Parse.h
   (R versions before 2.1.0) */

#ifndef R_EXT_PARSE_H_
#define R_EXT_PARSE_H_

typedef enum {
    PARSE_NULL,
    PARSE_OK,
    PARSE_INCOMPLETE,
    PARSE_ERROR,
    PARSE_EOF
} ParseStatus;

SEXP R_ParseVector(SEXP, int, ParseStatus *);

#endif
