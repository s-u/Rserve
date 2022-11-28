#ifndef TLS_H__
#define TLS_H__

#include "server.h"

typedef struct tls tls_t;

/* for set_tls_verify() */
#define TLS_NONE      0 /* default */
#define TLS_REQUIRE   1

/* in case shared tls is not set, it will be set to new_tls
   (which can be NULL) */
tls_t *shared_tls(tls_t *new_tls);

tls_t *new_tls(void);
int set_tls_pk(tls_t *tls, const char *fn);
int set_tls_cert(tls_t *tls, const char *fn);
int set_tls_ca(tls_t *tls, const char *fn_ca, const char *path_ca);
int set_tls_verify(tls_t *tls, int verify);
void free_tls(tls_t *tls);

int add_tls(args_t *c, tls_t *tls, int server);
void copy_tls(args_t *src, args_t *dst);
void close_tls(args_t *c);
int verify_peer_tls(args_t *c, char *cn, int len);

int perror_tls(const char *format, ...);
#endif
