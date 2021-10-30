#ifndef NO_CONFIG_H
#include "config.h"
#endif

#include "tls.h"

#ifdef HAVE_TLS

#include <openssl/ssl.h>
#ifdef RSERV_DEBUG
#include <openssl/err.h>
#endif

struct tls {
    SSL_CTX *ctx;
    const SSL_METHOD *method;
};

static int first_tls = 1;

static tls_t *tls;

tls_t *shared_tls(tls_t *new_tls) {
    if (!tls)
	tls = new_tls;
    return tls;
}

tls_t *new_tls() {
    tls_t *t = (tls_t*) calloc(1, sizeof(tls_t));
    
    if (first_tls) {
	SSL_library_init();
#ifdef RSERV_DEBUG
	SSL_load_error_strings();
#endif
	first_tls = 0;
	tls = t;
    }

    t->method = SSLv23_server_method();
    t->ctx = SSL_CTX_new(t->method);
    return t;
}

int set_tls_pk(tls_t *tls, const char *fn) {
    return SSL_CTX_use_PrivateKey_file(tls->ctx, fn, SSL_FILETYPE_PEM);
}

int set_tls_cert(tls_t *tls, const char *fn) {
    return SSL_CTX_use_certificate_file(tls->ctx, fn, SSL_FILETYPE_PEM);
}

int set_tls_ca(tls_t *tls, const char *fn_ca, const char *path_ca) {
    return SSL_CTX_load_verify_locations(tls->ctx, fn_ca, path_ca);
}

int set_tls_verify(tls_t *tls, int verify) {
    SSL_CTX_set_verify(tls->ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, 0);
    return 1;
}

struct args {
    server_t *srv; /* server that instantiated this connection */
    int s;
    int ss;
    int msg_id;
    SSL *ssl;
    void *res2;
};

static int tls_recv(args_t *c, void *buf, rlen_t len) {
    return SSL_read(c->ssl, buf, len);
}

static int tls_send(args_t *c, const void *buf, rlen_t len) {
    return SSL_write(c->ssl, buf, len);
}

int add_tls(args_t *c, tls_t *tls, int server) {
    c->ssl = SSL_new(tls->ctx);
    c->srv->send = tls_send;
    c->srv->recv = tls_recv;
    SSL_set_fd(c->ssl, c->s);
    if (server) 
	return SSL_accept(c->ssl);
    else
	return SSL_connect(c->ssl);
}

void copy_tls(args_t *src, args_t *dst) {
    dst->ssl = src->ssl;
    dst->s   = src->s;
    dst->srv->send = src->srv->send;
    dst->srv->recv = src->srv->recv;
}

void close_tls(args_t *c) {
    if (c->ssl) {
	SSL_shutdown(c->ssl);
	SSL_free(c->ssl);
	c->ssl = 0;
    }
}

void free_tls(tls_t *tls) {
}

/* if cn is present, len > 0 and there is a cert then the common name
   is copied to cn and terminated. It may be truncated if len is too short.
   Return values:
   0 = present but verification failed
   1 = present and verification successful
  -1 = absent */
int verify_peer_tls(args_t *c, char *cn, int len) {
    X509 *peer;
    if ((peer = SSL_get_peer_certificate(c->ssl))) {
	if (cn && len > 0) {
	    X509_NAME *sn = X509_get_subject_name(peer);
	    X509_NAME_get_text_by_NID(sn, NID_commonName, cn, len);
	    fprintf(stderr, "INFO: peer cert common name: \"%s\"\n", cn);
	}
	X509_free(peer);
	if (SSL_get_verify_result(c->ssl) == X509_V_OK) {
	    fprintf(stderr, "INFO: peer cert present and OK\n");
	    return 1;
	} else {
	    fprintf(stderr, "INFO: peer cert present, but verification FAILED\n");
	    return 0;
	}
    }

    fprintf(stderr, "INFO: peer nas NO cert\n");
    return -1;
}

#else /* no SSL/TLS support, ignore everything, fail on everything */

tls_t *shared_tls(tls_t *new_tls) { return 0; }

tls_t *new_tls() { return 0; }
int set_tls_pk(tls_t *tls, const char *fn) { return -1; }
int set_tls_cert(tls_t *tls, const char *fn) { return -1; }
int set_tls_ca(tls_t *tls, const char *fn_ca, const char *path_ca) { return -1; }
int set_tls_verify(tls_t *tls, int verify) { return -1; }
void free_tls(tls_t *tls) { }

int add_tls(args_t *c, tls_t *tls, int server) { return -1; }
void copy_tls(args_t *src, args_t *dst) { }
void close_tls(args_t *c) { }
int verify_peer_tls(args_t *c, char *cn, int len) { return -1; }

#endif
