#include "RSserver.h"
#include <sisocks.h>
#include <string.h>
#include <stdio.h>

/* size of the line buffer for each worker (request and header only)
 * requests that have longer headers will be rejected with 413 */
#define LINE_BUF_SIZE 1024

/* debug output - change the DBG(X) X to enable debugging output */
#define DBG(X)

/* --- httpd --- */

#define PART_REQUEST 0
#define PART_HEADER  1
#define PART_BODY    2

#define METHOD_POST 1
#define METHOD_GET  2
#define METHOD_HEAD 3

/* attributes of a connection/worker */
#define CONNECTION_CLOSE  0x01 /* Connection: close response behavior is requested */
#define HOST_HEADER       0x02 /* headers contained Host: header (required for HTTP/1.1) */
#define HTTP_1_0          0x04 /* the client requested HTTP/1.0 */
#define CONTENT_LENGTH    0x08 /* Content-length: was specified in the headers */
#define THREAD_OWNED      0x10 /* the worker is owned by a thread and cannot removed */
#define THREAD_DISPOSE    0x20 /* the thread should dispose of the worker */
#define CONTENT_TYPE      0x40 /* message has a specific content type set */
#define CONTENT_FORM_UENC 0x80 /* message content type is application/x-www-form-urlencoded */

struct buffer {
    struct buffer *next, *prev;
    int size, length;
    char data[1];
};

#ifdef unix
#include <sys/un.h> /* needed for unix sockets */
#endif

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s;
	SOCKET ss;
	/* the following entries are not populated by Rserve but can be used by server implemetations */
	char *buf, *sbuf;
	int   ver, bp, bl, sp, sl, flags;
	long  l1, l2;
	/* The following fields are informational, populated by Rserve */
    SAIN sa;
    int ucix;
#ifdef unix
    struct sockaddr_un su;
#endif
    char *line_buf;                /* line buffer (used for request and headers) */
    char *url, *body;              /* URL and request body */
    char *content_type;            /* content type (if set) */
    unsigned int line_pos, body_pos; /* positions in the buffers */
    long content_length;           /* desired content length */
    char part, method, attr;       /* request part, method and connection attributes */
    struct buffer *headers;        /* buffer holding header lines */
};

#define IS_HTTP_1_1(C) (((C)->attr & HTTP_1_0) == 0)

/* returns the HTTP/x.x string for a given connection - we support 1.0 and 1.1 only */
#define HTTP_SIG(C) (IS_HTTP_1_1(C) ? "HTTP/1.1" : "HTTP/1.0")

#ifndef USE_RINTERNALS
#define USE_RINTERNALS
#include <Rinternals.h>
#endif

/* free buffers starting from the tail(!!) */
static void free_buffer(struct buffer *buf) {
    if (!buf) return;
    if (buf->prev) free_buffer(buf->prev);
    free(buf);
}

/* allocate a new buffer */
static struct buffer *alloc_buffer(int size, struct buffer *parent) {
    struct buffer *buf = (struct buffer*) malloc(sizeof(struct buffer) + size);
    if (!buf) return buf;
    buf->next = 0;
    buf->prev = parent;
    if (parent) parent->next = buf;
    buf->size = size;
    buf->length = 0;
    return buf;
}

/* convert doubly-linked buffers into one big raw vector */
static SEXP collect_buffers(struct buffer *buf) {
    SEXP res;
    char *dst;
    int len = 0;
    if (!buf) return allocVector(RAWSXP, 0);
    while (buf->prev) { /* count the total length and find the root */
		len += buf->length;
		buf = buf->prev;
    }
    res = allocVector(RAWSXP, len + buf->length);
    dst = (char*) RAW(res);
    while (buf) {
		memcpy(dst, buf->data, buf->length);
		dst += buf->length;
		buf = buf->next;
    }
    return res;
}

static void free_args(args_t *c)
{
    DBG(printf("finalizing worker %p\n", (void*) c));
    if (c->url) {
		free(c->url);
		c->url = NULL;
    }
	if (c->line_buf) {
		free(c->line_buf);
		c->line_buf = NULL;
	}
    if (c->body) {
		free(c->body);
		c->body = NULL;
    }
	
    if (c->content_type) {
		free(c->content_type);
		c->content_type = NULL;
    }
    if (c->headers) {
		free_buffer(c->headers);
		c->headers = NULL;
    }
    if (c->s != INVALID_SOCKET) {
		closesocket(c->s);
		c->s = INVALID_SOCKET;
    }
}

static int send_response(SOCKET s, const char *buf, unsigned int len)
{
    unsigned int i = 0;
    /* we have to tell R to ignore SIGPIPE otherwise it can raise an error
       and get us into deep trouble */
    while (i < len) {
		int n = send(s, buf + i, len - i, 0);
		if (n < 1) {
			return -1;
		}
		i += n;
    }
    return 0;
}

/* sends HTTP/x.x plus the text (which should be of the form " XXX ...") */
static int send_http_response(args_t *c, const char *text) {
    char buf[96];
    const char *s = HTTP_SIG(c);
    int l = strlen(text), res;
    /* reduce the number of packets by sending the payload en-block from buf */
    if (l < sizeof(buf) - 10) {
		strcpy(buf, s);
		strcpy(buf + 8, text);
		return send_response(c->s, buf, l + 8);
    }
    res = send(c->s, s, 8, 0);
    if (res < 8) return -1;
    return send_response(c->s, text, strlen(text));
}

/* decode URI in place (decoding never expands) */
static void uri_decode(char *s)
{
    char *t = s;
    while (*s) {
		if (*s == '+') { /* + -> SPC */
			*(t++) = ' '; s++;
		} else if (*s == '%') {
			unsigned char ec = 0;
			s++;
			if (*s >= '0' && *s <= '9') ec |= ((unsigned char)(*s - '0')) << 4;
			else if (*s >= 'a' && *s <= 'f') ec |= ((unsigned char)(*s - 'a' + 10)) << 4;
			else if (*s >= 'A' && *s <= 'F') ec |= ((unsigned char)(*s - 'A' + 10)) << 4;
			if (*s) s++;
			if (*s >= '0' && *s <= '9') ec |= (unsigned char)(*s - '0');
			else if (*s >= 'a' && *s <= 'f') ec |= (unsigned char)(*s - 'a' + 10);
			else if (*s >= 'A' && *s <= 'F') ec |= (unsigned char)(*s - 'A' + 10);
			if (*s) s++;
			*(t++) = (char) ec;
		} else *(t++) = *(s++);
    }
    *t = 0;
}

/* parse a query string into a named character vector - must NOT be
 * URI decoded */
static SEXP parse_query(char *query)
{
    int parts = 0;
    SEXP res, names;
    char *s = query, *key = 0, *value = query, *t = query;
    while (*s) {
		if (*s == '&') parts++;
		s++;
    }
    parts++;
    res = PROTECT(allocVector(STRSXP, parts));
    names = PROTECT(allocVector(STRSXP, parts));
    s = query;
    parts = 0;
    while (1) {
		if (*s == '=' && !key) { /* first '=' in a part */
			key = value;
			*(t++) = 0;
			value = t;
			s++;
		} else if (*s == '&' || !*s) { /* next part */
			int last_entry = !*s;
			*(t++) = 0;
			if (!key) key = "";
			SET_STRING_ELT(names, parts, mkChar(key));
			SET_STRING_ELT(res, parts, mkChar(value));
			parts++;
			if (last_entry) break;
			key = 0;
			value = t;
			s++;
		} else if (*s == '+') { /* + -> SPC */
			*(t++) = ' '; s++;
		} else if (*s == '%') { /* we cannot use uri_decode becasue we need &/= *before* decoding */
			unsigned char ec = 0;
			s++;
			if (*s >= '0' && *s <= '9') ec |= ((unsigned char)(*s - '0')) << 4;
			else if (*s >= 'a' && *s <= 'f') ec |= ((unsigned char)(*s - 'a' + 10)) << 4;
			else if (*s >= 'A' && *s <= 'F') ec |= ((unsigned char)(*s - 'A' + 10)) << 4;
			if (*s) s++;
			if (*s >= '0' && *s <= '9') ec |= (unsigned char)(*s - '0');
			else if (*s >= 'a' && *s <= 'f') ec |= (unsigned char)(*s - 'a' + 10);
			else if (*s >= 'A' && *s <= 'F') ec |= (unsigned char)(*s - 'A' + 10);
			if (*s) s++;
			*(t++) = (char) ec;
		} else *(t++) = *(s++);
    }
    setAttrib(res, R_NamesSymbol, names);
    UNPROTECT(2);
    return res;
}

static SEXP R_ContentTypeName;

/* create an object representing the request body. It is NULL if the body is empty (or zero length).
 * In the case of a URL encoded form it will have the same shape as the query string (named string vector).
 * In all other cases it will be a raw vector with a "content-type" attribute (if specified in the headers) */
static SEXP parse_request_body(args_t *c) {
    if (!c || !c->body) return R_NilValue;
	
    if (c->attr & CONTENT_FORM_UENC) { /* URL encoded form - return parsed form */
		c->body[c->content_length] = 0; /* the body is guaranteed to have an extra byte for the termination */
		return parse_query(c->body);
    } else { /* something else - pass it as a raw vector */
		SEXP res = PROTECT(Rf_allocVector(RAWSXP, c->content_length));
		if (c->content_length)
			memcpy(RAW(res), c->body, c->content_length);
		if (c->content_type) { /* attach the content type so it can be interpreted */
			if (!R_ContentTypeName) R_ContentTypeName = install("content-type");
			setAttrib(res, R_ContentTypeName, mkString(c->content_type));
		}
		UNPROTECT(1);
		return res;
    }
}

/* finalize a request - essentially for HTTP/1.0 it means that
 * we have to close the connection */
static void fin_request(args_t *c) {
    if (!IS_HTTP_1_1(c))
		c->attr |= CONNECTION_CLOSE;
}

/* process a request by calling the httpd() function in R */
static void process_request(args_t *c)
{
    const char *ct = "text/html";
    char *query = 0, *s;
    SEXP sHeaders = R_NilValue;
    int code = 200;
    DBG(Rprintf("process request for %p\n", (void*) c));
    if (!c || !c->url) return; /* if there is not enough to process, bail out */
    s = c->url;
    while (*s && *s != '?') s++; /* find the query part */
    if (*s) {
		*(s++) = 0;
		query = s;
    }
    uri_decode(c->url); /* decode the path part */
    {   /* construct "try(httpd(url, query, body), silent=TRUE)" */
		SEXP sTrue = PROTECT(ScalarLogical(TRUE));
		SEXP sBody = PROTECT(parse_request_body(c));
		SEXP sQuery = PROTECT(query ? parse_query(query) : R_NilValue);
		SEXP sReqHeaders = PROTECT(c->headers ? collect_buffers(c->headers) : R_NilValue);
		SEXP sArgs = PROTECT(list4(mkString(c->url), sQuery, sBody, sReqHeaders));
		SEXP sTry = install("try");
		SEXP y, x = PROTECT(lang3(sTry,
								  LCONS(install(".http.request"), sArgs),
								  sTrue));
		SET_TAG(CDR(CDR(x)), install("silent"));
		DBG(Rprintf("eval(try(.http.request('%s'),silent=TRUE))\n", c->url));
		
		/* evaluate the above in the tools namespace */
		x = PROTECT(eval(x, R_FindNamespace(mkString("tools"))));
		
		/* the result is expected to have one of the following forms:

		   a) character vector of length 1 => error (possibly from try),
		   will create 500 response
		   
		   b) list(payload[, content-type[, headers[, status code]]])
		   
		   payload: can be a character vector of length one or a
		   raw vector. if the character vector is named "file" then
		   the content of a file of that name is the payload
		   
		   content-type: must be a character vector of length one
		   or NULL (if present, else default is "text/html")
		   
		   headers: must be a character vector - the elements will
		   have CRLF appended and neither Content-type nor
		   Content-length may be used
		   
		   status code: must be an integer if present (default is 200)
		*/
		
		if (TYPEOF(x) == STRSXP && LENGTH(x) > 0) { /* string means there was an error */
			const char *s = CHAR(STRING_ELT(x, 0));
			send_http_response(c, " 500 Evaluation error\r\nConnection: close\r\nContent-type: text/plain\r\n\r\n");
			DBG(Rprintf("respond with 500 and content: %s\n", s));
			if (c->method != METHOD_HEAD)
				send_response(c->s, s, strlen(s));
			c->attr |= CONNECTION_CLOSE; /* force close */
			UNPROTECT(7);
			return;
		}
		
		if (TYPEOF(x) == VECSXP && LENGTH(x) > 0) { /* a list (generic vector) can be a real payload */
			SEXP xNames = getAttrib(x, R_NamesSymbol);
			if (LENGTH(x) > 1) {
				SEXP sCT = VECTOR_ELT(x, 1); /* second element is content type if present */
				if (TYPEOF(sCT) == STRSXP && LENGTH(sCT) > 0)
					ct = CHAR(STRING_ELT(sCT, 0));
				if (LENGTH(x) > 2) { /* third element is headers vector */
					sHeaders = VECTOR_ELT(x, 2);
					if (TYPEOF(sHeaders) != STRSXP)
						sHeaders = R_NilValue;
					if (LENGTH(x) > 3) /* fourth element is HTTP code */
						code = asInteger(VECTOR_ELT(x, 3));
				}
			}
			y = VECTOR_ELT(x, 0);
			if (TYPEOF(y) == STRSXP && LENGTH(y) > 0) {
				char buf[64];
				const char *cs = CHAR(STRING_ELT(y, 0)), *fn = 0;
				if (code == 200)
					send_http_response(c, " 200 OK\r\nContent-type: ");
				else {
					sprintf(buf, "%s %d Code %d\r\nContent-type: ", HTTP_SIG(c), code, code);
					send_response(c->s, buf, strlen(buf));
				}
				send_response(c->s, ct, strlen(ct));
				if (sHeaders != R_NilValue) {
					unsigned int i = 0, n = LENGTH(sHeaders);
					for (; i < n; i++) {
						const char *hs = CHAR(STRING_ELT(sHeaders, i));
						send_response(c->s, "\r\n", 2);
						send_response(c->s, hs, strlen(hs));
					}
				}
				/* special content - a file: either list(file="") or list(c("*FILE*", "")) - the latter will go away */
				if (TYPEOF(xNames) == STRSXP && LENGTH(xNames) > 0 &&
					!strcmp(CHAR(STRING_ELT(xNames, 0)), "file"))
					fn = cs;
				if (LENGTH(y) > 1 && !strcmp(cs, "*FILE*"))
					fn = CHAR(STRING_ELT(y, 1));
				if (fn) {
					char *fbuf;
					FILE *f = fopen(fn, "rb");
					long fsz = 0;
					if (!f) {
						send_response(c->s, "\r\nContent-length: 0\r\n\r\n", 23);
						UNPROTECT(7);
						fin_request(c);
						return;
					}
					fseek(f, 0, SEEK_END);
					fsz = ftell(f);
					fseek(f, 0, SEEK_SET);
					sprintf(buf, "\r\nContent-length: %ld\r\n\r\n", fsz);
					send_response(c->s, buf, strlen(buf));
					if (c->method != METHOD_HEAD) {
						fbuf = (char*) malloc(32768);
						if (fbuf) {
							while (fsz > 0 && !feof(f)) {
								int rd = (fsz > 32768) ? 32768 : fsz;
								if (fread(fbuf, 1, rd, f) != rd) {
									free(fbuf);
									UNPROTECT(7);
									c->attr |= CONNECTION_CLOSE;
									return;
								}
								send_response(c->s, fbuf, rd);
								fsz -= rd;
							}
							free(fbuf);
						} else { /* allocation error - get out */
							UNPROTECT(7);
							c->attr |= CONNECTION_CLOSE;
							return;
						}
					}
					fclose(f);
					UNPROTECT(7);
					fin_request(c);
					return;
				}
				sprintf(buf, "\r\nContent-length: %u\r\n\r\n", (unsigned int) strlen(cs));
				send_response(c->s, buf, strlen(buf));
				if (c->method != METHOD_HEAD)
					send_response(c->s, cs, strlen(cs));
				UNPROTECT(7);
				fin_request(c);
				return;
			}
			if (TYPEOF(y) == RAWSXP) {
				char buf[64];
				Rbyte *cs = RAW(y);
				if (code == 200)
					send_http_response(c, " 200 OK\r\nContent-type: ");
				else {
					sprintf(buf, "%s %d Code %d\r\nContent-type: ", HTTP_SIG(c), code, code);
					send_response(c->s, buf, strlen(buf));
				}
				send_response(c->s, ct, strlen(ct));
				if (sHeaders != R_NilValue) {
					unsigned int i = 0, n = LENGTH(sHeaders);
					for (; i < n; i++) {
						const char *hs = CHAR(STRING_ELT(sHeaders, i));
						send_response(c->s, "\r\n", 2);
						send_response(c->s, hs, strlen(hs));
					}
				}
				sprintf(buf, "\r\nContent-length: %u\r\n\r\n", LENGTH(y));
				send_response(c->s, buf, strlen(buf));
				if (c->method != METHOD_HEAD)
					send_response(c->s, (char*) cs, LENGTH(y));
				UNPROTECT(7);
				fin_request(c);
				return;
			}
		}
		UNPROTECT(7);
    }
    send_http_response(c, " 500 Invalid response from R\r\nConnection: close\r\nContent-type: text/plain\r\n\r\nServer error: invalid response from R\r\n");
    c->attr |= CONNECTION_CLOSE; /* force close */
}

static void http_close(args_t *arg) {
	closesocket(arg->s);
	arg->s = -1;
}

/* this function is called to fetch new data from the client
 * connection socket and process it */
static void http_input_iteration(args_t *c) {
    int n;
	
    DBG(printf("worker_input_handler, data=%p\n", data));
    if (!c) return;
	
    DBG(printf("input handler for worker %p (sock=%d, part=%d, method=%d, line_pos=%d)\n", (void*) c, (int)c->s, (int)c->part, (int)c->method, (int)c->line_pos));
	
    /* FIXME: there is one edge case that is not caught on unix: if
     * recv reads two or more full requests into the line buffer then
     * this function exits after the first one, but input handlers may
     * not trigger, because there may be no further data. It is not
     * trivial to fix, because just checking for a full line at the
     * beginning and not calling recv won't trigger a new input
     * handler. However, under normal circumstance this should not
     * happen, because clients should wait for the response and even
     * if they don't it's unlikely that both requests get combined
     * into one packet. */
    if (c->part < PART_BODY) {
		char *s = c->line_buf;
		n = recv(c->s, c->line_buf + c->line_pos, LINE_BUF_SIZE - c->line_pos - 1, 0);
		DBG(printf("[recv n=%d, line_pos=%d, part=%d]\n", n, c->line_pos, (int)c->part));
		if (n < 0) { /* error, scrape this worker */
			http_close(c);
			return;
		}
		if (n == 0) { /* connection closed -> try to process and then remove */
			process_request(c);
			http_close(c);
			return;
		}
		c->line_pos += n;
		c->line_buf[c->line_pos] = 0;
		DBG(printf("in buffer: {%s}\n", c->line_buf));
		while (*s) {
			/* ok, we have genuine data in the line buffer */
			if (s[0] == '\n' || (s[0] == '\r' && s[1] == '\n')) { /* single, empty line - end of headers */
				/* --- check request validity --- */
				DBG(printf(" end of request, moving to body\n"));
				if (!(c->attr & HTTP_1_0) && !(c->attr & HOST_HEADER)) { /* HTTP/1.1 mandates Host: header */
					send_http_response(c, " 400 Bad Request (Host: missing)\r\nConnection: close\r\n\r\n");
					http_close(c);
					return;
				}
				if (c->attr & CONTENT_LENGTH && c->content_length) {
					if (c->content_length < 0 ||  /* we are parsing signed so negative numbers are bad */
						c->content_length > 2147483640 || /* R will currently have issues with body around 2Gb or more, so better to not go there */
						!(c->body = (char*) malloc(c->content_length + 1 /* allocate an extra termination byte */ ))) {
						send_http_response(c, " 413 Request Entity Too Large (request body too big)\r\nConnection: close\r\n\r\n");
						http_close(c);
						return;
					}
				}
				c->body_pos = 0;
				c->part = PART_BODY;
				if (s[0] == '\r') s++;
				s++;
				/* move the body part to the beginning of the buffer */
				c->line_pos -= s - c->line_buf;
				memmove(c->line_buf, s, c->line_pos);
				if (c->method != METHOD_POST) { /* anything but POST can be processed right away */
					if (c->attr & CONTENT_LENGTH) {
						send_http_response(c, " 400 Bad Request (GET/HEAD with body)\r\n\r\n");
						http_close(c);
						return;
					}
					process_request(c);
					if (c->attr & CONNECTION_CLOSE) {
						http_close(c);
						return;
					}
					/* keep-alive - reset the worker so it can process a new request */
					if (c->url) { free(c->url); c->url = NULL; }
					if (c->body) { free(c->body); c->body = NULL; }
					if (c->content_type) { free(c->content_type); c->content_type = NULL; }
					if (c->headers) { free_buffer(c->headers); c->headers = NULL; }
					c->body_pos = 0;
					c->method = 0;
					c->part = PART_REQUEST;
					c->attr = 0;
					c->content_length = 0;
					return;
				}
				/* copy body content (as far as available) */
				c->body_pos = (c->content_length < c->line_pos) ? c->content_length : c->line_pos;
				if (c->body_pos) {
					memcpy(c->body, c->line_buf, c->body_pos);
					c->line_pos -= c->body_pos; /* NOTE: we are NOT moving the buffer since non-zero left-over causes connection close */
				}
				/* POST will continue into the BODY part */
				break;
			}
			{
				char *bol = s;
				while (*s && *s != '\r' && *s != '\n') s++;
				if (!*s) { /* incomplete line */
					if (bol == c->line_buf) {
						if (c->line_pos < LINE_BUF_SIZE) /* one, incomplete line, but the buffer is not full yet, just return */
							return;
						/* the buffer is full yet the line is incomplete - we're in trouble */
						send_http_response(c, " 413 Request entity too large\r\nConnection: close\r\n\r\n");
						http_close(c);
						return;
					}
					/* move the line to the begining of the buffer for later requests */
					c->line_pos -= bol - c->line_buf;
					memmove(c->line_buf, bol, c->line_pos);
					return;
				} else { /* complete line, great! */
					if (*s == '\r') *(s++) = 0;
					if (*s == '\n') *(s++) = 0;
					DBG(printf("complete line: {%s}\n", bol));
					if (c->part == PART_REQUEST) {
						/* --- process request line --- */
						unsigned int rll = strlen(bol); /* request line length */
						char *url = bol + 5;
						if (rll < 14 || strncmp(bol + rll - 9, " HTTP/1.", 8)) { /* each request must have at least 14 characters [GET / HTTP/1.0] and have HTTP/1.x */
							send_response(c->s, "HTTP/1.0 400 Bad Request\r\n\r\n", 28);
							http_close(c);
							return;
						}
						if (!strncmp(bol + rll - 3, "1.0", 3)) c->attr |= HTTP_1_0;
						if (!strncmp(bol, "GET ", 4)) { c->method = METHOD_GET; url--; }
						if (!strncmp(bol, "POST ", 5)) c->method = METHOD_POST;
						if (!strncmp(bol, "HEAD ", 5)) c->method = METHOD_HEAD;
						if (!c->method) {
							send_http_response(c, " 501 Invalid or unimplemented method\r\n\r\n");
							http_close(c);
							return;
						}
						bol[strlen(bol) - 9] = 0;
						c->url = strdup(url);
						c->part = PART_HEADER;
						DBG(printf("parsed request, method=%d, URL='%s'\n", (int)c->method, c->url));
					} else if (c->part == PART_HEADER) {
						/* --- process headers --- */
						char *k = bol;
						if (!c->headers)
							c->headers = alloc_buffer(1024, NULL);
						if (c->headers) { /* record the header line in the buffer */
							int l = strlen(bol);
							if (l) { /* this should be really always true */
								if (c->headers->length + l + 1 > c->headers->size) { /* not enough space? */
									int fits = c->headers->size - c->headers->length;
									if (fits) memcpy(c->headers->data + c->headers->length, bol, fits);
									if (alloc_buffer(2048, c->headers)) {
										c->headers = c->headers->next;
										memcpy(c->headers->data, bol + fits, l - fits);
										c->headers->length = l - fits;
										c->headers->data[c->headers->length++] = '\n';
									}
								} else {
									memcpy(c->headers->data + c->headers->length, bol, l);
									c->headers->length += l;	
									c->headers->data[c->headers->length++] = '\n';
								}
							}
						}
						while (*k && *k != ':') {
							if (*k >= 'A' && *k <= 'Z')
								*k |= 0x20;
							k++;
						}
						if (*k == ':') {
							*(k++) = 0;
							while (*k == ' ' || *k == '\t') k++;
							DBG(printf("header '%s' => '%s'\n", bol, k));
							if (!strcmp(bol, "content-length")) {
								c->attr |= CONTENT_LENGTH;
								c->content_length = atol(k);
							}
							if (!strcmp(bol, "content-type")) {
								char *l = k;
								while (*l) { if (*l >= 'A' && *l <= 'Z') *l |= 0x20; l++; }
								c->attr |= CONTENT_TYPE;
								if (c->content_type) free(c->content_type);
								c->content_type = strdup(k);
								if (!strncmp(k, "application/x-www-form-urlencoded", 33))
									c->attr |= CONTENT_FORM_UENC;
							}
							if (!strcmp(bol, "host"))
								c->attr |= HOST_HEADER;
							if (!strcmp(bol, "connection")) {
								char *l = k;
								while (*l) { if (*l >= 'A' && *l <= 'Z') *l |= 0x20; l++; }
								if (!strncmp(k, "close", 5))
									c->attr |= CONNECTION_CLOSE;
							}
						}
					}
				}
			}
		}
		if (c->part < PART_BODY) {
			/* we end here if we processed a buffer of exactly one line */
			c->line_pos = 0;
			return;
		}
    }
    if (c->part == PART_BODY && c->body) { /* BODY  - this branch always returns */
		if (c->body_pos < c->content_length) { /* need to receive more ? */
			DBG(printf("BODY: body_pos=%d, content_length=%ld\n", c->body_pos, c->content_length));
			n = recv(c->s, c->body + c->body_pos, c->content_length - c->body_pos, 0);
			DBG(printf("      [recv n=%d - had %u of %lu]\n", n, c->body_pos, c->content_length));
			c->line_pos = 0;
			if (n < 0) { /* error, scrap this worker */
				http_close(c);
				return;
			}
			if (n == 0) { /* connection closed -> try to process and then remove */
				process_request(c);
				http_close(c);
				return;
			}
			c->body_pos += n;
		}
		if (c->body_pos == c->content_length) { /* yay! we got the whole body */
			process_request(c);
			if (c->attr & CONNECTION_CLOSE || c->line_pos) { /* we have to close the connection if there was a double-hit */
				http_close(c);
				return;
			}
			/* keep-alive - reset the worker so it can process a new request */
			if (c->url) { free(c->url); c->url = NULL; }
			if (c->body) { free(c->body); c->body = NULL; }
			if (c->content_type) { free(c->content_type); c->content_type = NULL; }
			if (c->headers) { free_buffer(c->headers); c->headers = NULL; }
			c->line_pos = 0; c->body_pos = 0;
			c->method = 0;
			c->part = PART_REQUEST;
			c->attr = 0;
			c->content_length = 0;
			return;
		}
    }
	
    /* we enter here only if recv was used to leave the headers with no body */
    if (c->part == PART_BODY && !c->body) {
		char *s = c->line_buf;
		if (c->line_pos > 0) {
			if ((s[0] != '\r' || s[1] != '\n') && (s[0] != '\n')) {
				send_http_response(c, " 411 length is required for non-empty body\r\nConnection: close\r\n\r\n");
				http_close(c);
				return;
			}
			/* empty body, good */
			process_request(c);
			if (c->attr & CONNECTION_CLOSE) {
				http_close(c);
				return;
			} else { /* keep-alive */
				int sh = 1;
				if (s[0] == '\r') sh++;
				if (c->line_pos <= sh)
					c->line_pos = 0;
				else { /* shift the remaining buffer */
					memmove(c->line_buf, c->line_buf + sh, c->line_pos - sh);
					c->line_pos -= sh;
				}
				/* keep-alive - reset the worker so it can process a new request */
				if (c->url) { free(c->url); c->url = NULL; }
				if (c->body) { free(c->body); c->body = NULL; }
				if (c->content_type) { free(c->content_type); c->content_type = NULL; }
				if (c->headers) { free_buffer(c->headers); c->headers = NULL; }
				c->body_pos = 0;
				c->method = 0;
				c->part = PART_REQUEST;
				c->attr = 0;
				c->content_length = 0;
				return;
			}
		}
		n = recv(c->s, c->line_buf + c->line_pos, LINE_BUF_SIZE - c->line_pos - 1, 0);
		if (n < 0) { /* error, scrap this worker */
			http_close(c);
			return;
		}
		if (n == 0) { /* connection closed -> try to process and then remove */
			process_request(c);
			http_close(c);
			return;
		}
		if ((s[0] != '\r' || s[1] != '\n') && (s[0] != '\n')) {
			send_http_response(c, " 411 length is required for non-empty body\r\nConnection: close\r\n\r\n");
			http_close(c);
			return;
		}
    }
}

static void HTTP_connected(void *parg) {
	args_t *arg = (args_t*) parg;

	if (Rserve_prepare_child(arg) != 0) { /* parent or error */
		free(arg);
		return;
	}

	if (!(arg->line_buf = (char*) malloc(LINE_BUF_SIZE))) {
		fprintf(stderr, "ERROR: unable to allocate line buffer\n");
		free(arg);
		return;
	}

	while (arg->s != -1)
		http_input_iteration(arg);

	free_args(arg);
}

server_t *create_HTTP_server(int port) {
	server_t *srv = create_server(port, 0);
	if (srv) {
		srv->connected = HTTP_connected;
		/* we are not actually using anyting else since HTTP_connected uses sockets directly */
		/* srv->send_resp = */
		srv->recv      = server_recv;
		srv->send      = server_send;
		srv->fin       = server_fin;
		srv->flags     = 0;
		add_server(srv);
		return srv;
	}
	return 0;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
