#include "websockets.h"
#include "md5.h"
#include "sha1.h"
#include "tls.h"
#include "qap.h"
#include "ulog.h"
#ifdef RSERV_DEBUG
#include "rsdebug.h"
#endif

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s;
	SOCKET ss;
	int msg_id;
	void *res1; /* used by TLS */
	struct args *tls_arg; /* if set it is used to wire send/recv calls */
	/* the following entries are not populated by Rserve but can be used by server implemetations */
	char *buf, *sbuf;
	int   ver, bp, bl, sp, sl, flags;
	size_t  l1, l2;
};

static ssize_t WS_recv_data(args_t *arg, void *buf, size_t read_len);
static int     WS_send_resp(args_t *arg, int rsp, size_t len, const void *buf);
static ssize_t WS_send_data(args_t *arg, const void *buf, size_t len);

/* we don't actually use R here, so no point looking for large vectors,
   so let's use size_t width - no config, so let's hope for __SIZE_WIDTH__.
   Note that this only defines the max frame size so at the worst we limit
   to 2Gb frames - likley more than enough either way */
#if defined __SIZE_WIDTH__ && (__SIZE_WIDTH__ >= 64)
#define rlen_max ((size_t) 0x7fffffffffffffff)
#else
#define rlen_max ((size_t) 0x7fffffff)
#endif

static ssize_t WS_wire_send(args_t *arg, const void *buf, size_t len) {
	return (arg->tls_arg) ? arg->tls_arg->srv->send(arg->tls_arg, buf, len) : send(arg->s, buf, len, 0);
}

static ssize_t WS_wire_recv(args_t *arg, void *buf, size_t len) {
	return (arg->tls_arg) ? arg->tls_arg->srv->recv(arg->tls_arg, buf, len) : recv(arg->s, buf, len, 0);
}

static void WS_wire_close(args_t *arg) {
	if (arg->tls_arg) {
		close_tls(arg->tls_arg);
		closesocket(arg->tls_arg->s);
		if (arg->s != arg->tls_arg->s) closesocket(arg->s);
		arg->tls_arg->s = -1;
		/* the server is virtual and allocated only for this instance
		   so it's ok to free it (all other server are re-used) */
		free(arg->tls_arg->srv);
		free(arg->tls_arg);
		arg->tls_arg = 0;
	} else
		closesocket(arg->s);
	arg->s = -1;
}

static int do_mask(char *msg, size_t len, int koff, char *key) {
	size_t i = 0;
	while (i < len) {
		msg[i] ^= key[(i + koff) & 3];
		i++;
    }
	return (i + koff) & 3;
}

/* due to very large cookies the lines may be very long, using 128kB for now */
#define LINE_BUF_SIZE (128*1024)

struct header_info {
	int version;
	char *origin;
	char *host;
	char *key;
	char *key1;
	char *key2;
	char *path;
	char *query;
	char *protocol;
};

static void free_header(struct header_info *h) {
	if (h->origin) free(h->origin);
	if (h->host) free(h->host);
	if (h->key) free(h->key);
	if (h->key1) free(h->key1);
	if (h->key2) free(h->key2);
	if (h->path) free(h->path);
	if (h->query) free(h->query);
	if (h->protocol) free(h->protocol);
}

static size_t count_spaces(const char *c) {
	size_t n = 0;
	while (*c) { if (*c == ' ') n++; c++; }
	return n;	
}

static unsigned long count_digits(const char *c) {
	size_t n = 0;
	while (*c) { if (*c >= '0' && *c <= '9') n = n * 10L + (size_t)(*c - '0'); c++; }
	return n;	
}

/* from base64.c */
void base64encode(const unsigned char *src, int len, char *dst);

#define FRAME_BUFFER_SIZE 65536

static void WS_connected(void *parg) {
	args_t *arg = (args_t*) parg;
	int n, bp = 0, empty_lines = 0, request_line = 1;

	struct header_info h;
	
	char *buf;

	/* we have to perform a handshake before giving over to QAP 
	   but we have to fork() first as to not block the server on handshake */
	if (prepare_child(arg) != 0) { /* parent or error */
		free(arg);
		return;
	}

	/* if TLS is requested then we need to synthesize arg and srv
	   for the TLS leg.
	   FIXME: check that disassociating arg->s and tls_arg->s has
	   no bad side-effects.
	*/
	if (arg->srv->flags & WS_TLS) {
		args_t *tls_arg = calloc(1, sizeof(args_t));
		tls_arg->s = arg->s;
		tls_arg->srv = calloc(1, sizeof(server_t));
		add_tls(tls_arg, shared_tls(0), 1);
		arg->tls_arg = tls_arg;
	} else arg->tls_arg = 0;

	buf = (char*) malloc(LINE_BUF_SIZE);
	if (!buf) {
		char lbuf[64];
		strcpy(lbuf, "HTTP/1.1 500 Out of memory\r\n\r\n");
		WS_wire_send(arg, lbuf, strlen(lbuf));
		WS_wire_close(arg);
		arg->s = -1;
		return;
	}
	buf[LINE_BUF_SIZE - 1] = 0;

	memset(&h, 0, sizeof(h));

#ifdef RSERV_DEBUG
	printf("INFO:WS: connection accepted for WebSockets\n");
#endif

	while ((n = WS_wire_recv(arg, buf + bp, LINE_BUF_SIZE - bp - 1)) > 0) {
		char *c = buf, *nl = c;
#ifdef RSERV_DEBUG
		buf[bp + n] = 0;
		printf("INFO:WS: recv(%d, %d) = %d\n%s\n---\n", bp, LINE_BUF_SIZE - bp - 1, n, buf);
#endif
		bp += n;
		while (*c) {
			char *dc = 0, *kc;
			while (*c == ' ' || *c == '\t') c++;
			kc = c;
			while (*c && *c != '\n') {
				if (!dc) {
					if (*c >= 'A' && *c <= 'Z') *c |= 0x20; /* to lower */
					if (*c == ':') {
						*c = 0;
						dc = c + 1;
					}
				}
				c++;
			}
			if (*c) { /* next full line */
				nl = c + 1;
				if (c > buf && *(c - 1) == '\r') *(c - 1) = 0;
				*c = 0;
				c++;
				if (request_line) {
					char *r1 = kc;
					request_line = 0;
					while (*kc && *kc != ' ') kc++;
					if (*kc == ' ') {
						r1 = ++kc;
						while (*kc && *kc != ' ') kc++;
						if (*kc == ' ') {
							char *r2 = r1;
							*kc = 0;
							while (*r2 && *r2 != '?') r2++;
							if (*r2 == '?') { /* split off query part */
								*(r2++) = 0;
								h.query = strdup(r2);
							}
							h.path = strdup(r1);
#ifdef RSERV_DEBUG
							printf("INFO:WS: request for '%s' (query%c%s)\n", r1, h.query ? ':' : ' ', h.query ? h.query : "not specified");
#endif
						}
					}					
				} else if (dc) {
					while (*dc == ' ' || *dc == '\t') dc++;
#ifdef RSERV_DEBUG
					printf("INFO:WS: header '%s' = '%s'\n", kc, dc);
#endif
					if (!strcmp(kc, "origin")) h.origin = strdup(dc);
					if (!strcmp(kc, "host")) h.host = strdup(dc);
					if (!strcmp(kc, "sec-websocket-version")) h.version = atoi(dc);
					if (!strcmp(kc, "sec-websocket-protocol")) h.protocol = strdup(dc);
					if (!strcmp(kc, "sec-websocket-key1")) h.key1 = strdup(dc);
					if (!strcmp(kc, "sec-websocket-key2")) h.key2 = strdup(dc);
					if (!strcmp(kc, "sec-websocket-key")) h.key = strdup(dc);
				} else if (!*kc && ++empty_lines) break;
			}
		}
#ifdef RSERV_DEBUG
		printf("INFO: bp=%d, nl=buf+%d\n", bp, (int) (nl - buf));
#endif
		if (nl == buf) {
			if (bp >= LINE_BUF_SIZE - 1) { /* no line in the entire buffer */
				strcpy(buf, "HTTP/1.1 400 Bad Request (line overflow)\r\n\r\n");
				WS_wire_send(arg, buf, strlen(buf));
				WS_wire_close(arg);
				arg->s = -1;
				free_header(&h);
				free(buf);
				return;
			}
			/* otherwise it's fine, we will load more */
		} else {
			if (nl >= buf + LINE_BUF_SIZE - 1 || (!empty_lines && !*nl)) /* everything was consumed */
				bp = 0;
			else {
				bp -= nl - buf;
				memmove(buf, nl, bp);
			}
		}
		if (empty_lines > 0)
			break;
	}
	if (empty_lines < 1) {
		strcpy(buf, "HTTP/1.1 400 Bad Request (connection failed before EOH)\r\n\r\n");
		WS_wire_send(arg, buf, strlen(buf));
		WS_wire_close(arg);
		arg->s = -1;
		free(buf);
		free_header(&h);
		return;
	}
#ifdef RSERV_DEBUG
	fprintf(stderr, "INFO: WebSockets version %d\n Origin: %s\n Host: %s\n Key: '%s'\n Key1: '%s'\n Key2: '%s'\n\n",
			h.version, h.origin ? h.origin : "<NULL>", h.host ? h.host : "<NULL>",
			h.key ? h.key : "<NULL>", h.key1 ? h.key1 : "<NULL>", h.key2 ? h.key2 : "<NULL>");
#endif

	arg->ver = h.version;
	if (h.version < 4) { /* 00 .. 03 (in fact that was no version in the handshake before 04) */
		unsigned int v[2];
		unsigned char keyb[16];
		unsigned char hash[16];

		if (bp < 8) {
			n = WS_wire_recv(arg, buf + bp, 8 - bp);
			if (n < 8 - bp) {
				strcpy(buf, "HTTP/1.1 400 Bad Request (Key3 incomplete)\r\n\r\n");
				WS_wire_send(arg, buf, strlen(buf));
				WS_wire_close(arg);
				arg->s = -1;
				free(buf);
				free_header(&h);
				return;
			}
		}
		if (!h.origin || !h.key1 || !h.key2 || !h.host) {
			strcpy(buf, "HTTP/1.1 400 Bad Request (at least one key header is missing)\r\n\r\n");
			WS_wire_send(arg, buf, strlen(buf));
			WS_wire_close(arg);
			arg->s = -1;
			free(buf);
			free_header(&h);
			return;
		}
		v[0] = count_digits(h.key1) / count_spaces(h.key1);
		v[1] = count_digits(h.key2) / count_spaces(h.key2);
		keyb[3] = v[0] & 255;
		keyb[2] = (v[0] >> 8) & 255;
		keyb[1] = (v[0] >> 16) & 255;
		keyb[0] = (v[0] >> 24) & 255;
		keyb[7] = v[1] & 255;
		keyb[6] = (v[1] >> 8) & 255;
		keyb[5] = (v[1] >> 16) & 255;
		keyb[4] = (v[1] >> 24) & 255;
		memcpy(keyb + 8, buf, 8);
		md5hash(keyb, 16, hash);
		if (!h.path) h.path = strdup("/");
		snprintf(buf, LINE_BUF_SIZE, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Origin: %s\r\nSec-WebSocket-Location: ws://%s%s\r\n%s%s%s\r\n",
				 h.origin, h.host, h.path, h.protocol ? "Sec-WebSocket-Protocol: " : "", h.protocol ? h.protocol : "", h.protocol ? "\r\n" : "");
		bp = strlen(buf);
		memcpy(buf + bp, hash, 16);
		WS_wire_send(arg, buf, bp + 16);
#ifdef RSERV_DEBUG
		printf("Responded with WebSockets.00 handshake\n");
#endif
	} else {
		unsigned char hash[21];
		char b64[40];
		strcpy(buf, h.key);
		strcat(buf, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		sha1hash(buf, strlen(buf), hash);
		hash[20] = 0; /* base64encode needs NUL sentinel */
		base64encode(hash, sizeof(hash) - 1, b64);
		/* FIXME: if the client requests multiple protocols, we should be picking one but we don't */
		snprintf(buf, LINE_BUF_SIZE, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s%s%s\r\n", b64, h.protocol ? "Sec-WebSocket-Protocol: " : "", h.protocol ? h.protocol : "", h.protocol ? "\r\n" : "");
		WS_wire_send(arg, buf, strlen(buf));
#ifdef RSERV_DEBUG
		printf("Responded with WebSockets.04+ handshake (version = %02d)\n", h.version);
#endif
	}
	free(buf);

	arg->bl = FRAME_BUFFER_SIZE;
	arg->bp = 0;
	arg->buf = (char*) malloc(FRAME_BUFFER_SIZE);
	arg->sl = FRAME_BUFFER_SIZE;
	arg->sbuf = (char*) malloc(FRAME_BUFFER_SIZE);

	buf = h.protocol ? strdup(h.protocol) : 0;
	
	free_header(&h);
	
	{
		ws_connected_fn_t connected = (ws_connected_fn_t) arg->srv->aux;
		connected(arg, buf);
	}
}

static server_t *ws_upgrade_srv, *wss_upgrade_srv; /* virtual server that represents the WS layer in HTTP/WS stack */

/* upgrade HTTP connection to WS connection, only 13+ protocol is supported this way */
/* NOTE: not included: origin, host */
/* IMPORTANT: it mangles the arg structure, so the caller should make sure it releases any obejcts from
              the structure that may leak */
/* FIXME: it only works on connections that have a direct socket since we don't have a stack to do TLS <-> WS <-> QAP */
void WS13_upgrade(args_t *arg, const char *key, const char *protocol, const char *version, ws_connected_fn_t connected) {
	char buf[512];
	unsigned char hash[21];
	char b64[44];
	server_t *srv;
	srv = (arg->srv->flags & WS_TLS) ? wss_upgrade_srv : ws_upgrade_srv;
	if (!srv) {
		srv = (server_t*) calloc(1, sizeof(server_t));
		if (!srv) {
			snprintf(buf, sizeof(buf), "HTTP/1.1 511 Allocation error\r\n\r\n");
			arg->srv->send(arg, buf, strlen(buf));
			return;
		}
		srv->parent    = arg->srv;
		srv->connected = WS_connected; /* this is not actually called */
		srv->send_resp = WS_send_resp;
		srv->recv      = WS_recv_data;
		srv->send      = WS_send_data;
		srv->fin       = server_fin;
		srv->flags     = arg->srv->flags & SRV_QAP_FLAGS; /* pass-through QAP flags */
		/* FIXME: this is really ugly - we have to pass ws_connected as aux, but
		   since we are caching the server instance this means you cannot have different
		   functions for different servers that are upgraded! */
		srv->aux       = (void*) connected;
		if (arg->srv->flags & WS_TLS) wss_upgrade_srv = srv; else ws_upgrade_srv = srv;
	}

	/* FIXME: can we just use the parent server? */
	if (arg->srv->flags & SRV_TLS) { /* if this server is connected through TLS we have to create wire TLS pass-through */
		args_t *tls_arg = calloc(1, sizeof(args_t));
		tls_arg->srv = calloc(1, sizeof(server_t));
		copy_tls(arg, tls_arg);
		arg->tls_arg = tls_arg;
	}

	strncpy(buf, key, sizeof(buf) - 50);
	strcat(buf, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
	sha1hash(buf, strlen(buf), hash);
	hash[20] = 0; /* base64encode needs NUL sentinel */
	base64encode(hash, sizeof(hash) - 1, b64);
	/* FIXME: if the client requests multiple protocols, we should be picking one but we don't */
	snprintf(buf, sizeof(buf), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s%s%s\r\n", b64, protocol ? "Sec-WebSocket-Protocol: " : "", protocol ? protocol : "", protocol ? "\r\n" : "");
	arg->srv->send(arg, buf, strlen(buf));
#ifdef RSERV_DEBUG
	printf("Responded with WebSockets.04+ handshake (version = %02d)\n", version ? atoi(version) : 0);
#endif

	arg->bl = FRAME_BUFFER_SIZE;
	arg->bp = 0;
	arg->buf = (char*) malloc(FRAME_BUFFER_SIZE);
	arg->sl = FRAME_BUFFER_SIZE;
	arg->sbuf = (char*) malloc(FRAME_BUFFER_SIZE);
	arg->srv = srv;
	arg->ver = version ? atoi(version) : 13; /* let's assume 13 if not present */

	{
		ws_connected_fn_t connected = (ws_connected_fn_t) srv->aux;
		connected(arg, protocol ? strdup(protocol) : 0);
	}
}

/* FIXME: big endian machines? */
#define itop(X) (X)
#define ptoi(X) (X)

static int WS_send_resp(args_t *arg, int rsp, size_t len, const void *buf) {
	unsigned char *sbuf = (unsigned char*) arg->sbuf;
	if (len > rlen_max - 128)
		return -1; /* too big */
	if (arg->ver == 0) {
		/* FIXME: we can't really tunnel QAP1 without some encoding ... */
	} else {
		qap_hdr_t ph;
		size_t pl = 0;
		size_t flen = len + sizeof(ph);
		ph.cmd = itop(rsp | ((rsp & CMD_OOB) ? 0 : CMD_RESP));
		ph.len = itop(len);
#ifdef __LP64__
		ph.res = itop(len >> 32);
#else
		ph.res = 0;
#endif
		ph.msg_id = arg->msg_id;

#ifdef RSERV_DEBUG
		if (io_log) {
			struct timeval tv;
			snprintf(io_log_fn, sizeof(io_log_fn), "/tmp/Rserve-io-%d.log", getpid());
			FILE *f = fopen(io_log_fn, "a");
			if (f) {
				double ts = 0;
				if (!gettimeofday(&tv, 0))
					ts = ((double) tv.tv_sec) + ((double) tv.tv_usec) / 1000000.0;
				if (first_ts < 1.0) first_ts = ts;
				fprintf(f, "%.3f [+%4.3f]  SRV --> CLI  [WS_send_resp]  (%x, %ld bytes)\n   HEAD ", ts, ts - first_ts, rsp, (long) len);
				fprintDump(f, &ph, sizeof(ph));
				fprintf(f, "   BODY ");
				if (len) fprintDump(f, buf, len); else fprintf(f, "<none>\n");
				fclose(f);
			}
		}
#endif

		sbuf[pl++] = ((arg->flags & F_OUT_BIN) ? 1 : 0) + ((arg->ver < 4) ? 0x04 : 0x81); /* text/binary, 4+ has inverted FIN bit */
		if (flen < 126) /* short length */
			sbuf[pl++] = flen;
		else if (flen < 65536) { /* 16-bit */
			sbuf[pl++] = 126;
			sbuf[pl++] = flen >> 8;
			sbuf[pl++] = flen & 255;
		} else { /* 64-bit (on 32-bit plarforms the high 4 will be 0) */
			sbuf[pl++] = 127;
			{
				int i = 8;
				size_t l = flen;
				while (i--) {
					sbuf[pl + i] = l & 255;
					l >>= 8;
				}
			}
			pl += 8;
		}	
		memcpy(sbuf + pl, &ph, sizeof(ph));
		pl += sizeof(ph);
		while (len + pl) {
			ssize_t n;
			/* arg->sl is only 64k so there are no size issues */
			size_t send_here = (len + pl > arg->sl) ? arg->sl : (len + pl);
			if (send_here > pl)
				memcpy(sbuf + pl, buf, send_here - pl);
			n = WS_wire_send(arg, sbuf, send_here);
#ifdef RSERV_DEBUG
			if (pl) {
				fprintf(stderr, "WS_send_resp: sending 4+ frame (ver %02d), n = %ld / %ld (of total %ld)\n", arg->ver, (long) n, (unsigned long)send_here, flen);
#ifdef WS_DEBUG
				{ int i, m = send_here; if (m > 100) m = 100; for (i = 0; i < m; i++) fprintf(stderr, " %02x", (int) sbuf[i]); fprintf(stderr,"\n"); }
#endif
			} else
				fprintf(stderr, "WS_send_resp: continuation (%ld bytes)\n", (long) n);
#endif
			if (n != send_here) {
#ifdef RSERV_DEBUG
				fprintf(stderr, "WS_send_resp: write failed (%ld expected, got %ld)\n",
						(long) send_here, (long) n);
#endif
				return -1;
			}
			buf = ((char*)buf) + send_here - pl;
			len -= send_here - pl;
			pl = 0;
		}
	}
	return 0;
}

void WS_set_binary(args_t *arg, int flag) {
	if (flag)
		arg->flags |= F_OUT_BIN;
	else
		arg->flags &= ~F_OUT_BIN;
}

static ssize_t WS_send_data_(args_t *arg, const void *buf, size_t len, int opcode);

static ssize_t WS_send_data(args_t *arg, const void *buf, size_t len) {
	int opcode = ((arg->flags & F_OUT_BIN) ? 1 : 0) + ((arg->ver < 4) ? 4 : 1); /* 2/1 for ver4+, 5/4 for ver0 */
	return WS_send_data_(arg, buf, len, opcode);
}

/* we use send_data only to send the ID string so we don't bother supporting frames bigger than the buffer */
static ssize_t WS_send_data_(args_t *arg, const void *buf, size_t len, int opcode) {
	unsigned char *sbuf = (unsigned char*) arg->sbuf;
	if (arg->ver == 0) {
		if (len < arg->sl - 2) {
			ssize_t n;
			sbuf[0] = 0;
			memcpy(sbuf + 1, buf, len);
			sbuf[len + 1] = 0xff;
			n = WS_wire_send(arg, sbuf, len + 2);
#ifdef RSERV_DEBUG
			fprintf(stderr, "WS_send_data: sending 00 frame, n = %ld / %lu\n",
					(long) n, (unsigned long) len + 2);
#endif
			if (n == len + 2) return len;
			if (n < len + 2 && n >= len) return len - 1;
			return n;
		} else {
#ifdef RSERV_DEBUG
			fprintf(stderr, "ERROR in WS_send_data: data too large\n");
#endif
			return -1;
		}
	} else {
		size_t total = len, pl = 0;
		sbuf[pl++] =  (opcode & 0x7f) | ((arg->ver < 4) ? 0 : 0x80); /* 4+ has inverted FIN bit */
		if (len < 126) /* short length */
			sbuf[pl++] = len;
		else if (len < 65536) { /* 16-bit */
			sbuf[pl++] = 126;
			sbuf[pl++] = len >> 8;
			sbuf[pl++] = len & 255;
		} else { /* 64-bit */
			sbuf[pl++] = 127;
			{
				int i = 8;
				size_t l = len;
				while (i--) {
					sbuf[pl + i] = l & 255;
					l >>= 8;
				}
			}
			pl += 8;
		}

        while (len + pl) {
            ssize_t n;
			size_t send_here = (len + pl > arg->sl) ? arg->sl : (len + pl);
            if (send_here > pl)
                memcpy(sbuf + pl, buf, send_here - pl);
            n = WS_wire_send(arg, sbuf, send_here);
#ifdef RSERV_DEBUG
            if (pl) {
                fprintf(stderr, "WS_send_data: sending 4+ frame (ver %02d), n = %ld / %lu (of total %ld)\n", arg->ver, (long) n, (unsigned long) send_here, (long) len);
#ifdef WS_DEBUG
                { int i, m = send_here; if (m > 100) m = 100; for (i = 0; i < m; i++) fprintf(stderr, " %02x", (int) sbuf[i]); fprintf(stderr,"\n"); }
#endif
            } else
                fprintf(stderr, "WS_send_data: continuation (%ld bytes)\n", (long) n);
#endif
            if (n != send_here) {
#ifdef RSERV_DEBUG
                fprintf(stderr, "WS_send_data: write failed (%ld expected, got %ld)\n",
						(long) send_here, (long) n);
#endif
                return -1;
            }
            buf = ((char*)buf) + send_here - pl;
            len -= send_here - pl;
            pl = 0;
        }
		return total;
	}
	return 0;
}

#define FRT_CLOSE  8
#define FRT_PING   9
#define FRT_PONG   10

static ssize_t WS_recv_data_(args_t *arg, void *buf, size_t read_len);

/* one extra indirection - we are handing WebSockets control frames internally
   so the application doesn't have to deal with them as they are WS-specific */
static ssize_t WS_recv_data(args_t *arg, void *buf, size_t read_len) {
	ssize_t n = 0;
	while (1) {
		n = WS_recv_data_(arg, buf, read_len);
		if (n < 1)
			break;
		/* catch control frames - those shouldn't go to the application */
		if (GET_F_FT(arg->flags) > 7) {
#ifdef RSERV_DEBUG
			fprintf(stderr, "WS_recv_data: control frame 0x%02x (%d bytes), catching\n", GET_F_FT(arg->flags), (int) n);
#endif
			switch (GET_F_FT(arg->flags)) {
			case FRT_PING:
				if (WS_send_data_(arg, buf, n, FRT_PONG) < 0)
					return -1;
				break;
			case FRT_PONG:
				/* simply ignore PONGs */
				break;
			case FRT_CLOSE:
				if (n > 1)
					ulog("INFO: WS CLOSE frame received, code = %u", 
						 (((unsigned int) ((unsigned char*)buf)[0]) << 8) |
						 ((unsigned int) ((unsigned char*)buf)[1]));
				else
					ulog("INFO: WS CLOSE frame received");
				/* respond with CLOSE */
				WS_send_data_(arg, buf, 0, FRT_CLOSE);
				return 0;
				break;
			}
		} else break;
	}
	return n;
}

static ssize_t WS_recv_data_(args_t *arg, void *buf, size_t read_len) {
#ifdef RSERV_DEBUG
	fprintf(stderr, "WS_recv_data for %ld (bp = %d)\n", (long) read_len, arg->bp);
#endif
	if (arg->ver == 0) {
		/* make sure we have at least one (in frame) or two (oof) bytes in the buffer */
		int min_size = (arg->flags & F_INFRAME) ? 1 : 2;
		while (arg->bp < min_size) {
			ssize_t n = WS_wire_recv(arg, arg->buf + arg->bp, arg->bl - arg->bp);
#ifdef RSERV_DEBUG
			fprintf(stderr, "WS_recv_data: needs ver 00 frame, reading %ld bytes in addition to %d\n", (long) n, arg->bp);
#ifdef WS_DEBUG
			{ size_t i; fprintf(stderr, "Buffer: "); for (i = 0; i < n; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[i]); fprintf(stderr,"\n"); }
#endif
#endif
			if (n < 1) return n;
			arg->bp += n;
		}

		if (!(arg->flags & F_INFRAME)) {
			if (arg->buf[0] != 0x00) {
#ifdef RSERV_DEBUG
				fprintf(stderr, "ERROR: WS_recv_data: ver0 yet not a text frame (0x%02x)\n", (int) (unsigned char) arg->buf[0]);
#endif
				return -1;
			}
			/* now we're in-frame - this is silly but makes the processing easier */
			arg->flags |= F_INFRAME;
			memmove(arg->buf, arg->buf + 1, arg->bp - 1);
		}

		/* first check if we can satify any need by using contents of the buffer */
		/* NOTE: this is actually always true since we guarantee both F_INFRAME and bp > 0 above */
	    if ((arg->flags & F_INFRAME) && arg->bp > 0) {
			unsigned char *b = (unsigned char*) arg->buf;
			ssize_t i = 0;
#ifdef RSERV_DEBUG
			fprintf(stderr, "WS_recv_data: have %d bytes of a frame, requested %d, returning what we have\n", arg->bp, (int) read_len);
#endif
			while (i < arg->bp && i < read_len && b[i] != 0xff) i++;
			if (i >= arg->bp) { /* end of buffer, still in frame */
				memcpy(buf, arg->buf, i);
				arg->bp = 0;
				return i;
			}
			if (b[i] == 0xff) { /* reached end of frame */
				if (i) memcpy(buf, arg->buf, i);
				arg->bp -= i + 1;
				if (arg->bp > 0)
					memmove(arg->buf, arg->buf + i + 1, arg->bp);
				arg->flags ^= F_INFRAME;
				return i;
			}
			/* read_len was less than the buffer and did not even reach the end of frame */
			memcpy(buf, arg->buf, i);
			arg->bp -= i;
			memmove(arg->buf, arg->buf + i, arg->bp);
			return i;
		}
	} /* ver 00 always returns before this */

	if ((arg->flags & F_INFRAME) && arg->bp > 0) { /* do we have content of a frame what has not been picked up yet? */
#ifdef RSERV_DEBUG
		fprintf(stderr, "WS_recv_data: have %d bytes of a frame, requested %d, returning what we have\n", arg->bp, (int) read_len);
#endif
		if (read_len > arg->bp) read_len = arg->bp; /* at most all buffer */
		if (read_len > arg->l1) read_len = arg->l1; /* and not beyond the current frame */
		memcpy(buf, arg->buf, read_len);
		if (arg->bp > read_len)
			memmove(arg->buf, arg->buf + read_len, arg->bp - read_len);
		arg->bp -= read_len;
		arg->l1 -= read_len;
		/* if the whole frame was consumed, flag out-of-frame for the next run */
		if (arg->l1 == 0)
			arg->flags ^= F_INFRAME;
		return read_len;
	}
	/* make sure we have at least one byte in the buffer */
	if (arg->bp == 0) {
		/* read as much as we can with one request */
		ssize_t n = WS_wire_recv(arg, arg->buf, arg->bl);
		if (n < 1) return n;
		arg->bp = n;
#ifdef RSERV_DEBUG
		fprintf(stderr, "INFO: WS_recv_data: read %ld bytes:\n", (long) n);
#ifdef WS_DEBUG
		{ size_t i; for (i = 0; i < n; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[i]); fprintf(stderr,"\n"); }
#endif
#endif
	}
	if (arg->flags & F_INFRAME) { /* in frame with new content */
		if (read_len > arg->l1) /* we can do at most the end of the frame */
			read_len = arg->l1;
		if (read_len > arg->bp) /* and at most what we got in the buffer */
			read_len = arg->bp;
		memcpy(buf, arg->buf, read_len);
		if (arg->flags & F_MASK)
			SET_F_MASK(arg->flags, do_mask(buf, read_len, GET_MASK_ID(arg->flags), (char*)&arg->l2));
		arg->bp -= read_len;
		arg->l1 -= read_len;
		if (arg->bp) /* if anything is left in the buffer, move it up */
			memmove(arg->buf, arg->buf + read_len, arg->bp);
		if (arg->l1 == 0) /* was that the entire frame? */
			arg->flags ^= F_INFRAME;
		return read_len;
	} else { /* not in frame - interpret a new frame */
		unsigned char *fr = (unsigned char*) arg->buf;
#ifdef RSERV_DEBUG /* FIXME: we don't use more -- why? */
		size_t more = (arg->ver < 4) ? ((fr[0] & 0x80) == 0x80) : ((fr[0] & 0x80) == 0);
#endif
		int mask = 0, ct = fr[0] & 127;
		size_t need = 0, at_least, payload;
		size_t len = 0;
		/* set the F_IN_BIN flag according to the frame type */
		if ((arg->ver < 4 && ct == 5) ||
			(arg->ver >= 4 && ct == 2))
			arg->flags |= F_IN_BIN;
		else
			arg->flags &= ~ F_IN_BIN;
		SET_F_FT(arg->flags, ct);
		if (arg->bp == 1) {
			ssize_t n = WS_wire_recv(arg, arg->buf + 1, arg->bl - 1);
			if (n < 1) return n;
			arg->bp = n + 1;
		}
		if (arg->ver > 6 && fr[1] & 0x80) mask = 1;
		len = fr[1] & 127;
		need = 2 + (mask ? 4 : 0) + ((len < 126) ? 0 : ((len == 126) ? 2 : 8));
		while (arg->bp < need) {
			ssize_t n = WS_wire_recv(arg, arg->buf + arg->bp, arg->bl - arg->bp);
			if (n < 1) return n;
			arg->bp += n;
		}
		if (len == 126)
			len = (fr[2] << 8) | fr[3];
		else if (len == 127) {
			if (fr[2] || fr[3]) {
#ifdef RSERV_DEBUG
				fprintf(stderr, "WS_recv_data: requested frame length is way too big - we support only up to 256TB\n");
#endif
				return -1;
			}
#define SH(X,Y) (((uint64_t)X) << Y)
			uint64_t raw_len = SH(fr[4], 48) | SH(fr[5], 40) | SH(fr[5], 32) | SH(fr[6], 24) | SH(fr[7], 16) | SH(fr[8], 8) | (uint64_t)fr[9];
			if (raw_len > rlen_max - 64L) {
#ifdef RSERV_DEBUG
				fprintf(stderr, "WS_recv_data: requested frame length is larger than rlen_max for this platform\n");
#endif
				return -1;
			}
			len = (size_t) raw_len;
		}
#ifdef RSERV_DEBUG
		fprintf(stderr, "INFO: WS_recv_data frame type=%02x, len=%lu, more=%d, mask=%d (need=%d)\n", ct, (unsigned long) len, (int) more, (int) mask, (int) need);
#endif
		at_least = need + len;
		if (at_least > arg->bl)
			at_least = arg->bl;

		/* this is always positive, because need is at most 14 and at_least
		   is need + len only capped by the buffer size which is >14 */
		payload = at_least - need;

		while (arg->bp < at_least) {
			ssize_t n = WS_wire_recv(arg, arg->buf + arg->bp, at_least - arg->bp);
#ifdef RSERV_DEBUG
			fprintf(stderr, "INFO: read extra %ld bytes in addition to %d (need %ld)\n", (long) n, arg->bp, (long) need);
#endif
			if (n < 1) return n;
			arg->bp += n;
		}
		/* FIXME: more recent protocols require MASK at all times */
		if (mask) {
#if defined RSERV_DEBUG && defined WS_DEBUG
			{ int i; for (i = 0; i < payload; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[need + i]); fprintf(stderr,"\n"); }
#endif
			SET_F_MASK(arg->flags, do_mask(arg->buf + need, payload, 0, arg->buf + need - 4));
			memcpy(&arg->l2, arg->buf + need - 4, 4);
#if defined RSERV_DEBUG && defined WS_DEBUG
			{ int i; for (i = 0; i < payload; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[need + i]); fprintf(stderr,"\n"); }
#endif
		} else arg->flags &= ~ F_MASK;
		
		/* if the frame fits in the buffer (payload == len since it has not been truncated) and
		   read requested at least as much, we can deliver the whole frame */
		if (payload == len && read_len >= payload) {
#ifdef RSERV_DEBUG
			fprintf(stderr, "INFO: WS_recv_data frame has %ld bytes, requested %ld, returning entire frame\n", (long) len, (long) read_len);
#endif
			memcpy(buf, arg->buf + need, len);
			if (arg->bp > at_least) { /* this is unlikely but possible if we got multiple frames in the first read */
				memmove(arg->buf, arg->buf + at_least, arg->bp - at_least);
				arg->bp -= at_least;
			} else arg->bp = 0;
			return len;
		}
		
		/* left-over - we will end up with an incompete frame - either we got an incomplete frame or
		   less than the span of the frame was requested */
#ifdef RSERV_DEBUG
		fprintf(stderr, "INFO: WS_recv_data frame has %lu bytes (of %lu frame), requested %d, returning partial frame\n", (unsigned long) payload, (unsigned long) len, (int) read_len);
#endif
		/* we can only return all we got */
		if (read_len > payload)
			read_len = payload;
		memcpy(buf, arg->buf + need, read_len);
		if (arg->bp > need + read_len) /* if there is any data beyond what we will deliver, we need to move it */
			memmove(arg->buf, arg->buf + need + read_len, arg->bp - need - read_len);
		len -= read_len; /* left in the frame is total minus delivered - we only get here if the frame did not fit, so len > 0 */
		arg->l1 = len;
		arg->flags |= F_INFRAME;
		arg->bp -= need + read_len;
		return read_len;
	} /* in frame */
}

server_t *create_WS_server(int port, int flags, ws_connected_fn_t connected) {
	server_t *srv = create_server(port, 0, 0, flags);
	if (srv) {
		srv->connected = WS_connected;
		srv->send_resp = WS_send_resp;
		srv->recv      = WS_recv_data;
		srv->send      = WS_send_data;
		srv->fin       = server_fin;
		srv->aux       = (void*) connected;
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
