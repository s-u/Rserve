#include "Rsrv.h"
#include "RSserver.h"
#include "md5.h"

#include <sisocks.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s;
	SOCKET ss;
	/* the following entries are not populated by Rserve but can be used by server implemetations */
	char *buf, *sbuf;
	int   ver, bp, bl, sp, sl, flags;
	long  l1, l2;
};

static void do_mask(char *msg, int len, char *key) {
	int i = 0;
	while (i < len) {
		msg[i] ^= key[i & 3];
		i++;
    }
}

#define LINE_BUF_SIZE 4096

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

static unsigned long count_spaces(const char *c) {
	unsigned long n = 0;
	while (*c) { if (*c == ' ') n++; c++; }
	return n;	
}

static unsigned long count_digits(const char *c) {
	unsigned long n = 0;
	while (*c) { if (*c >= '0' && *c <= '9') n = n * 10L + (unsigned long)(*c - '0'); c++; }
	return n;	
}

/* from sha1.c */
void sha1hash(const char *buf, int len, unsigned char hash[20]);
/* from base64.c */
void base64encode(const unsigned char *src, int len, char *dst);
/* from Rserve.c */
void Rserve_QAP1_connected(args_t *arg);

#define FRAME_BUFFER_SIZE 65536

static void WS_connected(void *parg) {
	args_t *arg = (args_t*) parg;
	server_t *srv = arg->srv;
	SOCKET s = arg->s;
	int n, bp = 0, empty_lines = 0, request_line = 1;

	struct header_info h;
	
	char *buf;

	/* we have to perform a handshake before giving over to QAP 
	   but we have to fork() first as to not block the server on handshake */
	if (Rserve_prepare_child(arg) != 0) { /* parent or error */
		free(arg);
		return;
	}

	buf = (char*) malloc(LINE_BUF_SIZE);
	if (!buf) {
		char lbuf[64];
		strcpy(lbuf, "HTTP/1.1 500 Out of memory\r\n\r\n");
		send(s, lbuf, strlen(lbuf), 0);
		closesocket(s);
		arg->s = -1;
		return;
	}
	buf[LINE_BUF_SIZE - 1] = 0;

	memset(&h, 0, sizeof(h));

#ifdef RSERV_DEBUG
	printf("INFO:WS: connection accepted for WebSockets\n");
#endif

	while ((n = recv(s, buf + bp, LINE_BUF_SIZE - bp - 1, 0)) > 0) {
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
				send(s, buf, strlen(buf), 0);
				closesocket(s);
				arg->s = -1;
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
		send(s, buf, strlen(buf), 0);
		closesocket(s);
		arg->s = -1;
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
			n = recv(s, buf + bp, 8 - bp, 0);
			if (n < 8 - bp) {
				strcpy(buf, "HTTP/1.1 400 Bad Request (Key3 incomplete)\r\n\r\n");
				send(s, buf, strlen(buf), 0);
				closesocket(s);
				arg->s = -1;
				free(buf);
				return;
			}
		}
		if (!h.origin || !h.key1 || !h.key2 || !h.host) {
			strcpy(buf, "HTTP/1.1 400 Bad Request (at least one key header is missing)\r\n\r\n");
			send(s, buf, strlen(buf), 0);
			closesocket(s);
			arg->s = -1;
			free(buf);
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
		send(s, buf, bp + 16, 0);
#ifdef RSERV_DEBUG
		printf("Responded with WebSockets.00 handshake\n");
#endif
	} else {
		unsigned char hash[20];
		char b64[40];
		strcpy(buf, h.key);
		strcat(buf, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		sha1hash(buf, strlen(buf), hash);
		base64encode(hash, sizeof(hash), b64);
		/* FIXME: if the client requests multiple protocols, we should be picking one but we don't */
		snprintf(buf, LINE_BUF_SIZE, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s%s%s\r\n", b64, h.protocol ? "Sec-WebSocket-Protocol: " : "", h.protocol ? h.protocol : "", h.protocol ? "\r\n" : "");
		send(s, buf, strlen(buf), 0);
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

	/* switch to underlying QAP1 */
	Rserve_QAP1_connected(arg);
}

#define F_INFRAME 0x10

static void WS_send_resp(args_t *arg, int rsp, rlen_t len, void *buf) {
	unsigned char *sbuf = (unsigned char*) arg->sbuf;
	if (arg->ver == 0) {
	} else {
		struct phdr ph;
		rlen_t i = 0;
		long flen = len + sizeof(ph);
		memset(&ph, 0, sizeof(ph));
		ph.cmd = itop(rsp | CMD_RESP);	
		ph.len = itop(len);
#ifdef __LP64__
		ph.res = itop(len >> 32);
#endif

		if (flen < arg->sl - 8 && len < 65536) {
			int n, pl = 0;
			sbuf[pl++] = (arg->ver < 4) ? 0x05 : 0x82; /* binary, 4+ has inverted FIN bit */
			if (flen < 126) /* short length */
				sbuf[pl++] = flen;
			else if (flen < 65536) { /* 16-bit */
				sbuf[pl++] = 126;
				sbuf[pl++] = flen >> 8;
				sbuf[pl++] = flen & 255;
			}
			memcpy(sbuf + pl, &ph, sizeof(ph));
			pl += sizeof(ph);
			/* no masking or other stuff */
			if (len) memcpy(sbuf + pl, buf, len);
			n = send(arg->s, sbuf, len + pl, 0);
			fprintf(stderr, "WS_send_dresp: sending 4+ frame (ver %02d), n = %d / %d\n", arg->ver, n, (int) len + pl);
			{ int i; for (i = 0; i < len + pl; i++) fprintf(stderr, " %02x", (int) sbuf[i]); fprintf(stderr,"\n"); }

		} else {
			fprintf(stderr, "ERROR in WS_send_data: data too large\n");
		}		
	}
}

static int  WS_send_data(args_t *arg, void *buf, rlen_t len) {
	unsigned char *sbuf = (unsigned char*) arg->sbuf;
	if (arg->ver == 0) {
		if (len < arg->sl - 2) {
			int n;
			sbuf[0] = 0;
			memcpy(sbuf + 1, buf, len);
			sbuf[len + 1] = 0xff;
			n = send(arg->s, sbuf, len + 2, 0);
			fprintf(stderr, "WS_send_data: sending 00 frame, n = %d / %d\n", n, (int) len + 2);
			if (n == len + 2) return len;
			if (n < len + 2 && n >= len) return len - 1;
			return n;
		} else {
			fprintf(stderr, "ERROR in WS_send_data: data too large\n");
			return -1;
		}
	} else {
		if (len < arg->sl - 8 && len < 65536) {
			int n, pl = 0;
			sbuf[pl++] = (arg->ver < 4) ? 0x04 : 0x81; /* text, 4+ has inverted FIN bit */
			if (len < 126) /* short length */
				sbuf[pl++] = len;
			else if (len < 65536) { /* 16-bit */
				sbuf[pl++] = 126;
				sbuf[pl++] = len >> 8;
				sbuf[pl++] = len & 255;
			}
			/* no masking or other stuff */
			memcpy(sbuf + pl, buf, len);
			n = send(arg->s, sbuf, len + pl, 0);
			fprintf(stderr, "WS_send_data: sending 4+ frame (ver %02d), n = %d / %d\n", arg->ver, n, (int) len + pl);
			if (n == len + pl) return len;
			if (n < len + pl && n >= len) return len - 1;
			return n;
		} else {
			fprintf(stderr, "ERROR in WS_send_data: data too large\n");
			return -1;
		}		
	}
	return 0;
}

static int  WS_recv_data(args_t *arg, void *buf, rlen_t read_len) {
	fprintf(stderr, "WS_recv_data for %d (bp = %d)\n", (int) read_len, arg->bp);
	if (arg->flags & F_INFRAME && arg->bp > 0) { /* do we have content of a frame what has not been picked up yet? */
		fprintf(stderr, "WS_recv_data: have %d bytes of a frame, requested %d, returning what we have\n", arg->bp, (int) read_len);
		if (read_len > arg->bp) read_len = arg->bp;
		memcpy(buf, arg->buf, read_len);
		if (arg->bp > read_len)
			memmove(arg->buf, arg->buf + read_len, arg->bp - read_len);
		arg->bp -= read_len;
		arg->l1 -= read_len;
		if (arg->l1 == 0) arg->flags ^= F_INFRAME;
		return read_len;
	}
	if (arg->bp == 0) {
		int n = recv(arg->s, arg->buf, arg->bl, 0);
		if (n < 1) return n;
		arg->bp = n;
		fprintf(stderr, "INFO: WS_recv_data: read %d bytes:\n", n);
		{ int i; for (i = 0; i < n; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[i]); fprintf(stderr,"\n"); }
	}
	if (arg->ver > 3) {
		if (arg->flags & F_INFRAME) {
			
		} else {
			unsigned char *fr = (unsigned char*) arg->buf;
			int more = (arg->ver < 4) ? ((fr[0] & 0x80) == 0x80) : ((fr[0] & 0x80) == 0), mask = 0;
			int need = 0, ct = fr[0] & 127;
			long len = 0;
			if (arg->bp == 1) {
				int n = recv(arg->s, arg->buf + 1, arg->bl - 1, 0);
				if (n < 1) return n;
				arg->bp = n + 1;
			}
			if (arg->ver > 6 && fr[1] & 0x80) mask = 1;
			len = fr[1] & 127;
			need = 2 + (mask ? 4 : 0) + ((len < 126) ? 0 : ((len == 126) ? 2 : 8));
			while (arg->bp < need) {
				int n = recv(arg->s, arg->buf + arg->bp, arg->bl - arg->bp, 0);
				if (n < 1) return n;
				arg->bp += n;
			}
			if (len == 126)
				len = (fr[2] << 8) | fr[3];
			else if (len == 127) {
				if (fr[2] || fr[3]) {
					fprintf(stderr, "WS_recv_data: requested frame length is way too big - we support only up to 256TB\n");
					return -1;
				}
#define SH(X,Y) (((long)X) << Y)
				len = SH(fr[4], 48) | SH(fr[5], 40) | SH(fr[5], 32) | SH(fr[6], 24) | SH(fr[7], 16) | SH(fr[8], 8) | (long)fr[9];
			}
			fprintf(stderr, "INFO: WS_recv_data frame type=%02x, len=%d, more=%d, mask=%d (need=%d)\n", ct, (int) len, more, mask, need);
			if (arg->bp + need + len <= arg->bl) { /* we can slurp it */
				while (arg->bp < need + len) {
					int n = recv(arg->s, arg->buf + arg->bp, arg->bl - arg->bp, 0);
					fprintf(stderr, "INFO: read extra %d bytes in addition to %d (need %d)\n", n, arg->bp, need);
					if (n < 1) return n;
					arg->bp += n;
				}
				if (mask) {
					{ int i; for (i = 0; i < len; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[need + i]); fprintf(stderr,"\n"); }
					do_mask(arg->buf + need, len, arg->buf + need - 4);
					{ int i; for (i = 0; i < len; i++) fprintf(stderr, " %02x", (int) (unsigned char) arg->buf[need + i]); fprintf(stderr,"\n"); }
				}
				if (len <= read_len) {
					fprintf(stderr, "INFO: WS_recv_data frame has %d bytes, requested %d, returning entire frame\n", (int) len, (int) read_len);
					memcpy(buf, arg->buf + need, len);
					return len;
				}
				/* left-over */
				fprintf(stderr, "INFO: WS_recv_data frame has %d bytes, requested %d, returning partial frame\n", (int) len, (int) read_len);
				memcpy(buf, arg->buf + need, read_len);
				len -= read_len;
				memmove(arg->buf, arg->buf + need + read_len, len);
				arg->l1 = len;
				arg->flags |= F_INFRAME;
				arg->bp = len;
				return read_len;
			} else { /* FIXME */
			}
		}
	}
}

server_t *create_WS_server(int port) {
	server_t *srv = create_server(port, 0);
	if (srv) {
		srv->connected = WS_connected;
		srv->send_resp = WS_send_resp;
		srv->recv      = WS_recv_data;
		srv->send      = WS_send_data;
		srv->fin       = server_fin;
		add_server(srv);
		return srv;
	}
	return 0;
}

#include <Rinternals.h>

void serverLoop(void);

#ifdef unix
typedef void (*sig_fn_t)(int);

static void brkHandler_R(int i) {
    Rprintf("\nCaught break signal, shutting down WebSockets.\n");
    stop_server_loop();
}
#endif

SEXP run_WSS(SEXP sPort) {
	server_t *srv = create_WS_server(asInteger(sPort));
	if (srv) {
		sig_fn_t old;
		Rprintf("-- starting WebSockets server at port %d (pid=%d) --\n", asInteger(sPort), getpid());
#ifdef unix
		old = signal(SIGINT, brkHandler_R);
#endif
		serverLoop();
#ifdef unix
		signal(SIGINT, old);
#endif
		rm_server(srv);
	}
	return ScalarLogical(TRUE);
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
