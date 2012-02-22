#include "Rsrv.h"
#include "RSserver.h"
#include "md5.h"

#include <sisocks.h>
#include <string.h>
#include <stdio.h>

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s, ss;
	int ws_ver;
};

static void mask(int len, char *msg, char *key) {
	int i = 0;
	while (i < len) {
		msg[i] ^= key[i & 3];
		i++;
    }
}

#if 0

/* Receive exactly one non-00 protocol frame */
static int recv_frame() {
	SEXP ans = R_NilValue;
	char *buf, *p;
	unsigned char h1[2];  // header
	unsigned char h2[8];  // extended payload length
	unsigned char h3[4];  // masking key
	unsigned char c;
	unsigned long long len, l;
	int mask;
	int l2 = 0, l3 = 0;
	
	memset(h1, 0, 2);
	j = recv(s, (char *)h1, 2, 0);
	if (j < 2) return ans;
	mask = (h1[1] & (1 << 7)) > 0;
	c = h1[1] & ~(1 << 7);
	j = c;
	if (j == 126) {
		memset(h2, 0, 8);
		j = recv(s, (char *)h2, 2, 0);
		if (j < 2) return ans;
		len = 256 * (unsigned int)h2[0] + (unsigned int)h2[1];
		l2 = 2;
	} else if (j == 127) {
		memset(h2,0,8);
		j = recv(s, (char *)h2, 8, 0);
		if (j < 8) return ans;
		// XXX should be able to directly cast this, right?  memcpy(&len, h2, 8);
		len = h2[7];
		l = h2[6]; l = l << 8; len+=l;
		l = h2[5]; l = l << 16; len+=l;
		l = h2[4]; l = l << 24; len+=l;
		l = h2[3]; l = l << 32; len+=l;
		l = h2[2]; l = l << 40; len+=l;
		l = h2[1]; l = l << 48; len+=l;
		l = h2[0]; l = l << 56; len+=l;
		l2 = 8;
	} else len = j;

	if(mask){
		memset(h3,0,4);
		j = recv(s, (char *)h3, 4, 0);
		if (j < 4) return ans;
		l3 = 4;
	}
	buf = (char *)malloc(2 + l2 + l3 + len);
	p = buf;
	memcpy(p, h1, 2); p+=2;
	if (l2 > 0) memcpy(p, h2, l2);
	p += l2;
	if (l3 > 0) memcpy(p, h3, l3);
	p += l3;
	j = (unsigned int)len;
	j = recv(s, (char *)p, len, 0);
	if (j < 1) {
		free(buf);
		return(ans);
	}
	len = len + 2 + l2 + l3;
    free(buf);
	
	return ans;
}

/* Receive exactly one 00 protocol frame, damned inefficiently.  */
static void recv_frame00() {
	SEXP ans = R_NilValue;
	char c;
	char *buf, *p;
	struct pollfd pfds;
	int h, j, k;
	int bufsize = MBUF;
	buf = (char *)malloc(MBUF);
	k = 0;
	
	while(h>0) {
		j = recv(s, &c, 1, 0);
		if(j<1) break;
		buf[k] = c;
		k++;
		if(c<0) break;
		if(k>maxbufsize){
			warning("Maxmimum message size exceeded.");
			break;
		}
		if(k+1 > bufsize) {
			bufsize = bufsize + MBUF;
			buf = (char *)realloc(buf, bufsize);  
		}
		h = poll(&pfds, 1, 50);
	}

	return ans;
}

#endif

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

static void WS_connected(void *parg) {
	args_t *arg = (args_t*) parg;
	server_t *srv = arg->srv;
	SOCKET s = arg->s;
	int n, bp = 0, empty_lines = 0, request_line = 1;

	struct header_info h;
	
	char *buf = (char*) malloc(LINE_BUF_SIZE);
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

	arg->ws_ver = h.version;
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
		snprintf(buf, LINE_BUF_SIZE, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Origin: %s\r\nSec-WebSocket-Location: ws://%s%s\r\n\r\n",
				 h.origin, h.host, h.path);
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
		snprintf(buf, LINE_BUF_SIZE, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", b64);
		send(s, buf, strlen(buf), 0);
#ifdef RSERV_DEBUG
		printf("Responded with WebSockets.04+ handshake\n");
#endif
	}
	free(buf);
}

static void WS_send_resp(args_t *arg, int rsp, rlen_t len, void *buf) {

}

static int  WS_send_data(args_t *arg, void *buf, rlen_t len) {
	return 0;
}

static int  WS_recv_data(args_t *arg, void *buf, rlen_t len) {
	return 0;
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
    Rprintf("\nCaught break signal, shutting down Rserve.\n");
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
