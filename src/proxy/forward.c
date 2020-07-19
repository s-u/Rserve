/* HTTP and WebSocket server serving static content and
   forwarding QAP1 protocol.
   Based on Rserve.

   (C)Copyright 2014 Simon Urbanek

   License: BSD
   
*/

#include "http.h"
#include "http_tools.h"
#include "websockets.h"
#include "qap.h"
#include "tls.h"
#include "rserr.h"
#include "ulog.h"
#include "bsdcmpt.h"
#include "chandler.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/un.h> /* needed for unix sockets */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* send OOB idle on WebSockets every 10 min (FIXME: make this configurable) */
#define HEARTBEAT_INTERVAL 600

#define MAX_READ_CHUNK (1024 * 1024)
#define MAX_SEND_CHUNK (1024 * 1024)

/* FIXME: only for little endian machines */
#define ptoi(X) (X)
#define itop(X) (X)

static char buf[1024];

static char *doc_root = ".";
static int   doc_root_len = 1;
static char *sm_host = 0;
static char *sm_port = 0;
static char *default_sm_port = "40";

static const char *infer_content_type(const char *fn) {
    const char *ext = fn ? strrchr(fn, '.') : 0;
    if (!ext) return 0;
    ext++;
    if (!strcmp(ext, "svg")) return "image/svg+xml";
    if (!strcmp(ext, "js"))  return "application/javascript";
    if (!strcmp(ext, "css")) return "text/css";
    if (!strcmp(ext, "png")) return "image/png";
    if (!strcmp(ext, "jpeg") || !strcmp(ext, "jpg")) return "image/jpeg";
    return 0;
}

static void http_request(http_request_t *req, http_result_t *res) {
    FILE *f;
    char *s;
    struct stat st;
    double ts;
    int not_modified = 0, add_slash = 0;
    const char *append_headers = 0, *c_type = 0;

    fprintf(stderr, "----\nINFO: request for '%s', Date: %s, headers:\n%s\n", req->url, posix2http(req->date), req->headers ? req->headers : "<NONE>");
    /* leave room for ".gz\0" plus leading slash */
    if (req->url[0] != '/' && doc_root_len && doc_root[doc_root_len - 1] != '/') add_slash = 1;
    s = (char*) malloc(strlen(req->url) + doc_root_len + 8);
    /* FIXME: if (!s) */
    strcpy(s + doc_root_len + add_slash, req->url);
    memcpy(s, doc_root, doc_root_len);
    if (add_slash) s[doc_root_len] = '/';

    /* if any handler served the request, exit */
    if (call_content_handlers(req, res, s)) {
        free(s);
        return;
    }

    /* FIXME: technically, the processing of regular, static files
       should also be jsut a handler -- move the code below into one. */

    if (stat(s, &st) || !(f = fopen(s, "rb"))) {
        free(s);
	res->err = strdup("Path not found");
	res->code = 404;
	return;
    }

    c_type = infer_content_type(s);

    /* check for conditional GET */
    if (req->headers) {
	const char *if_mod = get_header(req, "If-Modified-Since");
	if (if_mod) {
	    double since = http2posix(if_mod);
	    if (since >= MTIME(st)) {
		not_modified = 1;
		res->code = 304;
	    }
	}
    }

    /* worry about content only if the result is not 304 Not Modified */
    if (!not_modified) {
	/* check whether the client is ok with gzip compressed version and use that if possible */
	const char *accept = get_header(req, "Accept-Encoding");
	if (accept) {
	    const char *e = strchr(accept, '\n');
	    if (e && strnstr(accept, "gzip", e - accept)) { /* accepts gzip? */
		struct stat gzst;
		FILE *gzf;
		strcat(s, ".gz");
		/* .gz present and not older than the source = serve the compressed version */
		if (!stat(s, &gzst) && MTIME(gzst) >= MTIME(st) && (gzf = fopen(s, "rb"))) {
		    fclose(f);
		    f = gzf;
		    st = gzst;
		    append_headers = "Content-Encoding: gzip\r\n";
		}
	    }
	}

	res->payload = (char*) malloc((st.st_size < 512) ? 512 : st.st_size);
	res->payload_len = st.st_size;
	if (fread(res->payload, 1, res->payload_len, f) != res->payload_len) {
	    snprintf(res->payload, 512, "I/O error: %s", strerror(errno));
	    res->err = res->payload;
	    res->payload = 0;
	    res->payload_len = 0;
	    res->code = 500;
	    fclose(f);
            free(s);
	    return;
	}
    }
    free(s);

    fclose(f);
    /* append Last-Modified: based on the served file and set no-cache */
    ts = (double) time(0);
    snprintf(buf, sizeof(buf), "Last-Modified: %s\r\nCache-Control: no-cache\r\n%s",
	     posix2http((MTIME(st) > ts) ? ts : MTIME(st)),
	     append_headers ? append_headers : ""
        );
    res->headers = strdup(buf);
    if (c_type) res->content_type = strdup(c_type);
}

struct args {
    server_t *srv; /* server that instantiated this connection */
};

typedef struct queue {
    unsigned long len;
    unsigned long seq;
    struct queue *next;
    char data[1];
} queue_t;

typedef struct {
    const char *qap_socket_path;
    
    args_t *ws;  /* WebSocket args structure */
    int qap;     /* QAP socket */
    pthread_mutex_t mux;
    pthread_cond_t  queue_available;
    int queue_sleeping; /* if set the queue consumer is sleeping and wants to be signalled */
    unsigned long queue_seq;
    int qap_stage, active, qap_alive, ws_alive;
    queue_t *ws_to_qap;
} proxy_t;

/* FIXME: we have no good way to pass this to the http handler, so we use a global var for now */
proxy_t *proxy;

static void *forward(void *ptr) {
    qap_hdr_t hdr;
    char idstr[34];
    proxy_t *proxy = (proxy_t*) ptr;
    int s = proxy->qap;
    ssize_t n;
    queue_t *qe;

    ulog("QAP->WS  INFO: started forwarding thread");
    while (proxy->active && proxy->qap_alive) {
	n = read(s, &hdr, sizeof(hdr));
	ulog("QAP->WS  INFO: read n = %d", n);
	if (n < 0) { /* error */
	    if (errno == EINTR)
		continue; /* don't worry about EINTR */
	    ulog("QAP->WS  ERROR: read header: %s", strerror(errno));
	    break;
	}
	if (n != sizeof(hdr)) { /* not even complete header */
	    if (n == 0)
		ulog("QAP->WS  NOTE: QAP socket closed");
	    else
		ulog("QAP->WS  ERROR: read header: %d read, %d expected", n, (int) sizeof(hdr));
	    break;
	}
	/* there is one special case - if this is non-OCAP mode and qap_stage is zero
	   then the first packet will be IDstring and not a QAP message */
	if (proxy->qap_stage == 0) { /* the first 4 bytes from the server must be one of:
					Rsrv - Rserve ID string (32 bytes)
					RSpx - Rserve proxy
					RsOC - OCAP mode
				     */
	    if (!memcmp((char*)&hdr, "Rsrv", 4) && !memcmp(((char*)&hdr) + 8, "QAP1", 4)) { /* QAP1 = ID string */
		memcpy(idstr, &hdr, sizeof(hdr));
		{
		    idstr[12] = 0; /* it's Rsrv<version>QAP1 and stop at that for display purposes */
		    ulog("QAP->WS  INFO: *** server protocol: %s", idstr);
		    memcpy(idstr, &hdr, sizeof(hdr));
		}
		n = read(s, idstr + sizeof(hdr), 32 - sizeof(hdr));
		ulog("QAP->WS  INFO: read[IDstring] n = %d", n);
		if (n < 32 - sizeof(hdr)) {
		    ulog("QAP->WS  ERROR: read QAP1 ID string: %d read, %d expected", n, 32 - sizeof(hdr));
		    break;
		}
		if (memcmp(idstr + 8, "QAP1", 4)) {
		    ulog("QAP->WS  ERROR: Rserve protocol used is not QAP1");
		    break;
		}
		pthread_mutex_lock(&proxy->mux);
		ulog("QAP->WS  INFO: forwarding IDstring (%d bytes)", 32);
		n = proxy->ws_alive ? proxy->ws->srv->send(proxy->ws, idstr, 32) : -2;
		pthread_mutex_unlock(&proxy->mux);
		if (n < 32) { /* ID string forward failed */
		    ulog("QAP->WS  ERROR: send QAP1 ID string failed: %d read, %d expected [%s]", n, 32, strerror(errno));
		    break;
		}
		/* done - back to normal mode */
		proxy->qap_stage = 1;
		WS_set_binary(proxy->ws, 1); /* QAP is binary */
		continue;
	    }

	    if (!memcmp((char*)&hdr, "RSpx", 4)) { /* RSpx = Rserve proxy */
		ulog("QAP->WS  ERROR: RSpx proxy protocol is currently unsupported");
		/* currently unsupported */
		break;
	    }

	    if (!memcmp((char*)&hdr, "RsOC", 4)) { /* RsOC = OCAP mode - strictly QAP from the start */
		ulog("QAP->WS  INFO: *** server protocol: Rserve OCAP QAP1");
		proxy->qap_stage = 1;
		WS_set_binary(proxy->ws, 1); /* QAP is binary */
	    } else { /* everything else = bad packet */
		ulog("QAP->WS  ERROR: server doesn't use any of Rsrv/QAP1, RSpx, RsOC - aborting");
		break;
	    }
	}

	/* from here on it's guaranteed QAP */
	{
	    unsigned long tl, pos = 0;
#if LONG_MAX > 2147483647
	    tl = ptoi(hdr.res);
	    tl <<= 32;
	    tl |= ptoi(hdr.len);
#else
	    tl = ptoi(hdr.len);
#endif
	    ulog("QAP->WS  INFO: <<== message === (cmd=0x%x, msg_id=0x%x), size = %lu", hdr.cmd, hdr.msg_id, tl);

	    /* FIXME: this is really an abuse of queue_t for historical reasons -- we just use it as a buffer!! */
	    if (!(qe = malloc(tl + sizeof(hdr) + sizeof(queue_t)))) { /* failed to allocate buffer for the message */
		/* FIXME: we should flush the contents and respond with an error condition */
		ulog("QAP->WS  ERROR: unable to allocate memory for message of size %lu", tl);
		break;
	    }

	    qe->next = 0;
	    qe->len = tl + sizeof(hdr);
	    memcpy(qe->data, &hdr, sizeof(hdr));

	    while (pos < tl) {
	        n = read(s, qe->data + sizeof(hdr) + pos, (tl - pos > MAX_READ_CHUNK) ? MAX_READ_CHUNK : (tl - pos));
		ulog("QAP->WS  INFO: read n=%d (%lu of %lu)", n, pos, tl);		     
		if (n < 1) break;
		pos += n;
	    }

	    if (pos < tl) {
	        ulog("QAP->WS  ERROR: could read only %lu bytes of %lu bytes message [%s]", pos, tl, strerror(errno));
		break; /* bail out on read error/EOF */
	    }

	    ulog("QAP->WS  INFO: sending total of %lu bytes", qe->len);
	    /* message complete - send */
	    pthread_mutex_lock(&proxy->mux);
	    n = (proxy->ws_alive) ? proxy->ws->srv->send(proxy->ws, qe->data, qe->len) : -2;
	    ulog("QAP->WS  INFO: send returned %d", n);
	    pthread_mutex_unlock(&proxy->mux);
	    if (n < qe->len) {
	        ulog("QAP->WS  ERROR: was able to send only %ld bytes of %lu bytes message [%s]", (long) n, tl, strerror(errno));
		free(qe);
		break;
	    }
	    free(qe);
	}
    }
    closesocket(s);
    proxy->qap_alive = 0;
    proxy->qap = -1;
    /* QAP socket is dead */
    ulog("QAP->WS  INFO: finished forwarding thread, QAP closed");
    return 0;
}

/* WS->queue */
static void *enqueue(void *ptr) {
    proxy_t *proxy = (proxy_t*) ptr;
    qap_hdr_t hdr;

    ulog("WS ->Q   INFO: started enqueuing thread");
    while (proxy->active && proxy->ws_alive) {
	int n = proxy->ws->srv->recv(proxy->ws, &hdr, sizeof(hdr));
	unsigned long tl, pos = 0;
	queue_t *qe;

	ulog("WS ->Q   INFO: WS recv = %d", n);
	if (n < sizeof(hdr)) {
	    if (n == 0)
		ulog("WS ->Q   INFO: WebSocket closed");
	    else
		ulog("WS ->Q   ERROR: header read expected %d, got %d [%s]", sizeof(hdr), n, strerror(errno));
	    break;
	}

#if LONG_MAX > 2147483647
	tl = ptoi(hdr.res);
	tl <<= 32;
	tl |= ptoi(hdr.len);
#else
	tl = ptoi(hdr.len);
#endif
	ulog("WS ->Q   INFO: === message ==>> (cmd=0x%x, msg_id=0x%x), size = %lu", hdr.cmd, hdr.msg_id, tl);

	if (!(qe = malloc(tl + sizeof(hdr) + sizeof(queue_t)))) { /* failed to allocate buffer for the message */
	    /* FIXME: we should flush the contents and respond with an error condition */
	    ulog("WS ->Q   ERROR: unable to allocate memory for message of size %lu", tl);
	    break;
	}

	qe->next = 0;
	qe->len = tl + sizeof(hdr);
	memcpy(qe->data, &hdr, sizeof(hdr));
	while (pos < tl) {
	    ulog("WS ->Q   INFO: requesting %lu (so far %lu of %lu)", tl - pos, pos, tl);
	    n = proxy->ws->srv->recv(proxy->ws, qe->data + sizeof(hdr) + pos, tl - pos);
	    if (n < 1) {
		ulog("WS ->Q   ERROR: read %lu of %lu then got %d [%s]", pos, tl, n, strerror(errno));
		break;
	    }
	    pos += n;
	}
	if (pos < tl) break;

	ulog("WS ->Q   INFO: enqueuing message");
	/* got the message - enqueue */
	pthread_mutex_lock(&proxy->mux);
	qe->seq = ++proxy->queue_seq; /* currently not needed, but safer to increment when locked */
	if (proxy->ws_to_qap) {
	    queue_t *q = proxy->ws_to_qap;
	    /* find the end of the queue */
	    while (q->next)
		q = q->next;
	    q->next = qe; /* append */
	} else
	    proxy->ws_to_qap = qe;
	if (proxy->queue_sleeping)
	    pthread_cond_signal(&proxy->queue_available);
	pthread_mutex_unlock(&proxy->mux);
	ulog("WS ->Q   INFO: done enqueuing");
    }

    pthread_mutex_lock(&proxy->mux);
    proxy->ws_alive = 0;
    /* signal queue so the main thread can check our status and find out that we're done */
    pthread_cond_signal(&proxy->queue_available);
    pthread_mutex_unlock(&proxy->mux);

    ulog("WS ->Q   INFO: finished enqueuing thread");

    /* WS will be closed by exitting from the main thread */
    return 0;
}

static void *heartbeat(void *ptr) {
    proxy_t *proxy = (proxy_t*) ptr;
    struct {
	qap_hdr_t hdr;
	unsigned int sexp_hdr, list_hdr, str_hdr;
	char str[8];
    } idle_msg;
    
    /* construct list("idle") OOB SEND packet by hand:
       QAP1(SEXP(list("idle"))) */
    memset(&idle_msg, 0, sizeof(idle_msg));
    idle_msg.hdr.cmd = itop(OOB_SEND);
    idle_msg.hdr.len = itop(20); /* 4 (SEXP) + 4 (VECTOR) + 4 (STR) + 8 ("idle\0\1\1\1") */
    idle_msg.sexp_hdr = itop(SET_PAR(DT_SEXP, 16));
    idle_msg.list_hdr = itop(SET_PAR(XT_VECTOR, 12));
    idle_msg.str_hdr  = itop(SET_PAR(XT_ARRAY_STR, 8));
    memset(idle_msg.str, 1, 8); /* pad with 1 */
    strcpy(idle_msg.str, "idle");

    while (proxy->active && proxy->ws_alive) {
	sleep(HEARTBEAT_INTERVAL);
	pthread_mutex_lock(&proxy->mux);
	if (proxy->ws_alive)
	    proxy->ws->srv->send(proxy->ws, &idle_msg, ptoi(idle_msg.hdr.len) + sizeof(qap_hdr_t));
	pthread_mutex_unlock(&proxy->mux);
    }
    return 0;
}
	    
static void ws_connected(args_t *arg, char *protocol) {
    int s;
    struct sockaddr_un sau;
    pthread_t forward_thread, enqueue_thread, heartbeat_thread;
    pthread_attr_t thread_attr;
    
    fprintf(stderr, "INFO: web sockets connected (protocol %s)\n", protocol ? protocol : "<NULL>");

    proxy->ws = arg;
    if ((s = proxy->qap = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
	RSEprintf("unable to get local socket: %s\n", strerror(errno));
	return;
    }
    
    memset(&sau, 0, sizeof(sau));
    sau.sun_family = AF_LOCAL;
    if (strlen(proxy->qap_socket_path) + 1 > sizeof(sau.sun_path)) {
	RSEprintf("local socket path too long\n");
	proxy->qap = -1;
	closesocket(s);
	return;
    }
    strcpy(sau.sun_path, proxy->qap_socket_path);
    if (connect(s, (struct sockaddr*)&sau, sizeof(sau))) {
	RSEprintf("unable to connect to local socket '%s': %s\n", sau.sun_path, strerror(errno));
	/* FIXME: report this to the client? */
	proxy->qap = -1;
	closesocket(s);
	return;
    }

    /* connected both ends */
    pthread_mutex_init(&proxy->mux, 0);	
    pthread_cond_init(&proxy->queue_available, 0);
    proxy->qap_stage = 0;
    proxy->ws_to_qap = 0;
    proxy->active = 1;
    proxy->ws_alive = 1;
    proxy->qap_alive = 1;

    /* create QAP -> WS forwarding thread */
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&forward_thread, &thread_attr, forward, proxy);

    /* create WS read enqueuing thread */
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&enqueue_thread, &thread_attr, enqueue, proxy);

    /* create WS heartbeat thread */
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&heartbeat_thread, &thread_attr, heartbeat, proxy);

    /* Note about the mutex:
       the mutex is locked for
       a) all operations on the queue
       b) for all WS send operations
       so the one operation that doesn't lock is
       the blocking WS read. Hence no other thread
       than "enqueue" (WS->Q) is allowed to call WS read. */

    /* what's left is queue -> QAP
       we use queue_available condition var to yield until
       equeue signals contents on the queue
     */
    while (proxy->active) {
	queue_t *q;
	pthread_mutex_lock(&proxy->mux);
	ulog("Q  ->QAP INFO: waiting for message in the queue");
	if (!proxy->ws_to_qap && proxy->qap_alive) { /* if there is nothing to process, wait until enqueue posts something */
	    proxy->queue_sleeping = 1;
	    pthread_cond_wait(&proxy->queue_available, &proxy->mux);
	    proxy->queue_sleeping = 0;
	}
	/* ok, we land here with the queue mutex still locked 
	   so we pull the message from the head of the queue and release the rest of the queue
	 */
	q = proxy->ws_to_qap;
	ulog("Q  ->QAP INFO: queue signalled - %s", q ? "message present" : "queue empty");
	if (q)
	    proxy->ws_to_qap = q->next;
	pthread_mutex_unlock(&proxy->mux);

	/* mutex unlocked, we own the message */
	if (q) {
	    if (!proxy->qap_alive) { /* QAP is dead */
		qap_hdr_t hdr = { 0, 0, 0, 0 }, *src = (qap_hdr_t*) q->data;
		if (!proxy->ws_alive) { /* WS is dead, too - get out */
		    proxy->active = 0;
		    break;
		}
		hdr.cmd = itop(SET_STAT(RESP_ERR, ERR_conn_broken));
		hdr.msg_id = src->msg_id;
		/* QAP is dead - signal an error */
		pthread_mutex_lock(&proxy->mux);
		if (proxy->ws_alive)
		    proxy->ws->srv->send(proxy->ws, &hdr, sizeof(hdr));
		pthread_mutex_unlock(&proxy->mux);
		/* don't close WS - we'll still respond to all
		   messages WS sends our way so it can unwind
		   all callbacks */
	    } else {
		unsigned long tl = q->len, pos = 0;
		while (pos < tl && proxy->qap != -1) {
		    int n = send(proxy->qap, q->data + pos, (tl - pos > MAX_SEND_CHUNK) ? MAX_SEND_CHUNK : (tl - pos), 0);
		    ulog("Q  ->QAP INFO: sent %d (at %lu of %lu)", n, pos, tl);
		    if (n < 1)
			break; /* send failed or broken pipe */
		    pos += n;
		}
		if (pos < tl) { /* QAP broken */
		    ulog("Q  ->QAP ERROR: send error, aborting QAP connection");
		    closesocket(proxy->qap);
		    proxy->qap = -1;
		    proxy->qap_alive = 0;
		    free(q);
		    break;
		}
		ulog("Q  ->QAP INFO: message delivered");
	    }
	    free(q);
	} else if (!proxy->ws_alive) { /* if the queue is empty and WS is dead,
					  it's time to leave */
	    ulog("INFO: WS closed and queue empty, clean shutdown");
	    proxy->active = 0;
	}
    }

    if (proxy->qap_alive) {
	/* QAP is still alive ... inform the thread that we're done and signal
	   so it breaks out of recv() */
	proxy->qap_alive = 0;
	pthread_kill(forward_thread, SIGINT);
    }
    
    /* if WS is still alive, we inform it about our shutdown */
    pthread_mutex_lock(&proxy->mux);
    if (proxy->ws_alive) {
	qap_hdr_t hdr = { 0, 0, 0, 0 };
	hdr.cmd = itop(OOB_SEND);
	proxy->ws_alive = 0;
	proxy->ws->srv->send(proxy->ws, &hdr, sizeof(hdr));
    }
    pthread_mutex_unlock(&proxy->mux);
    ulog("INFO: WebSockets forwarding process done.");
}

/* send a message to the server maranger if configured */
static void send_srvmgr(char *what) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;

    if (!sm_host || !sm_port) return; /* noop if no srvmgr is defined */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; /* IPv4/6 but TCP */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    if ((s = getaddrinfo(sm_host, sm_port, &hints, &result))) {
	ulog("ERROR: cannot resolve srvmgr host (%s): %s", sm_host, gai_strerror(s));
	return;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
	struct timeval timeout;
	sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (sfd == -1)
	    continue;
	/* reduce the timeout substantially to 200ms */
	timeout.tv_sec  = 0;
	timeout.tv_usec = 200000;
	setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
	    break;
	close(sfd);
    }

    if (!rp) {
	ulog("ERROR: cannot connect to srvmgr host (%s:%s): %s", sm_host, sm_port, strerror(errno));
	return;
    }
    send(sfd, what, strlen(what), 0);
    ulog("INFO: send '%s' to srvmgr %s:%s", what, sm_host, sm_port);
    close(sfd);
}

/* queuing notes:

   so far we are using a simple FIFO, but we need something smarter
   due to OOB_MSG which have to deliver results back by "jumping" the queue.
   For that, we have to keep track of requests sent to the QAP side
   hold any further requests until the reqeust is done. In the meantime,
   we have to allow OOB MSG to pass. This meas that QAP->WS thread
   has to also signal the queue in case the queue is blocked due
   to a pending request result.

   To make things even more fun, we may need to support multiple QAP
   connections, thus running one QAP->WS thread for each.
   We may be ok with just one Q->QAP thread - it simplifies things
   and the only issue is that transmitting a message to one QAP
   process blocks transmission to another one. However,
   Q->QAP connection is a local socket, so it's really fast
   (a 20Mb packet took only 36ms to transmit in debugging mode).

   Finally, we may want some protocol for QAPs to exchange
   messages with each other. Thsi should be easy, though, since
   the QAP->WS thread can simply enqueue the message instead
   of sending it.
*/

/* from rscript.c */
int R_script_handler(http_request_t *req, http_result_t *res, const char *path);
void R_script_socket(const char *s);

static int die(const char *str) { fprintf(stderr,"\nERROR: %s\n\n", str); return 1; }

#define TLS_INFO_KEY  1
#define TLS_INFO_CERT 2
#define TLS_INFO_CA   4

int main(int ac, char **av) {
    int http_port = 8088, ws_port = -1, i = 0, flags = 0, tls_info = 0;
    int active_servers = 0;
    const char *ulog_path = "ulog_socket";
    const char *scr_path = "Rscript_socket";

    ulog_set_app_name("forward");
    proxy = (proxy_t*) malloc(sizeof(proxy_t));
    memset(proxy, 0, sizeof(proxy_t));
    proxy->qap_socket_path = "Rserve_socket";

    while (++i < ac)
        if (av[i][0] == '-')
            switch (av[i][1]) {
            case 's': if (++i < ac) proxy->qap_socket_path = av[i]; else return die("missing path in -s <http-socket>"); break;
            case 'u': if (++i < ac) ulog_path = av[i]; else return die("missing path in -u <ulog-socket>"); break;
            case 'p': if (++i < ac) http_port = atoi(av[i]); else return die("missing HTTP port in -p <port>"); break;
            case 'w': if (++i < ac) ws_port = atoi(av[i]); else return die("missing WebSockets port in -w <port>"); break;
            case 'r': if (++i < ac) doc_root = av[i]; else return die("missing path in -r <doc-root>"); break;
            case 'R': if (++i < ac) scr_path = av[i]; else return die("missing path in -R <Rscript-socket>"); break;
	    case 'k': if (++i < ac) {
		    tls_t *tls = shared_tls(0);
		    if (!tls)
			tls = shared_tls(new_tls());
		    if (!tls)
			return die("unable to initialize SSL - you may be missing SSL support.");
		    if (!set_tls_pk(tls, av[i]))
			return perror_tls("ERROR: Unable to load SSL key from '%s': ", av[i]);
		    flags |= SRV_TLS;
		    tls_info |= TLS_INFO_KEY;
		} else return die("missing key path in -k <key-path>");
		break;
	    case 'C': if (++i < ac) {
		    tls_t *tls = shared_tls(0);
		    if (!tls)
			tls = shared_tls(new_tls());
		    if (!set_tls_ca(tls, av[i], 0))
			return perror_tls("ERROR: Unable to load CA chain from '%s': ", av[i]);
		    tls_info |= TLS_INFO_CA;
		} else return die("missing CA-path path in -C <CA-path>");
		break;
	    case 'S': if (++i < ac) {
		    char *c = strchr(av[i], ':');
		    sm_port = c ? (c + 1) : default_sm_port;
		    if (c) *c = 0;
		    sm_host = av[i];
		} else return die("missing host in -S <host>[:<port>]");
		break;
	    case 'c': if (++i < ac) {
		    tls_t *tls = shared_tls(0);
		    if (!tls)
			tls = shared_tls(new_tls());
		    if (!set_tls_cert(tls, av[i]))
			return perror_tls("ERROR: Unable to load SSL certificate from '%s': ", av[i]);
		    tls_info |= TLS_INFO_CERT;
		} else return die("missing cert-path path in -C <cert-path>");
		break;
            case 'h': printf("\n\
 Usage: %s [-h] [-p <http-port>] [-w <ws-port>] [-s <QAP-socket>] [-R <Rscript-socket>] [-r <doc-root>]\n\
        [-k <TLS-key-path> [-c <TLS-cert-path>] [-C <TLS-CA-path>]] [-u <ulog-socket>] [-S <host>[:<port>]]]\n\n", av[0]);
                return 0;
            default:
                fprintf(stderr, "\nUnrecognized flag -%c\n", av[i][1]);
                return 1;
            }

    if (tls_info & TLS_INFO_KEY) {
	if ((tls_info & (TLS_INFO_KEY | TLS_INFO_CERT)) != (TLS_INFO_KEY | TLS_INFO_CERT))
	    return die("-k <key> requires a corresponding certificate to be supplied with -c <cert>, but it is missing");
    } else if (tls_info)
	fprintf(stderr, "WARNING: -c or -C are supplied without -k, they are ignored since SSL is only enabled if -k is present.\n");

    doc_root_len = strlen(doc_root);
    ulog_set_path(ulog_path);
    ulog("----------------");
    R_script_socket(scr_path);
    add_content_handler(R_script_handler);
    if (http_port > 0) {
	server_t *srv = create_HTTP_server(http_port, HTTP_WS_UPGRADE | flags, http_request, ws_connected);
	if (srv) {
	    ulog("WS/QAP INFO: started HTTP server on port %d", http_port);
	    active_servers++;
	} else
	    ulog("WS/QAP ERROR: failed to start HTTP server on port %d", http_port);
    }
    if (ws_port > 0) {
	server_t *srv = create_WS_server(ws_port, WS_PROT_QAP | flags, ws_connected);
	if (srv) {
	    ulog("WS/QAP INFO: started WebSocket server on port %d", ws_port);
	    active_servers++;
	} else
	    ulog("WS/QAP ERROR: failed to start WebSocket server on port %d", ws_port);
    }
    if (!active_servers)
	return die("there are no active servers, aborting.");
    ulog("WS/QAP INFO: starting server loop (http=%d, ws=%d, qap='%s', rscript='%s', doc_root='%s'", http_port, ws_port, proxy->qap_socket_path, scr_path, doc_root);
    send_srvmgr("ADD");
    serverLoop();
    send_srvmgr("DEL");
    return 0;
}
