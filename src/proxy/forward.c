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
#include "rserr.h"
#include "ulog.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/un.h> /* needed for unix sockets */

#define MAX_READ_CHUNK (1024 * 1024)
#define MAX_SEND_CHUNK (1024 * 1024)

/* FIXME: only for little endian machines */
#define ptoi(X) (X)
#define itop(X) (X)

static char buf[1024];

static void http_request(http_request_t *req, http_result_t *res) {
    FILE *f;
    char *s;
    struct stat st;
    double ts;
    int not_modified = 0;
    const char *append_headers = 0;

    fprintf(stderr, "----\nINFO: request for '%s', Date: %s, headers:\n%s\n", req->url, posix2http(req->date), req->headers ? req->headers : "<NONE>");
    s = (char*) malloc(strlen(req->url) + 8);
    strcpy(s + 2, req->url);
    s[0] = '.';
    s[1] = '/';
    if (stat(s, &st) || !(f = fopen(s, "rb"))) {
	res->err = strdup("Path not found");
	res->code = 404;
	return;
    }

    /* check for conditional GET */
    if (req->headers) {
	const char *if_mod = get_header(req, "If-Modified-Since");
	if (if_mod) {
	    double since = http2posix(if_mod);
	    if (since >= st.st_mtimespec.tv_sec) {
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
		if (!stat(s, &gzst) && gzst.st_mtimespec.tv_sec >= st.st_mtimespec.tv_sec && (gzf = fopen(s, "rb"))) {
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
	    return;
	}
    }

    fclose(f);
    /* append Last-Modified: based on the served file and set no-cache */
    ts = (double) time(0);
    snprintf(buf, sizeof(buf), "Last-Modified: %s\r\nCache-control: no-cache\r\n%s",
	     posix2http((st.st_mtimespec.tv_sec > ts) ? ts : st.st_mtimespec.tv_sec),
	     append_headers ? append_headers : ""
	     );
    res->headers = strdup(buf);
}

struct args {
    server_t *srv; /* server that instantiated this connection */
};

typedef struct queue {
    unsigned long len;
    struct queue *next;
    char data[1];
} queue_t;

typedef struct {
    const char *qap_socket_path;
    
    args_t *ws;  /* WebSocket args structure */
    int qap;     /* QAP socket */
    pthread_mutex_t mux;
    pthread_cond_t  queue_available;
    int qap_stage, active, qap_alive, ws_alive;
    queue_t *qap_to_ws;
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

    ulog("QAP->WS INFO: started forwarding thread");
    while (proxy->active && proxy->qap_alive) {
	n = read(s, &hdr, sizeof(hdr));
	ulog("QAP->WS INFO: read n = %d", n);
	if (n < 0) { /* error */
	    if (errno == EINTR)
		continue; /* don't worry about EINTR */
	    ulog("QAP->WS ERROR: read header: %s", strerror(errno));
	    break;
	}
	if (n != sizeof(hdr)) { /* not even complete header */
	    ulog("QAP->WS ERROR: read header: %d read, %d expected", n, (int) sizeof(hdr));
	    break;
	}
	/* there is one special case - if this is non-OCAP mode and qap_stage is zero
	   then the first packet will be IDstring and not a QAP message */
	if (proxy->qap_stage == 0) { /* the first 4 bytes from the server must be one of:
					Rsrv - Rserve ID string (32 bytes)
					RSpx - Rserve proxy
					RsOC - OCAP mode
				     */
	    if (!memcmp((char*)&hdr, "Rsrv", 4)) { /* QAP1 = ID string */
		memcpy(idstr, &hdr, sizeof(hdr));
		n = read(s, idstr + sizeof(hdr), 32 - sizeof(hdr));
		ulog("QAP->WS INFO: read[IDstring] n = %d", n);
		if (n < 32 - sizeof(hdr)) {
		    ulog("QAP->WS ERROR: read QAP1 ID string: %d read, %d expected", n, 32 - sizeof(hdr));
		    break;
		}
		if (memcmp(idstr + 8, "QAP1", 4)) {
		    ulog("QAP->WS ERROR: Rserve protocol used is not QAP1");
		    break;
		}
		pthread_mutex_lock(&proxy->mux);
		ulog("QAP->WS INFO: forwarding IDstring (%d bytes)", 32);
		n = proxy->ws->srv->send(proxy->ws, idstr, 32);
		pthread_mutex_unlock(&proxy->mux);
		if (n < 32) { /* ID string forward failed */
		    ulog("QAP->WS ERROR: send QAP1 ID string failed: %d read, %d expected [%s]", n, 32, strerror(errno));
		    break;
		}
		/* done - back to normal mode */
		proxy->qap_stage = 1;
		WS_set_binary(proxy->ws, 1); /* QAP is binary */
		continue;
	    }

	    if (!memcmp((char*)&hdr, "RSpx", 4)) { /* RSpx = Rserve proxy */
		ulog("QAP->WS ERROR: RSpx proxy protocol is currently unsupported");
		/* currently unsupported */
		break;
	    }

	    if (!memcmp((char*)&hdr, "RsOC", 4)) { /* RsOC = OCAP mode - strictly QAP from the start */
		proxy->qap_stage = 1;
		WS_set_binary(proxy->ws, 1); /* QAP is binary */
	    } else { /* everything else = bad packet */
		ulog("QAP->WS ERROR: server doesn't use any of QAP1, RSpx, RsOC - aborting");
		break;
	    }
	}

	/* from here on it's guaranteed QAP */
	{
	    unsigned long tl, pos = 0;
	    //#if LONG_MAX > 2147483647
	    tl = ptoi(hdr.res);
	    tl <<= 32;
	    tl |= ptoi(hdr.len);
	    //#else
	    //tl = ptoi(hdr.len);
	    //#endif
	    ulog("QAP->WS INFO: <<== message === (cmd=0x%x, msg_id=0x%x), size = %lu", hdr.cmd, hdr.msg_id, tl);
	    if (!(qe = malloc(tl + sizeof(hdr) + sizeof(queue_t)))) { /* failed to allocate buffer for the message */
		/* FIXME: we should flush the contents and respond with an error condition */
		ulog("QAP->WS ERROR: unable to allocate memory for message of size %lu", tl);
		break;
	    }

	    qe->next = 0;
	    qe->len = tl + sizeof(hdr);
	    memcpy(qe->data, &hdr, sizeof(hdr));

	    while (pos < tl) {
	        n = read(s, qe->data + sizeof(hdr) + pos, (tl - pos > MAX_READ_CHUNK) ? MAX_READ_CHUNK : (tl - pos));
		ulog("QAP->WS INFO: read n=%d (%lu of %lu)", n, pos, tl);		     
		if (n < 1) break;
		pos += n;
	    }

	    if (pos < tl) {
	        ulog("QAP->WS ERROR: could read only %lu bytes of %lu bytes message [%s]", pos, tl, strerror(errno));
		break; /* bail out on read error/EOF */
	    }

	    ulog("QAP->WS INFO: sending total of %lu bytes", qe->len);
	    /* message complete - send */
	    pthread_mutex_lock(&proxy->mux);
	    n = proxy->ws->srv->send(proxy->ws, qe->data, qe->len);
	    ulog("QAP->WS INFO: send returned %d", n);
	    pthread_mutex_unlock(&proxy->mux);
	    if (n < qe->len) {
	        ulog("QAP->WS ERROR: was able to send only %ld bytes of %lu bytes message [%s]", (long) n, tl, strerror(errno));
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
    ulog("QAP->WS INFO: finished forwarding thread, QAP closed");
    return 0;
}

/* WS->queue */
static void *enqueue(void *ptr) {
    proxy_t *proxy = (proxy_t*) ptr;
    qap_hdr_t hdr;

    ulog("WS->Q INFO: started enqueuing thread");
    while (proxy->active && proxy->ws_alive) {
	int n = proxy->ws->srv->recv(proxy->ws, &hdr, sizeof(hdr));
	unsigned long tl, pos = 0;
	queue_t *qe;

	ulog("WS->Q INFO: WS recv = %d", n);
	if (n < sizeof(hdr)) {
	    ulog("WS->Q ERROR: header read expected %d, got %d [%s]", sizeof(hdr), n, strerror(errno));
	    break;
	}

	//#if LONG_MAX > 2147483647
	tl = ptoi(hdr.res);
	tl <<= 32;
	tl |= ptoi(hdr.len);
	//#else
	//tl = ptoi(hdr.len);
	//#endif
	ulog("WS->Q INFO: === message ==>> (cmd=0x%x, msg_id=0x%x), size = %lu", hdr.cmd, hdr.msg_id, tl);

	if (!(qe = malloc(tl + sizeof(hdr) + sizeof(queue_t)))) { /* failed to allocate buffer for the message */
	    /* FIXME: we should flush the contents and respond with an error condition */
	    ulog("WS->Q ERROR: unable to allocate memory for message of size %lu", tl);
	    break;
	}

	qe->next = 0;
	qe->len = tl + sizeof(hdr);
	memcpy(qe->data, &hdr, sizeof(hdr));
	while (pos < tl) {
	    ulog("WS->Q INFO: requesting %lu (so far %lu of %lu)", tl - pos, pos, tl);
	    n = proxy->ws->srv->recv(proxy->ws, qe->data + sizeof(hdr) + pos, tl - pos);
	    if (n < 1) {
		ulog("WS->Q ERROR: read %lu of %lu then got %d [%s]", pos, tl, n, strerror(errno));
		break;
	    }
	    pos += n;
	}
	if (pos < tl) break;

	ulog("WS->Q INFO: enqueuing message");
	/* got the message - enqueue */
	pthread_mutex_lock(&proxy->mux);
	if (proxy->ws_to_qap) {
	    queue_t *q = proxy->ws_to_qap;
	    while (q->next)
		q = q->next;
	    q->next = qe;
	} else
	    proxy->ws_to_qap = qe;
	pthread_cond_signal(&proxy->queue_available);
	pthread_mutex_unlock(&proxy->mux);
	ulog("WS->Q INFO: done enqueuing");
    }

    proxy->ws_alive = 0;
    /* signal queue so the main thread can check our status and find out that we're done */
    pthread_mutex_lock(&proxy->mux);
    pthread_cond_signal(&proxy->queue_available);
    pthread_mutex_unlock(&proxy->mux);

    ulog("WS->Q INFO: finished enqueuing thread");

    /* WS will be closed by exitting from the main thread */
    return 0;
}
	    
static void ws_connected(args_t *arg, char *protocol) {
    int s;
    struct sockaddr_un sau;
    pthread_t forward_thread, enqueue_thread;
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
    proxy->qap_to_ws = 0;
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

    /* Note about the mutex:
       the mutex is locked for
       a) all operations on the queue
       b) for all WS send operations
       so the one operation that doesn't lock is
       the blocking WS read. Hence no other thread
       than "equeue" is allowed to call WS read. */

    /* what's left is queue -> QAP */
    while (proxy->active) {
	queue_t *q;
	pthread_mutex_lock(&proxy->mux);
	//ulog("Q->QAP INFO: waiting for message in the queue");
	if (!proxy->ws_to_qap && proxy->qap_alive) /* if there is nothing to process, wait until enqueue posts something */
	    pthread_cond_wait(&proxy->queue_available, &proxy->mux);
	/* ok, we land here with the queue mutex still locked 
	   so we pull the message from the head of the queue and release the rest of the queue
	 */
	q = proxy->ws_to_qap;
	//ulog("Q->QAP INFO: queue signalled - %s", q ? "message present" : "queue empty");
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
		proxy->ws->srv->send(proxy->ws, &hdr, sizeof(hdr));
		pthread_mutex_unlock(&proxy->mux);
		/* don't close WS - we'll still respond to all
		   messages WS sends our way so it can unwind
		   all callbacks */
	    } else {
		unsigned long tl = q->len, pos = 0;
		while (pos < tl && proxy->qap != -1) {
		    int n = send(proxy->qap, q->data + pos, (tl - pos > MAX_SEND_CHUNK) ? MAX_SEND_CHUNK : (tl - pos), 0);
		    ulog("Q->QAP INFO: sent %d (at %lu of %lu)", n, pos, tl);
		    if (n < 1)
			break; /* send failed or broken pipe */
		    pos += n;
		}
		if (pos < tl) { /* QAP broken */
		    ulog("Q->QAP ERROR: send error, aborting QAP connection");
		    closesocket(proxy->qap);
		    proxy->qap = -1;
		    proxy->qap_alive = 0;
		    free(q);
		    break;
		}
		ulog("Q->QAP INFO: message delivered");
	    }
	    free(q);
	} else if (!proxy->ws_alive) { /* if the queue is empty and WS is dead,
					  it's time to leave */
	    ulog("INFO: WS closed and queue empty, clean shutdown");
	    proxy->active = 0;
	}
    }

    if (proxy->qap_alive) {
	/* QAP is still alive ... */
	/* FIXME: should we somehow inform the QAP thread?
	   Right now it will simply die with the process,
	   which is currently OK since it's blocking on read()
	   without any active allocations, but in case we care ... */
	proxy->qap_alive = 0;
	pthread_kill(forward_thread, SIGINT);
    }
    
    /* if WS is still alive, we inform it about our shutdown */
    if (proxy->ws_alive) {
	qap_hdr_t hdr = { 0, 0, 0, 0 };
	hdr.cmd = itop(OOB_SEND);
	pthread_mutex_lock(&proxy->mux);
	proxy->ws_alive = 0;
	proxy->ws->srv->send(proxy->ws, &hdr, sizeof(hdr));
	pthread_mutex_unlock(&proxy->mux);
    }
    ulog("INFO: WebSockets frowarding process done.");
 }

int main() {
    proxy = (proxy_t*) malloc(sizeof(proxy_t));
    memset(proxy, 0, sizeof(proxy_t));
    proxy->qap_socket_path = "Rserve_socket";

    ulog_set_path("ulog_socket");
    ulog("----------------");
    create_HTTP_server(8088, HTTP_WS_UPGRADE, http_request, ws_connected);
    create_WS_server(8089, WS_PROT_QAP, ws_connected);
    ulog("INFO: starting server loop");
    serverLoop();
    return 0;
}
