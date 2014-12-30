#include "http.h"
#include "websockets.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* from date.c */
char  *posix2http(double);
double http2posix(const char*);

static char buf[1024];

static const char *get_header(http_request_t *req, const char *name) {
    const char *c = req->headers, *e;
    int name_len = strlen(name);
    if (!c) return 0;
    while (*c && (e = strchr(c, '\n'))) {
	const char *v = strchr(c, ':');
	if (v && (v < e) && (v - c == name_len)) {
	    int i;
	    for (i = 0; i < name_len; i++)
		if ((name[i] & 0xdf) != (c[i] & 0xdf))
		    break;
	    if (i == name_len) {
		v++;
		while (*v == '\t' || *v == ' ')
		    v++;
		return v;
	    }
	}
	while (*e == '\n' || *e == '\t') e++;
	c = e;
    }
    return 0;
}

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
	fprintf(stderr, "INFO: If-Mod? %s\n", if_mod ? if_mod : "<NO>");
	if (if_mod) {
	    double since = http2posix(if_mod);
	    fprintf(stderr, "INFO: last mod comparison: %d vs %d\n",
		    (int) since, (int) st.st_mtimespec.tv_sec);
	    if (since >= st.st_mtimespec.tv_sec) {
		not_modified = 1;
		res->code = 304;
	    }
	}
    }

    if (!not_modified) {
	const char *accept = get_header(req, "Accept-Encoding");
	if (accept) { /* check whether the client is ok with gzip compressed version */
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
	    res->code = 501;
	    fclose(f);
	    return;
	}
    }

    fclose(f);
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

static void ws_connected(args_t *arg, char *protocol) {
    server_t *srv = arg->srv;
    const char *test = "hello, world!";
    fprintf(stderr, "INFO: web sockets connected (protocol %s)\n", protocol ? protocol : "<NULL>");
    
    srv->send(arg, test, strlen(test));
}

int main() {
    create_HTTP_server(8088, HTTP_WS_UPGRADE, http_request, ws_connected);
    create_WS_server(8089, WS_PROT_QAP, ws_connected);
    serverLoop();
    return 0;
}
