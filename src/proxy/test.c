#include "http.h"
#include "websockets.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void http_request(http_request_t *req, http_result_t *res) {
    FILE *f;
    char *s;
    struct stat st;
    fprintf(stderr, "INFO: request for '%s'\n", req->url);
    s = (char*) malloc(strlen(req->url) + 8);
    strcpy(s + 2, req->url);
    s[0] = '.';
    s[1] = '/';
    if (stat(s, &st) || !(f = fopen(s, "rb"))) {
	res->err = strdup("Path not found");
	res->code = 404;
	return;
    }
    res->payload = (char*) malloc((st.st_size < 512) ? 512 : st.st_size);
    res->payload_len = st.st_size;
    if (fread(res->payload, 1, res->payload_len, f) != res->payload_len) {
	snprintf(res->payload, 512, "I/O error: %s", strerror(errno));
	res->err = res->payload;
	res->payload = 0;
	res->payload_len = 0;
	res->code = 501;
	return;
    }
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
