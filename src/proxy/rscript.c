#include "chandler.h"
#include "ulog.h"
#include "qap.h"

/* FIXME: add support for big-endian machines */
#define itop(X) (X)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

static const char *scr_socket = "/data/rcloud/run/Rscripts";

static int recvn(int s, char *buf, int len) {
    int i = 0;
    while (len) {
        int n = recv(s, buf + i, len, 0);
        if (n == 0) return i;
        if (n < 0) return n; /* FIXME: handle EINTR ? */
        i += n;
        len -= n;
    }
    return i;
}

static char *strapp(char *x, char *y) {
    if (y) {
        size_t l = strlen(y);
        memcpy(x, y, l);
        x += l;
    }
    return x;
}

int R_script_handler(http_request_t *req, http_result_t *res, const char *path) {
    int l = strlen(path), s;

    /* we only serve .R scripts */
    if (l < 2 || strcmp(path + l - 2, ".R")) return 0;

    ulog("INFO: serving R script '%s'", path);
    
    s = socket(AF_LOCAL, SOCK_STREAM, 0);

    { /* connect to script services QAP socket */
        struct sockaddr_un sau;
        struct phdr hdr;
        char *oci;
        int n;
        memset(&sau, 0, sizeof(sau));
        sau.sun_family = AF_LOCAL;
        strcpy(sau.sun_path, scr_socket);
        if (s == -1 || connect(s, (struct sockaddr*)&sau, sizeof(sau))) {
            ulog("ERROR: failed to connect to script socket '%s': %s", scr_socket, strerror(errno));
            res->err = strdup("cannot connect to R services");
            res->code = 500;
            return 1;
        }
        if ((n = recvn(s, (char*) &hdr, sizeof(hdr))) != sizeof(hdr)) {
            ulog("ERROR: cannot read ID string/header (n = %d, errno: %s)", n, strerror(errno));
            res->err = strdup("cannot read ID string/header from R services");
            res->code = 500;
            close(s);
            return 1;
        }
        hdr.cmd = itop(hdr.cmd);
        hdr.len = itop(hdr.len);

        if (hdr.cmd != CMD_OCinit) {
            ulog("ERROR: server did not respond with RsOC message - wrong protocol?");
            res->err = strdup("R services are not running in OCAP mode");
            res->code = 500;
            close(s);
            return 1;
        }
        if (hdr.res || hdr.len > 0x7fffff || hdr.len < 32) {
            ulog("ERROR: initial message doesn't have expected length (got %d bytes)", hdr.len);
            res->err = strdup("R services responded with invalid large message");
            res->code = 500;
            close(s);
            return 1;
        }
        
        oci = (char*) malloc(hdr.len + 128);
        if (!oci) {
            ulog("ERROR: out of memory when allocating buffer for RsOC message");
            res->err = strdup("out of memory");
            res->code = 500;
            close(s);
            return 1;
        }
        if ((n = recvn(s, oci, hdr.len)) != hdr.len) {
            free(oci);
            ulog("ERROR: read error in RsOC payload (n = %d, errno: %s)", n, strerror(errno));
            res->err = strdup("cannot read ID string/header from R services");
            res->code = 500;
            close(s);
            return 1;
        }

        {
            char qq[4096], *q = qq;
            int i;
            for (i = 0; i < hdr.len; i++) q += snprintf(q, 8, " %02x", (int) ((unsigned char*)oci)[i]);
            ulog(qq);
        }

        /* parse RsOC */
        {
            unsigned int *hp = (unsigned int*) oci;
            if (PAR_TYPE(itop(*hp)) == DT_SEXP) {
                hp++;
                if (PAR_TYPE(itop(*hp)) == (XT_ARRAY_STR | XT_HAS_ATTR)) {
                    unsigned int ocl = PAR_LEN(itop(*hp));
                    /* check length sanity */
                    if (ocl <= hdr.len - 8) {
                        /* simple packing: url, query, headers, body
                           all but body may not contain \0 so they are
                           separated by \0, body is the remainder */
                        unsigned long l = 0, tpl;
                        char *outp, *oc;
                        qap_hdr_t *oh;
                        unsigned int *oi;

                        if (req->url) l += strlen(req->url);
                        if (req->query) l += strlen(req->query);
                        if (req->headers) l += strlen(req->headers);
                        if (req->body_len) l += req->body_len;
                        l += 3; /* 3 separating \0s */
                        
                        /* FIXME: support large packets */
                        if (l > 0xffff80) {
                            free(oci);  
                            ulog("ERROR: large packages are curretnly unsupported (needed to store %lu bytes)", l);
                            res->err = strdup("sorry, large packets are currently unsupported");
                            res->code = 500;
                            close(s);
                            return 1;
                        }

                        tpl = l + ocl + 36; /* DT_SEXP; XT_LANG_NOTAG; OCAP; XT_RAW; raw-len + 16-byte hdr */
                        tpl = (tpl + 3) & (~3);
                        ulog("l = %lu, tpl = %lu", l, tpl);
                        outp = (char*) malloc(tpl);
                        if (!outp) {
                            ulog("ERROR: out of memory when allocating output buffer (%lu bytes)", tpl);
                            res->err = strdup("out of memory");
                            res->code = 500;
                            close(s);
                            return 1;
                        }
                        oh = (qap_hdr_t*) outp;
                        oi = (unsigned int*) (outp + sizeof(qap_hdr_t));
                        oh->cmd = itop(CMD_OCcall);
                        oh->len = itop((unsigned int) (tpl - sizeof(qap_hdr_t)));
                        oh->res = 0;
                        oh->msg_id = hdr.msg_id;
                        tpl -= sizeof(qap_hdr_t) + 4; /* hdr - DT_SXP header */
                        *(oi++) = itop(SET_PAR(DT_SEXP, tpl));
                        tpl -= 4;
                        *(oi++) = itop(SET_PAR(XT_LANG_NOTAG, tpl));
                        tpl -= 4;
                        memcpy(oi, hp, ocl + 4);
                        tpl -= ocl + 4;
                        oi += (ocl + 4) / 4; /* Note: we don't check alignment */
                        *(oi++) = itop(SET_PAR(XT_RAW, (l + 7) & 0xfffffffc));
                        *(oi++) = itop(l);
                        oc = (char*) oi;
                        ulog("l will be stored at %ld", (long int) (oc - outp));
                        oc = strapp(oc, req->url);
                        *(oc++) = 0;
                        oc = strapp(oc, req->query);
                        *(oc++) = 0;
                        oc = strapp(oc, req->headers);
                        *(oc++) = 0;
                        if (req->body_len) memcpy(oc, req->body, req->body_len);
                        ulog("INFO: sending %d bytes (n = %d)", itop(oh->len) + sizeof(qap_hdr_t),
                             send(s, outp, itop(oh->len) + sizeof(qap_hdr_t), 0));

                        {
                            char qq[4096], *q = qq;
                            int i;
                            for (i = 0; i < ((tpl > 256) ? 256 : tpl); i++)
                                q += snprintf(q, 8, " %02x", (int) ((unsigned char*)outp)[i]);
                            ulog(qq);
                        }

                        free(outp);
                    }

                    close(s);
                }
            }
        }                
            
        close(s);
        free(oci);
    }

    res->err = strdup("not implemented yet");
    res->payload = 0;
    res->payload_len = 0;
    res->code = 500;

    return 1;
}
