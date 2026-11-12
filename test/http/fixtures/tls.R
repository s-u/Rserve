## Fixture for test-tls.R: HTTP on port and HTTPS on port + 1.
## Usage: Rscript tls.R --port=<port> --docroot=<dir> --certs=<dir> [--client=<spec>] [--lib=<lib>]
##   client: value of tls.client (e.g. require or match:alice), if given the
##           client CA is used as tls.ca (Rserve has only one TLS context, so
##           the server certificate is the full chain in that case)
args <- commandArgs(TRUE)
arg <- function(name, default=NULL) {
    a <- grep(paste0("^--", name, "="), args, value=TRUE)
    if (length(a)) sub("^--[^=]*=", "", a[1]) else default
}
if (!is.null(arg("lib"))) .libPaths(c(arg("lib"), .libPaths()))
cat("PID", Sys.getpid(), "\n"); flush(stdout()) # the driver needs the pid of the R process
port    <- as.integer(arg("port"))
docroot <- arg("docroot")
certs   <- arg("certs")
client  <- arg("client")

library(Rserve)

parse.headers <- function(h) {
    if (!length(h)) return(character())
    l <- strsplit(rawToChar(h), "\n", fixed=TRUE)[[1]]
    l <- l[grepl(":", l, fixed=TRUE)]
    setNames(trimws(sub("^[^:]*:", "", l)), tolower(sub(":.*", "", l)))
}
.http.request <- function(url, query, body, headers) {
    h <- parse.headers(headers)
    if (url == "/echo")
        return(list(paste0("method=", h[["request-method"]], ";body=", length(body), ";sum=", sum(as.integer(body))),
                    "text/plain"))
    if (url == "/big")
        return(list(as.raw(rep(1:250, length.out=5e6)), "application/octet-stream"))
    list("not found", "text/plain", character(), 404L)
}
Rserve.http.add.static("/static/", docroot, "index.html", last=TRUE)
cf <- function(f) file.path(certs, f)
cfg <- list(http.port=port, https.port=port + 1L, qap=FALSE, websockets=FALSE, config.file=tempfile())
if (is.null(client)) {
    cfg <- c(cfg, tls.cert=cf("server.pem"), tls.key=cf("server.key"), tls.ca=cf("inter.pem"))
} else
    cfg <- c(cfg, tls.cert=cf("server-chain.pem"), tls.key=cf("server.key"), tls.ca=cf("client-ca.pem"),
             tls.client=client)
do.call(run.Rserve, cfg)
