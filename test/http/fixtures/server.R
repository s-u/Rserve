## Fixture for test-http.R and test-conc.R: Rserve with only the HTTP server.
## Usage: Rscript server.R --port=<port> --docroot=<dir> [--lib=<lib>] [--rawbody=1]
##
## Static handlers (Rserve.http.add.static):
##   /static/  docroot, index.html, last=TRUE (404 if the file does not exist)
##   /pub/     docroot, no index, last=FALSE (falls through to .http.request)
## everything else goes to .http.request() below
args <- commandArgs(TRUE)
arg <- function(name, default=NULL) {
    a <- grep(paste0("^--", name, "="), args, value=TRUE)
    if (length(a)) sub("^--[^=]*=", "", a[1]) else default
}
if (!is.null(arg("lib"))) .libPaths(c(arg("lib"), .libPaths()))
cat("PID", Sys.getpid(), "\n"); flush(stdout()) # the driver needs the pid of the R process
port    <- as.integer(arg("port"))
docroot <- arg("docroot")
rawbody <- isTRUE(arg("rawbody") == "1")

library(Rserve)

## the request headers come as a raw vector of "Name: value\n" lines
parse.headers <- function(h) {
    if (!length(h)) return(character())
    l <- strsplit(rawToChar(h), "\n", fixed=TRUE)[[1]]
    l <- l[grepl(":", l, fixed=TRUE)]
    setNames(trimws(sub("^[^:]*:", "", l)), tolower(sub(":.*", "", l)))
}
txt <- function(x, code=200L, ct="text/plain", hdr=character()) list(x, ct, hdr, code)

.http.request <- function(url, query, body, headers) {
    h <- parse.headers(headers)
    method <- if ("request-method" %in% names(h)) h[["request-method"]] else "?"
    if (url == "/echo") {
        q <- if (is.null(query)) "" else paste(names(query), query, sep="=", collapse="&")
        ct <- attr(body, "content-type")
        bt <- if (is.raw(body)) (if (length(body)) rawToChar(body[body != 0]) else "")
              else if (is.character(body)) paste(names(body), body, sep="=", collapse="&") else ""
        return(txt(paste0("method=", method, ";query=", q, ";body=", length(body), ";class=", class(body)[1],
                          ";ct=", if (is.null(ct)) "" else ct, ";bodytxt=", bt)))
    }
    if (url == "/hdr")   # reflect request headers (as received, one per line)
        return(txt(if (length(headers)) rawToChar(headers) else ""))
    if (url == "/custom-headers")
        return(txt("ok", hdr=c("X-Test: 1", "X-Other: two")))
    if (grepl("^/code/", url))
        return(txt("code", as.integer(sub("^/code/", "", url))))
    if (url == "/rawcode") # raw payload with the status given by ?c=
        return(list(charToRaw("rawbody"), "text/plain", character(), as.integer(query[["c"]])))
    if (url == "/raw")
        return(list(as.raw(0:255), "application/octet-stream"))
    if (url == "/empty")
        return(list(raw(0), "text/plain"))
    if (url == "/emptystr")
        return(txt(""))
    if (url == "/big")
        return(list(as.raw(rep(1:250, length.out=5e6)), "application/octet-stream"))
    if (url == "/file")
        return(list(file=file.path(docroot, "hello.txt"), "text/plain"))
    if (url == "/tmpfile") {
        f <- tempfile(tmpdir=docroot); writeBin(charToRaw("temporary\n"), f) # no CRLF on Windows
        return(list(tmpfile=f, "text/plain", paste0("X-Tmpfile: ", f), if ("c" %in% names(query)) as.integer(query[["c"]]) else 200L))
    }
    if (url == "/docfile") # a file from the document root, served by R
        return(list(file=file.path(docroot, basename(query[["f"]])), "application/octet-stream"))
    if (url == "/missing-file")
        return(list(file="/nonexistent/file.txt", "text/plain"))
    if (url == "/pid") return(txt(as.character(Sys.getpid())))
    ## leaves a trace in the file system, so the tests can tell whether the
    ## handler was called (works with forked children)
    if (url == "/touch") {
        file.create(file.path(docroot, basename(query[["f"]])))
        return(txt(paste0("touched;body=", length(body))))
    }
    if (url == "/a+b") return(txt("plus"))
    if (url == "/a b") return(txt("space"))
    if (url == "/error")  stop("boom")
    if (url == "/notlist") return(42L)
    if (url == "/emptylist") return(list())
    if (url == "/utf8")
        return(txt("héllo", ct="text/plain; charset=utf-8"))
    if (url == "/latin1")
        return(txt(iconv("héllo", "UTF-8", "latin1"), ct="text/plain; charset=utf-8"))
    if (url == "/sleep") { if ("m" %in% names(query)) file.create(file.path(docroot, basename(query[["m"]])))
        Sys.sleep(1); return(txt("slept")) }
    if (url == "/conn-close") return(txt("bye", hdr="Connection: close"))
    if (url == "/settle") return(txt("ok"))
    txt(paste("not found:", url), 404L)
}

Rserve.http.add.static("/static/", docroot, "index.html", last=TRUE)
Rserve.http.add.static("/pub/", docroot)
cat("READY\n", file=stderr()); flush(stderr())
cfg <- list(http.port=port, qap=FALSE, websockets=FALSE, config.file=tempfile())
if (rawbody) cfg$http.raw.body <- "enable"
do.call(run.Rserve, cfg)
