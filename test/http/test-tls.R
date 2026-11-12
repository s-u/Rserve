## HTTPS next to HTTP. The client is the openssl command line tool (OPENSSL, see run.R).
## Fixture: fixtures/tls.R, srv$port is HTTP, srv$port + 1 is HTTPS.
## CLIENT: FALSE - the server certificate chain is completed from tls.ca
##         TRUE  - tls.client=match:xalice,alice,bob.example.org.x,bob.example.org
##                 (the CNs also occur as substrings of other entries), the server
##                 certificate is a chain file

HTTPS <- srv$port + 1L
no.client <- if (!CLIENT) "the server does not ask for client certificates"
## all tests that don't test client certificates use alice's (it is ignored if not asked for)
CERT  <- if (CLIENT) "alice.pem"

## sends req (string or raw) to port with openssl s_client (verifying the
## server against the test root CA), returns list(status, out (raw), err)
tls <- function(port, req, cert=CERT, timeout=30) {
    f <- c(tempfile("in"), tempfile("out"), tempfile("err")); on.exit(unlink(f))
    writeBin(if (is.character(req)) charToRaw(req) else req, f[1])
    args <- c("s_client", "-quiet", "-connect", paste0(HOST, ":", port), "-servername", "localhost",
              "-CAfile", shQuote(file.path(CERTS, "ca.pem")), "-verify_return_error",
              if (!is.null(cert)) c("-cert", shQuote(file.path(CERTS, cert)), "-key", shQuote(file.path(CERTS, cert))))
    status <- suppressWarnings(system2(OPENSSL, args, stdin=f[1], stdout=f[2], stderr=f[3], timeout=timeout))
    list(status=status, out=if (file.exists(f[2])) readBin(f[2], "raw", file.size(f[2])) else raw(),
         err=paste(if (file.exists(f[3])) readLines(f[3], warn=FALSE), collapse="\n"))
}
## all responses in the output of tls()
responses <- function(x) {
    con <- rawConnection(x$out); on.exit(close(con))
    r <- list()
    while (!is.na((p <- read.resp(con))$status)) r[[length(r) + 1L]] <- p
    r
}
req.str <- function(path, method="GET", close=TRUE, body=NULL, hdr=NULL)
    c(charToRaw(paste0(method, " ", path, " HTTP/1.1\r\nHost: localhost\r\n", if (length(hdr)) paste0(hdr, "\r\n", collapse=""),
                       if (!is.null(body)) paste0("Content-Length: ", length(body), "\r\n"),
                       if (close) "Connection: close\r\n", "\r\n")), body)
## a single request, returns the response (status NA if there was none)
tget <- function(port, path, cert=CERT, ...) {
    x <- tls(port, req.str(path, ...), cert)
    r <- responses(x)
    if (length(r)) r[[1L]] else list(status=NA, text="", err=x$err)
}
rejected <- function(port, cert=NULL) {
    r <- tget(port, "/echo", cert)
    expect(is.na(r$status), paste("got a response:", format(r)))
}

test("HTTP next to HTTPS", { r <- get("/static/hello.txt"); expect(st(r) == "200 hello world\n", st(r)) })
test("HTTPS: static file, the server chain verifies", {
    r <- tget(HTTPS, "/static/hello.txt"); expect(st(r) == "200 hello world\n", c(st(r), r$err)) })
test("HTTPS: R handler", { r <- tget(HTTPS, "/echo"); expect(st(r) == "200 method=GET;body=0;sum=0", c(st(r), r$err)) })
test("HTTPS: range", {
    r <- tget(HTTPS, "/static/digits.txt", hdr="Range: bytes=3-4"); expect(st(r) == "206 34", c(st(r), r$err)) })
test("HTTPS: 1MB request body", {
    b <- as.raw(rep(0:255, length.out=1e6))
    r <- tget(HTTPS, "/echo", method="POST", body=b)
    expect(st(r) == paste0("200 method=POST;body=1000000;sum=", sum(as.integer(b))), c(st(r), r$err)) })
test("HTTPS: 5MB response", {
    r <- tget(HTTPS, "/big")
    expect(isTRUE(r$status == 200) && length(r$body) == 5e6 && identical(r$body[1:3], as.raw(1:3)), length(r$body)) })
test("HTTPS: static 32MB file", {
    r <- tget(HTTPS, "/static/big.bin"); expect(isTRUE(r$status == 200) && length(r$body) == 32e6, length(r$body)) })
## the requests arrive at once, so most of them are only in the TLS buffers
## (not the socket) once the first one has been read
test("HTTPS: 20 pipelined requests on one connection", {
    paths <- rep(c("/static/hello.txt", "/echo"), 10)
    x <- tls(HTTPS, do.call(c, lapply(seq_along(paths), function(i) req.str(paths[i], close=(i == 20)))))
    r <- responses(x)
    expect(length(r) == 20 && all(vapply(r, function(o) isTRUE(o$status == 200), TRUE)), paste(length(r), "responses", x$err))
    expect(identical(vapply(r, `[[`, "", "text"), rep(c("hello world\n", "method=GET;body=0;sum=0"), 10))) })
test("HTTPS: requests pipelined after large bodies", {
    sizes <- c(20000L, 40000L, 100000L)
    x <- tls(HTTPS, c(do.call(c, lapply(sizes, function(n) req.str("/echo", "POST", FALSE, as.raw(rep(1:7, length.out=n))))),
                      req.str("/static/hello.txt")))
    r <- responses(x)
    expect(length(r) == 4, paste(length(r), "responses", x$err))
    expect(identical(vapply(r, `[[`, "", "text"),
                     c(sprintf("method=POST;body=%d;sum=%d", sizes, vapply(sizes, function(n) sum(rep(1:7, length.out=n)), 1)), "hello world\n")),
           vapply(r, `[[`, "", "text")) })
test("HTTPS: plain HTTP request is not answered as HTTP", {
    con <- socketConnection(HOST, HTTPS, open="r+b", blocking=TRUE, timeout=5); on.exit(close(con))
    send(con, "GET /static/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    r <- read.resp(con); expect(!isTRUE(r$status == 200), r) })
test("HTTPS: server survives a client that closes during the handshake", {
    for (i in 1:5) { con <- socketConnection(HOST, HTTPS, open="r+b", blocking=TRUE, timeout=5); send(con, as.raw(c(22, 3, 1))); close(con) }
    settle(); r <- tget(HTTPS, "/static/hello.txt"); expect(isTRUE(r$status == 200), r$err) })

## ---- client certificates (CLIENT) ----------------------------------------------
test("client: no certificate is rejected", rejected(HTTPS), skip=no.client)
test("client: matching CN is accepted", {
    for (cert in c("alice.pem", "bob.pem")) { r <- tget(HTTPS, "/echo", cert); expect(isTRUE(r$status == 200), list(cert, r$err)) } }, skip=no.client)
test("client: CN not in the list is rejected", rejected(HTTPS, "carol.pem"), skip=no.client)
test("client: certificate from another CA is rejected", rejected(HTTPS, "rogue.pem"), skip=no.client)
test("client: plain HTTP is not affected", { r <- get("/static/hello.txt"); expect(st(r) == "200 hello world\n", st(r)) }, skip=no.client)
test("lifecycle: server still running", expect(server.alive(), server.log(20)))
