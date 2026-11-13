## Static files, R handler (.http.request) and HTTP protocol handling.
## Fixture: fixtures/server.R

## features Rserve does not implement (on purpose, see README.md)
NOTIMPL <- "not implemented in Rserve"

## ---- static ---------------------------------------------------------------
test("static: file", {
    r <- get("/static/hello.txt")
    expect(r$status == 200, r); expect(identical(r$text, "hello world\n"))
    expect(identical(r$headers[["content-type"]], "text/plain"))
    expect(identical(r$headers[["content-length"]], "12"))
    expect(!is.null(r$headers[["last-modified"]]), r)
    expect(identical(r$headers[["accept-ranges"]], "bytes"), r)
})
test("static: UTF-8 file name", { r <- get("/static/caf%C3%A9.txt", timeout=5); expect(r$status == 200 && identical(r$text, "utf8\n"), r) })
test("static: '+' in a file name is literal", { r <- get("/static/a+b.txt"); expect(r$status == 200 && identical(r$text, "plus\n"), r) })
test("static: control characters in the URL do not hang the server", { for (p in c("/static/hello%01.txt", "/static/%1f", "/static/caf%C3%A9-none")) expect(!is.na(get(p, timeout=5)$status), p) })
test("static: HEAD has no body", {
    r <- request("HEAD", "/static/hello.txt")
    expect(r$status == 200 && r$headers[["content-length"]] == "12" && !length(r$body), r)
})
test("static: HEAD keeps keep-alive framing", {
    con <- conn(); on.exit(close(con))
    send(con, "HEAD /static/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    r <- read.resp(con, head.only=TRUE); expect(r$status == 200, r)
    send(con, "GET /static/digits.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    r <- read.resp(con); expect(r$status == 200 && identical(r$text, "0123456789"), r) })
test("static: index at root", { r <- get("/static/"); expect(r$status == 200 && has(r$text, "root"), r) })
test("static: index in subdir with slash", { r <- get("/static/sub/"); expect(r$status == 200 && has(r$text, "sub"), r) })
test("static: subdir without slash redirects", {
    r <- get("/static/sub"); expect(r$status == 301, r)
    expect(identical(r$headers[["location"]], "/static/sub/"), r) })
test("static: redirect location is URL-encoded", {
    r <- get("/static/a%20b%25"); expect(r$status == 301, r)
    loc <- r$headers[["location"]]; expect(identical(loc, "/static/a%20b%25/"), loc)
    r <- get(loc); expect(r$status == 200 && has(r$text, "odd"), r) })
test("static: dir without index is not listed", expect.in(get("/static/emptydir/")$status, c(403, 404)))
test("static: missing -> 404 (last=TRUE)", expect(get("/static/nope.txt")$status == 404))
test("static: missing falls through to R (last=FALSE)", {
    r <- get("/pub/nope.txt"); expect(r$status == 404 && has(r$text, "not found: /pub/nope.txt"), r) })
test("static: file in a fall-through handler", { r <- get("/pub/hello.txt"); expect(st(r) == "200 hello world\n", st(r)) })
## > 2GB needs 64-bit file offsets (long is 32-bit on Windows), the file is sparse
test("static: file > 2GB", {
    f <- file.path(DOCROOT, "huge.bin"); on.exit(unlink(f))
    file.create(f)
    if (WIN) system2("fsutil", c("sparse", "setflag", shQuote(normalizePath(f))), stdout=FALSE, stderr=FALSE)
    con <- file(f, "r+b"); seek(con, 3e9, rw="write"); writeBin(charToRaw("0123456789"), con); close(con)
    expect(file.size(f) == 3000000010, file.size(f))
    r <- request("HEAD", "/static/huge.bin")
    expect(r$status == 200 && identical(r$headers[["content-length"]], "3000000010"), r)
    r <- get("/static/huge.bin", headers=list(Range="bytes=3000000005-"))
    expect(r$status == 206 && identical(r$text, "56789") &&
           identical(r$headers[["content-range"]], "bytes 3000000005-3000000009/3000000010"), r)
    r <- request("HEAD", "/docfile?f=huge.bin") # served by R (size from ftell)
    expect(r$status == 200 && identical(r$headers[["content-length"]], "3000000010"), r) })
test("static: overlong path -> 414", {
    r <- get(paste0("/static/", strrep("a", 600))); expect(r$status == 414, r) })

## ---- ranges and conditional GET ---------------------------------------------
rng <- function(range, ...) get("/static/digits.txt", headers=c(list(Range=range), list(...)))
test("range: closed", {
    r <- rng("bytes=2-5")
    expect(r$status == 206, r); expect(identical(r$text, "2345"))
    expect(identical(r$headers[["content-range"]], "bytes 2-5/10"))
    expect(identical(r$headers[["content-length"]], "4"))
})
test("range: open-ended", { r <- rng("bytes=7-"); expect(r$status == 206 && r$text == "789", r) })
test("range: suffix", { r <- rng("bytes=-3"); expect(r$status == 206 && r$text == "789" && r$headers[["content-range"]] == "bytes 7-9/10", r) })
test("range: suffix longer than the file", { r <- rng("bytes=-50"); expect(r$status == 206 && r$text == "0123456789", r) })
test("range: end past EOF is truncated", { r <- rng("bytes=8-100"); expect(r$status == 206 && r$text == "89" && r$headers[["content-range"]] == "bytes 8-9/10", r) })
test("range: single byte", { r <- rng("bytes=0-0"); expect(r$status == 206 && r$text == "0", r) })
test("range: start past EOF -> 416", {
    r <- rng("bytes=50-60"); expect(r$status == 416, r)
    expect(identical(r$headers[["content-range"]], "bytes */10"), r) })
test("range: zero-length suffix -> 416", expect(rng("bytes=-0")$status == 416))
test("range: multiple ranges are ignored", { r <- rng("bytes=0-1,5-6"); expect(r$status == 200 && r$text == "0123456789", r) })
test("range: invalid ranges are ignored", for (h in c("bytes=5-3", "bytes=x-", "items=1-2", "bytes=-", "bytes 1-2")) {
    r <- rng(h); expect(r$status == 200 && r$text == "0123456789", list(h, r)) })
test("range: huge numbers are ignored", { r <- rng("bytes=99999999999999999999999-"); expect.in(r$status, c(200, 416)) })
test("range: HEAD ignores Range", {
    r <- request("HEAD", "/static/digits.txt", headers=list(Range="bytes=2-5"))
    expect(r$status == 200 && r$headers[["content-length"]] == "10", r) })
test("range: If-Range with the current date", {
    lm <- get("/static/digits.txt")$headers[["last-modified"]]
    r <- rng("bytes=2-5", "If-Range"=lm); expect(r$status == 206 && r$text == "2345", r) })
test("range: If-Range with another date or an ETag", for (v in c("Thu, 01 Jan 1970 00:00:01 GMT", '"abc"')) {
    r <- rng("bytes=2-5", "If-Range"=v); expect(r$status == 200 && r$text == "0123456789", list(v, r)) })
test("range: in a big file", {
    r <- get("/static/big.bin", headers=list(Range="bytes=20000000-20000009"))
    expect(r$status == 206 && length(r$body) == 10 && all(r$body == 0), r) })
test("range: keep-alive after 206 and 416", {
    con <- conn(); on.exit(close(con))
    for (h in c("bytes=2-5", "bytes=50-", "bytes=1-1")) {
        send(con, paste0("GET /static/digits.txt HTTP/1.1\r\nHost: x\r\nRange: ", h, "\r\n\r\n"))
        r <- read.resp(con); expect.in(r$status, c(206, 416), list(h, r)) }
    send(con, "GET /static/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n"); expect(read.resp(con)$text == "hello world\n") })
test("conditional GET -> 304", {
    lm <- get("/static/hello.txt")$headers[["last-modified"]]
    r <- get("/static/hello.txt", headers=list("If-Modified-Since"=lm))
    expect(r$status == 304, r); expect(!length(r$body)); expect(is.null(r$headers[["content-length"]]))
})
test("conditional GET, old date -> 200",
    expect(get("/static/hello.txt", headers=list("If-Modified-Since"="Thu, 01 Jan 1970 00:00:01 GMT"))$status == 200))
test("conditional GET, garbage date -> 200",
    expect(get("/static/hello.txt", headers=list("If-Modified-Since"="yesterday"))$status == 200))
test("conditional GET, 304 wins over Range", {
    lm <- get("/static/digits.txt")$headers[["last-modified"]]
    expect(rng("bytes=2-5", "If-Modified-Since"=lm)$status == 304) })
test("conditional GET, 304 keeps keep-alive framing", {
    lm <- get("/static/hello.txt")$headers[["last-modified"]]
    con <- conn(); on.exit(close(con))
    for (i in 1:2) {
        send(con, paste0("GET /static/hello.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: ", lm, "\r\n\r\n"))
        expect(read.resp(con)$status == 304)
    }
})

## ---- traversal ------------------------------------------------------------
not.served <- function(p) { r <- get(p); expect(r$status != 200, paste("served:", p)) }
test("traversal: ..", not.served("/static/../secret-outside.txt"))
test("traversal: encoded ..", { not.served("/static/%2e%2e/secret-outside.txt"); not.served("/static/%2E%2E%2Fsecret-outside.txt") })
test("traversal: deep ..", not.served("/static/sub/../../secret-outside.txt"))
test("traversal: backslash (Windows separator)", { not.served("/static/..\\secret-outside.txt"); not.served("/static/%2e%2e%5csecret-outside.txt"); not.served("/static/sub\\..\\..\\secret-outside.txt") })
test("traversal: drive letters and NTFS streams", { not.served("/static/C:%5cWindows%5cwin.ini"); not.served("/static/C:/Windows/win.ini")
    r <- get("/static/hello.txt::$DATA"); expect(r$status != 200 || identical(r$text, "hello world\n"), r) })
test("traversal: NUL byte", expect.in(get("/static/hello.txt%00.png")$status, c(400, 404)))
test("traversal: double slash absolute", not.served("/static//etc/passwd"))
test("traversal: fall-through handler", not.served("/pub/../secret-outside.txt"))

## ---- R handler ------------------------------------------------------------
test("rfun: GET with query", {
    r <- get("/echo?a=1&b=hello%20world&c=x%2By")
    expect(r$status == 200, r); expect(has(r$text, "method=GET")); expect(has(r$text, "a=1"))
    expect(has(r$text, "b=hello world")); expect(has(r$text, "c=x+y"), r$text)
})
test("rfun: POST body", {
    r <- request("POST", "/echo", list("Content-Type"="text/plain"), "payload")
    expect(r$status == 200, r); expect(has(r$text, "method=POST") && has(r$text, "body=7"))
    expect(has(r$text, "bodytxt=payload") && has(r$text, "ct=text/plain"), r$text)
})
test("rfun: Content-Type parameters keep their case", {
    r <- request("POST", "/echo", list("Content-Type"="Multipart/Form-Data; boundary=AbC"), "x")
    expect(has(r$text, "ct=multipart/form-data; boundary=AbC"), r$text) })
test("rfun: POST 1MB body", {
    r <- request("POST", "/echo", list("Content-Type"="application/octet-stream"), as.raw(rep(65:74, 1e5)))
    expect(r$status == 200 && has(r$text, "body=1000000"), r)
})
test("rfun: empty POST with Content-Type does not crash", {
    r <- request("POST", "/echo", list("Content-Type"="text/plain", "Content-Length"="0"))
    expect(r$status == 200, r); healthy()
})
test("rfun: POST without Content-Length has no body", {
    r <- rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); expect(r$status == 200 && has(r$text, "body=0"), r) })
test("rfun: GET with Content-Type does not crash", { r <- get("/echo", headers=list("Content-Type"="text/plain")); expect(r$status == 200, r); healthy() })
test("rfun: form-urlencoded body is parsed", {
    r <- request("POST", "/echo", list("Content-Type"="application/x-www-form-urlencoded"), "a=1&b=x+y%21")
    expect(r$status == 200 && has(r$text, "class=character") && has(r$text, "bodytxt=a=1&b=x y!"), r) })
test("rfun: other methods", for (m in c("PUT", "DELETE", "PATCH", "OPTIONS")) {
    r <- request(m, "/echo", body=if (m != "OPTIONS") ""); expect(r$status == 200 && has(r$text, paste0("method=", m)), list(m, r)) })
test("rfun: request headers visible", {
    r <- get("/hdr", headers=list("X-Foo"="bar", "User-Agent"="tester")); low <- tolower(r$text)
    expect(has(low, "x-foo: bar") && has(low, "user-agent: tester"), r$text) })
test("rfun: Request-Method is set by the server", {
    r <- get("/hdr"); expect(grepl("^Request-Method: GET\n", r$text), r$text) })
test("rfun: headers > 1KB are all delivered", {
    h <- setNames(as.list(rep(strrep("v", 100), 40)), paste0("X-H", 0:39))
    r <- get("/hdr", headers=h); expect(r$status == 200, r)
    for (i in 0:39) expect(has(r$text, paste0("X-H", i, ": ", strrep("v", 100), "\n")), i) })
test("rfun: a 20KB header is delivered intact", {
    v <- paste(rep(c("abc", "defg"), length.out=5000), collapse="")
    r <- get("/hdr", headers=list("X-A"="1", Cookie=v, "X-B"="2")); expect(r$status == 200, r)
    expect(has(r$text, paste0("Cookie: ", v, "\nX-B: 2\n")), substr(r$text, 1, 100)) })
test("rfun: custom response headers", {
    r <- get("/custom-headers"); expect(r$status == 200, r)
    expect(identical(r$headers[["x-test"]], "1") && identical(r$headers[["x-other"]], "two"), r) })
test("rfun: status codes", for (code in c(201, 301, 400, 401, 403, 404, 405, 418, 500, 503)) {
    r <- get(paste0("/code/", code)); expect(r$status == code && r$text == "code", list(code, r)) })
test("rfun: invalid status code -> 500", for (code in c("NA", "99", "600", "-1")) {
    r <- get(paste0("/rawcode?c=", code)); expect(r$status == 500, list(code, r)); healthy() })
test("rfun: status line format", expect(grepl("^HTTP/1\\.1 418 \\S", get("/code/418")$line)))
test("rfun: 204/304 have no body nor Content-Length", for (code in c(204, 304)) for (p in c("/code/", "/rawcode?c=")) {
    con <- conn(); send(con, sprintf("GET %s%d HTTP/1.1\r\nHost: x\r\n\r\n", p, code))
    r <- read.resp(con); expect(r$status == code && is.null(r$headers[["content-length"]]), list(p, code, r))
    ## the payload must not be sent, so the next response must parse
    send(con, "GET /echo?after=1 HTTP/1.1\r\nHost: x\r\n\r\n")
    r <- read.resp(con); expect(r$status == 200 && has(r$text, "after=1"), list(p, code, "next request:", r))
    close(con) })
test("rfun: binary roundtrip", {
    r <- get("/raw"); expect(r$status == 200 && identical(r$body, as.raw(0:255)))
    expect(identical(r$headers[["content-type"]], "application/octet-stream")) })
test("rfun: empty payload", { r <- get("/empty"); expect(r$status == 200 && identical(r$headers[["content-length"]], "0")) })
test("rfun: empty string payload", { r <- get("/emptystr"); expect(r$status == 200 && identical(r$headers[["content-length"]], "0")) })
test("rfun: 5MB response", {
    r <- get("/big"); expect(r$status == 200 && length(r$body) == 5e6 && identical(r$body[1:5], as.raw(1:5)), length(r$body)) })
test("rfun: UTF-8", { r <- get("/utf8"); expect(identical(r$body, charToRaw("héllo")), r) })
test("rfun: latin1 strings are sent as UTF-8", { r <- get("/latin1"); expect(identical(r$body, charToRaw("héllo")), r$body) },
     skip="Rserve sends CHAR() as is")
test("rfun: file payload", { r <- get("/file"); expect(r$status == 200 && identical(r$text, "hello world\n"), r) })
test("rfun: tmpfile payload is removed", {
    r <- get("/tmpfile"); expect(r$status == 200 && identical(r$text, "temporary\n"), r)
    f <- r$headers[["x-tmpfile"]]; expect(!is.null(f), "no X-Tmpfile header")
    expect(wait.for(!file.exists(f)), "tmpfile not unlinked") })
test("rfun: tmpfile payload is removed with 304", {
    r <- get("/tmpfile?c=304"); expect(r$status == 304, r)
    f <- r$headers[["x-tmpfile"]]; expect(!is.null(f), "no X-Tmpfile header")
    expect(wait.for(!file.exists(f)), "tmpfile not unlinked") })
test("rfun: missing file payload is well-formed", {
    con <- conn(3); on.exit(close(con))
    send(con, "GET /missing-file HTTP/1.1\r\nHost: x\r\n\r\n")
    r <- read.resp(con); expect.in(r$status, c(200, 404, 500), r)
    if (r$status == 200) expect(identical(r$headers[["content-length"]], "0"))
    ## no stray bytes after the body: the next response on the connection must parse
    send(con, "GET /echo HTTP/1.1\r\nHost: x\r\n\r\n")
    expect(read.resp(con)$status == 200, "connection desynchronised by stray bytes")
})
test("rfun: R error -> 500, server survives", {
    r <- get("/error"); expect(r$status == 500 && has(r$text, "boom"), r); healthy() })
test("rfun: invalid results -> 500", for (p in c("/notlist", "/emptylist")) {
    r <- get(p); expect(r$status == 500, list(p, r)) })
test("rfun: incomplete request is not passed to the handler", {
    con <- conn(3); send(con, "GET /touch?f=partial HTTP/1.1\r\nHost: x\r\n"); Sys.sleep(0.2); close(con)
    settle(); expect(!file.exists(file.path(DOCROOT, "partial")), "handler called"); healthy() })
test("rfun: truncated body is not passed to the handler", {
    con <- conn(3); send(con, "POST /touch?f=truncated HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nshort")
    Sys.sleep(0.2); close(con)
    settle(); expect(!file.exists(file.path(DOCROOT, "truncated")), "handler called"); healthy() })
test("path: '+' is literal in the path", expect(identical(get("/a+b")$text, "plus")))
test("path: %20 is a space", expect(identical(get("/a%20b")$text, "space")))
test("query: '+' is space", expect(has(get("/echo?a=x+y")$text, "a=x y")))
test("query: no value, no key", { r <- get("/echo?flag&=v&k="); expect(r$status == 200 && has(r$text, "query==flag&=v&k=;"), r$text) })
test("path: percent decoding", expect(get("/code/%34%31%38")$status == 418))
test("query: malformed percent escapes", { expect(get("/echo?a=%zz&b=%4")$status == 200); healthy() })

## ---- protocol -------------------------------------------------------------
test("proto: HTTP/1.0 closes", {
    con <- conn(3); on.exit(close(con)); send(con, "GET /static/hello.txt HTTP/1.0\r\n\r\n")
    r <- read.resp(con); expect(r$status == 200 && r$version == "HTTP/1.0", r); expect(closed(con), "HTTP/1.0 connection left open") })
test("proto: HTTP/1.1 requires Host", expect(rawreq("GET /static/hello.txt HTTP/1.1\r\n\r\n")$status == 400))
test("proto: keep-alive, 20 requests", {
    con <- conn(); on.exit(close(con))
    for (i in 1:20) { send(con, sprintf("GET /echo?i=%d HTTP/1.1\r\nHost: x\r\n\r\n", i))
        r <- read.resp(con); expect(r$status == 200 && has(r$text, paste0("i=", i)), list(i, r)) } })
test("proto: keep-alive mixed static/rfun/POST", {
    con <- conn(); on.exit(close(con))
    for (p in c("/static/hello.txt", "/echo", "/static/digits.txt", "POST", "/raw", "/static/hello.txt")) {
        if (p == "POST") send(con, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc")
        else send(con, sprintf("GET %s HTTP/1.1\r\nHost: x\r\n\r\n", p))
        expect(read.resp(con)$status == 200, p) } })
test("proto: Connection: close honoured", {
    con <- conn(3); on.exit(close(con)); send(con, "GET /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    read.resp(con); expect(closed(con)) })
test("proto: Connection: close closes promptly", {
    con <- conn(5); on.exit(close(con)); send(con, "GET /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    read.resp(con); t0 <- Sys.time(); expect(closed(con))
    expect(elapsed(t0) < 1, sprintf("closed after %.2fs", elapsed(t0))) })
test("proto: Connection header is case-insensitive", {
    con <- conn(3); on.exit(close(con)); send(con, "GET /echo HTTP/1.1\r\nHost: x\r\nCONNECTION: Close\r\n\r\n")
    read.resp(con); expect(closed(con)) })
test("proto: LF-only line endings", expect(rawreq("GET /echo HTTP/1.1\nHost: x\nConnection: close\n\n")$status == 200))
test("proto: byte-at-a-time request", {
    req <- charToRaw("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
    con <- conn(); on.exit(close(con))
    for (b in seq_along(req)) { send(con, req[b]); Sys.sleep(0.002) }
    r <- read.resp(con); expect(r$status == 200 && has(r$text, "bodytxt=hello"), r) })
test("proto: request split between CR and LF", {
    con <- conn(); on.exit(close(con))
    send(con, "GET /echo HTTP/1.1\r"); Sys.sleep(0.2); send(con, "\nHost: x\r"); Sys.sleep(0.2)
    send(con, "\nX-A: 1\r"); Sys.sleep(0.2); send(con, "\nConnection: close\r\n\r"); Sys.sleep(0.2); send(con, "\n")
    expect(read.resp(con)$status == 200) })
test("proto: headers and body in separate packets", {
    con <- conn(); on.exit(close(con))
    send(con, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n"); Sys.sleep(0.2)
    send(con, "01234"); Sys.sleep(0.2); send(con, "56789")
    r <- read.resp(con); expect(r$status == 200 && has(r$text, "bodytxt=0123456789"), r) })
test("proto: Expect: 100-continue does not stall", {
    con <- conn(10); on.exit(close(con))
    send(con, "POST /echo HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
    ## a compliant client waits only briefly for 100, then sends the body anyway
    Sys.sleep(0.5); send(con, "hello")
    r <- read.resp(con)
    if (isTRUE(r$status == 100L)) r <- read.resp(con)
    expect(r$status == 200, r) })
test("proto: Expect: 100-continue gets 100 before the body is sent", {
    con <- conn(3); on.exit(close(con))
    send(con, "POST /echo HTTP/1.1\r\nHost: x\r\nExpect: 100-Continue\r\nContent-Length: 5\r\n\r\n")
    r <- read.resp(con); expect(isTRUE(r$status == 100L), r)
    send(con, "hello"); r <- read.resp(con); expect(r$status == 200 && has(r$text, "bodytxt=hello"), r) })
test("proto: no 100 if the body is already there", {
    con <- conn(3); on.exit(close(con))
    send(con, "POST /echo HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
    r <- read.resp(con); expect(r$status == 200, r) })
test("proto: no 100 for HTTP/1.0", {
    con <- conn(3); on.exit(close(con))
    send(con, "POST /echo HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n"); Sys.sleep(0.3); send(con, "hello")
    r <- read.resp(con); expect(r$status == 200, r) })
test("proto: pipelined requests", {
    con <- conn(5); on.exit(close(con))
    send(con, "GET /echo?n=1 HTTP/1.1\r\nHost: x\r\n\r\nGET /echo?n=2 HTTP/1.1\r\nHost: x\r\n\r\n")
    r1 <- read.resp(con); expect(has(r1$text, "n=1"))
    r2 <- read.resp(con); expect(has(r2$text, "n=2"), "second pipelined request not answered") })
test("proto: request pipelined after a POST", {
    con <- conn(5); on.exit(close(con))
    send(con, paste0("POST /echo?n=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc",
                     "GET /echo?n=2 HTTP/1.1\r\nHost: x\r\n\r\n"))
    r1 <- read.resp(con); expect(has(r1$text, "n=1") && has(r1$text, "bodytxt=abc"), r1)
    r2 <- read.resp(con); expect(has(r2$text, "n=2"), "request after the POST not answered") })
## the parser stops at NUL, a pipelined request with NUL before the end of
## the line must not make the server wait for a line it never sees (busy loop)
test("proto: NUL in pipelined data does not hang the connection", {
    con <- conn(5)
    send(con, c(charToRaw("GET /echo?n=1 HTTP/1.1\r\nHost: x\r\n\r\nGE"), as.raw(0), charToRaw("T /x HTTP/1.1\n")))
    r <- read.resp(con, head.only=TRUE); expect(r$status == 200, r)
    close(con)
    if (!WIN) expect(wait.for(!length(running(srv$pid)), 5), "the child serving the connection did not exit")
    healthy() })
test("proto: truncated body does not hurt the server", {
    con <- conn(3)
    send(con, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nshort")
    close(con); settle(); healthy() })

## ---- framing and smuggling ------------------------------------------------------
test("proto: Transfer-Encoding -> 501", {
    for (te in c("chunked", "gzip, chunked")) {
        r <- rawreq(paste0("POST /touch?f=te HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: ", te, "\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
        expect(r$status == 501, list(te, r)) }
    settle(); expect(!file.exists(file.path(DOCROOT, "te")), "handler called"); healthy() })
test("proto: whitespace before colon -> 400 (no request smuggling)", {
    for (h in c("Content-Length : 41", "Transfer-Encoding : chunked", "Content-Length\t: 41")) {
        con <- conn(3)
        send(con, paste0("POST /echo HTTP/1.1\r\nHost: x\r\n", h, "\r\n\r\nGET /touch?f=smuggled HTTP/1.1\r\nHost: x\r\n\r\n"))
        r <- read.resp(con); close(con); expect(r$status == 400, list(h, r))
    }
    settle(); expect(!file.exists(file.path(DOCROOT, "smuggled")), "smuggled request was processed"); healthy() })
test("proto: duplicate Host -> 400", expect(rawreq("GET /echo HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")$status == 400))
test("proto: Connection: close is announced in the response", {
    r <- get("/echo"); expect(identical(tolower(r$headers[["connection"]]), "close"), r) }, skip=NOTIMPL)
test("proto: Connection: keep-alive, close is honoured", {
    con <- conn(3); on.exit(close(con)); send(con, "GET /echo HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n")
    read.resp(con); expect(closed(con)) }, skip=NOTIMPL)
test("proto: handler can close the connection", {
    con <- conn(3); on.exit(close(con)); send(con, "GET /conn-close HTTP/1.1\r\nHost: x\r\n\r\n")
    r <- read.resp(con); expect(r$status == 200 && identical(r$text, "bye"), r); expect(closed(con), "connection left open") },
    skip=NOTIMPL)

## ---- malformed ------------------------------------------------------------
test("bad: binary garbage", { r <- request(raw=as.raw(c(1, 2, 3, charToRaw("garbage"), 13, 10, 13, 10))); expect(is.na(r$status) || r$status == 400, r); healthy() })
test("bad: no HTTP version", { expect(rawreq("GET /echo\r\n\r\n")$status == 400); healthy() })
test("bad: HTTP/2.0", { expect.in(rawreq("GET /echo HTTP/2.0\r\nHost: x\r\n\r\n")$status, c(400, 505)); healthy() })
test("bad: unknown method on a static path", { expect.in(rawreq("BREW /static/hello.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")$status, c(200, 405, 501)); healthy() })
test("bad: negative Content-Length", { expect.in(rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\nConnection: close\r\n\r\n")$status, c(400, 413)); healthy() })
test("bad: huge Content-Length -> 413", { expect(rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999\r\nConnection: close\r\n\r\n")$status == 413); healthy() })
test("bad: non-numeric Content-Length -> 400", { expect(rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\nConnection: close\r\n\r\n")$status == 400); healthy() })
test("bad: Content-Length with trailing garbage -> 400", { expect(rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3x\r\nConnection: close\r\n\r\nabc")$status == 400); healthy() })
test("bad: conflicting Content-Length -> 400", {
    r <- rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde")
    expect(r$status == 400, r); healthy() })
test("ok: repeated identical Content-Length", {
    r <- rawreq("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
    expect(r$status == 200 && has(r$text, "bodytxt=abc"), r) })
## the server rejects these without reading the whole request, so closing the
## connection resets it and on Windows the client then loses the response (NA)
expect.reject <- function(status, codes) if (!(WIN && is.na(status))) expect.in(status, codes)
test("bad: 100KB request line", { expect.reject(rawreq(paste0("GET /", strrep("a", 1e5), " HTTP/1.1\r\nHost: x\r\n\r\n"))$status, c(400, 413, 414)); healthy() })
test("bad: 100KB header", { expect.reject(request("GET", "/echo", list("X-Big"=strrep("a", 1e5)))$status, c(400, 413, 431)); healthy() })
test("bad: line exactly filling the buffer", {
    ## LINE_BUF_SIZE is 32768, one byte is reserved for the NUL
    for (n in 32760:32770) { r <- request("GET", "/echo", list("X-Big"=strrep("a", n)))
        expect.reject(r$status, c(200, 413)) }
    healthy() })
test("bad: 2000 headers", { h <- setNames(as.list(rep(strrep("v", 50), 2000)), paste0("X-H", 1:2000)); expect.in(request("GET", "/echo", h)$status, c(200, 400, 413, 431)); healthy() })
test("bad: header line starting with whitespace", {
    expect.in(rawreq("GET /echo HTTP/1.1\r\nHost: x\r\n X-A: 1\r\nConnection: close\r\n\r\n")$status, 400); healthy() })
test("bad: header without colon", { expect.in(rawreq("GET /echo HTTP/1.1\r\nHost: x\r\nNoColonHere\r\nConnection: close\r\n\r\n")$status, c(200, 400)); healthy() })
test("bad: overlong method", { expect.in(rawreq(paste0(strrep("M", 2000), " /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))$status, c(200, 400, 501)); healthy() })
test("bad: GET with body", { expect.in(request("GET", "/echo", body="abc")$status, c(200, 400)); healthy() })
test("bad: abrupt disconnects", {
    for (p in c("", "GET", "GET /echo HTTP/1.1\r\n", "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nab")) {
        con <- conn(); if (nzchar(p)) send(con, p); close(con) }
    settle(); healthy() })
test("bad: client closes during large response (SIGPIPE)", {
    con <- conn(); send(con, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n"); rd(con, 1000); close(con)
    con <- conn(); send(con, "GET /static/big.bin HTTP/1.1\r\nHost: x\r\n\r\n"); rd(con, 1000); close(con)
    settle(); healthy() })
test("bad: odd URLs", {
    for (p in c("/static//hello.txt", "/static/./hello.txt", "/static/hello.txt/", "//static/hello.txt", "*", "/static/%", "/static/%4")) {
        r <- rawreq(sprintf("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", p)); expect(!is.na(r$status), p) }
    healthy() })
test("bad: absolute-form URI", { expect.in(rawreq("GET http://localhost/echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")$status, c(200, 400, 404)); healthy() })
