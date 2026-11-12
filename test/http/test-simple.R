## The stand-alone Rserve binary with --RS-simple-http-only <docroot>.
## Started by start.binary() (see helpers.R)

test("simple: index", { r <- get("/"); expect(r$status == 200 && has(r$text, "root"), r) })
test("simple: file", { r <- get("/hello.txt"); expect(st(r) == "200 hello world\n", st(r)) })
test("simple: subdir redirect and index", {
    r <- get("/sub"); expect(r$status == 301 && identical(r$headers[["location"]], "/sub/"), r)
    r <- get("/sub/"); expect(r$status == 200 && has(r$text, "sub"), r) })
test("simple: missing -> 404", expect(get("/nope.txt")$status == 404))
test("simple: range", { r <- get("/digits.txt", headers=list(Range="bytes=2-5")); expect(r$status == 206 && r$text == "2345", r) })
test("simple: conditional GET", {
    lm <- get("/hello.txt")$headers[["last-modified"]]
    expect(get("/hello.txt", headers=list("If-Modified-Since"=lm))$status == 304) })
test("simple: traversal", for (p in c("/../secret-outside.txt", "/%2e%2e/secret-outside.txt", "/sub/../../secret-outside.txt"))
    expect(get(p)$status != 200, p))
test("simple: keep-alive", {
    con <- conn(); on.exit(close(con))
    for (p in c("/hello.txt", "/digits.txt", "/nope", "/hello.txt")) {
        send(con, sprintf("GET %s HTTP/1.1\r\nHost: x\r\n\r\n", p)); expect.in(read.resp(con)$status, c(200, 404), p) } })
test("simple: server still running", expect(server.alive(), server.log(20)))
