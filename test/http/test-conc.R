## Concurrency and lifecycle tests.
## Fixture: fixtures/server.R
## On unix Rserve forks a child per connection; on Windows it serves one
## connection at a time, so tests that need a second connection served
## meanwhile cannot work there.

seq.only <- if (WIN) "Rserve on Windows serves one connection at a time"
test("conc: 8 parallel clients x 25 requests", {
    res <- par.lapply(1:8, function(i) {
        for (j in 1:25) {
            r <- get(sprintf("/echo?i=%d&j=%d", i, j))
            if (r$status != 200 || !has(r$text, sprintf("i=%d&j=%d", i, j))) return(FALSE)
            if (!identical(get("/static/hello.txt")$text, "hello world\n")) return(FALSE)
        }
        TRUE })
    expect(all(unlist(res)), "some parallel requests failed") })
test("conc: half-open connection does not block others", {
    slow <- conn(); on.exit(close(slow)); send(slow, "GET /echo HTTP/1.1\r\nHost: x\r\nX-Slow: ")
    t0 <- Sys.time(); for (i in 1:10) expect(get("/echo")$status == 200)
    expect(elapsed(t0) < 5, "stalled") }, skip=seq.only)
test("conc: idle keep-alive connections do not block others", {
    idle <- lapply(1:10, function(i) { s <- conn(); send(s, "GET /echo HTTP/1.1\r\nHost: x\r\n\r\n"); read.resp(s); s })
    on.exit(for (s in idle) close(s))
    t0 <- Sys.time(); expect(get("/echo")$status == 200)
    expect(elapsed(t0) < 5, "starved") }, skip=seq.only)
test("conc: slow R handler does not block static files", {
    marker <- file.path(DOCROOT, "slow-started"); unlink(marker); on.exit(unlink(marker))
    slow <- conn(30); on.exit(close(slow), add=TRUE); send(slow, "GET /sleep?m=slow-started HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    expect(wait.for(file.exists(marker)), "the slow handler did not start")
    t0 <- Sys.time(); expect(get("/static/hello.txt")$status == 200)
    dt <- elapsed(t0)
    r <- read.resp(slow)
    expect(dt < 0.8, paste("static request waited", round(dt, 2), "s behind an R handler"))
    expect(identical(r$text, "slept")) }, skip=seq.only)
test("conc: each connection is served by a forked child", {
    p1 <- get("/pid")$text; p2 <- get("/pid")$text
    expect(p1 != p2 && p1 != as.character(srv$pid), c(p1, p2, srv$pid)) }, skip=no.fork)
test("conc: no zombie children are left behind", {
    for (i in 1:20) get("/echo")
    expect(wait.for(zombies(srv$pid) == 0, 5), paste(zombies(srv$pid), "zombies")) }, skip=no.fork)
test("conc: connection churn", {
    for (i in 1:200) {
        con <- tryCatch(conn(), error=function(e) stop("connect #", i, " failed: ", conditionMessage(e)))
        close(con)
    }
    for (i in 1:50) { r <- get("/echo"); expect(r$status == 200, list(paste0("request #", i, ":"), r)) }
    healthy() })

test("lifecycle: server still running", expect(server.alive(), server.log(20)))
