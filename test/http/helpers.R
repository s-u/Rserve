## Shared infrastructure for the Rserve HTTP tests: server control, a tiny HTTP
## client and a minimal test framework. Sourced by run.R into the global
## environment, the test files use these functions directly.

HOST <- "127.0.0.1"
WIN  <- .Platform$OS.type == "windows"

## ---- server control -------------------------------------------------------
## srv holds the server the tests currently talk to: list(port, pid, log, docroot)
srv <- NULL

pid.alive <- function(pid) {
    if (is.na(pid)) return(FALSE)
    if (!WIN) return(isTRUE(tools::pskill(pid, 0)))
    ## pskill() always terminates on Windows, but psnice() only queries the
    ## process (NA if it doesn't exist); tasklist needs rights we may not have
    !is.na(tools::psnice(pid))
}
## the fixtures print "PID <pid>" as their first line (Rscript may be a wrapper
## so the pid of the process we start is not necessarily that of R)
log.pid <- function(log) {
    l <- if (file.exists(log)) grep("^PID [0-9]+", readLines(log, warn=FALSE), value=TRUE) else character()
    if (length(l)) as.integer(sub("^PID ([0-9]+).*", "\\1", l[1])) else NA_integer_
}
port.open <- function(port)
    tryCatch({ close(socketConnection(HOST, port, open="r+b", timeout=1)); TRUE },
             error=function(e) FALSE, warning=function(w) FALSE)

## runs Rscript <args> in the background with stdout and stderr going to log.
## On Windows system2() opens the log without sharing, so it could not be read
## while the process runs; a redirection by cmd allows that
rscript.bg <- function(args, log) {
    rscript <- file.path(R.home("bin"), "Rscript")
    if (WIN)
        system2("cmd", c("/c", paste0('"', paste(shQuote(rscript), paste(args, collapse=" "),
                                                 ">", shQuote(log), "2>&1"), '"')), wait=FALSE)
    else
        system2(rscript, args, stdout=log, stderr=log, wait=FALSE)
}

## starts Rscript fixtures/<fixture> --port=.. --docroot=.. [--lib=..] <args>
## and waits until it accepts connections; sets and returns srv
start.server <- function(fixture, args=character()) {
    log <- tempfile("server", fileext=".log")
    for (i in 1:20) {
        port <- sample(20000:60000, 1)
        unlink(log)
        rscript.bg(c(shQuote(file.path(HERE, "fixtures", fixture)), paste0("--port=", port),
                     paste0("--docroot=", shQuote(DOCROOT)), if (!is.null(LIB)) paste0("--lib=", shQuote(LIB)), args),
                   log)
        pid <- NA_integer_
        for (k in 1:150) { # wait for the listener or death
            Sys.sleep(0.1)
            if (is.na(pid)) pid <- log.pid(log)
            if (!is.na(pid) && port.open(port))
                return(srv <<- list(port=port, pid=pid, log=log, docroot=DOCROOT, fixture=fixture, args=args))
            if (!is.na(pid) && !pid.alive(pid)) break
        }
        if (!is.na(pid)) kill.server(list(pid=pid))
    }
    stop("could not start server ", fixture, ":\n", paste(if (file.exists(log)) readLines(log, warn=FALSE), collapse="\n"))
}

## kills the server (and on unix its children, i.e., forked workers)
kill.server <- function(s=srv) {
    if (is.null(s) || is.na(s$pid)) return(invisible())
    if (!WIN) for (w in children(s$pid)) tools::pskill(w, tools::SIGKILL)
    if (pid.alive(s$pid)) tools::pskill(s$pid, tools::SIGKILL)
    invisible()
}
server.alive <- function() pid.alive(srv$pid)
## replaces a dead server with a fresh one started the same way
restart.server <- function() {
    kill.server()
    if (identical(srv$fixture, "<binary>")) start.binary(srv$args) else start.server(srv$fixture, srv$args)
}

## starts the stand-alone Rserve binary (R CMD <RSERVE.BIN> ...) with the HTTP
## server on a random port, Rserve daemonizes so its pid is taken from the pid file
start.binary <- function(args=character()) {
    log <- tempfile("server", fileext=".log")
    pf <- tempfile("rserve", fileext=".pid")
    for (i in 1:20) {
        port <- sample(20000:60000, 1)
        unlink(c(log, pf))
        system2(file.path(R.home("bin"), "R"), c("CMD", shQuote(RSERVE.BIN), "--RS-pidfile", shQuote(pf),
                                                 "--RS-set", paste0("http.port=", port), args, "--no-save"),
                stdout=log, stderr=log, wait=TRUE, timeout=30)
        pid <- NA_integer_
        for (k in 1:150) {
            Sys.sleep(0.1)
            if (is.na(pid) && file.exists(pf) && length(l <- readLines(pf, warn=FALSE)))
                pid <- suppressWarnings(as.integer(l[1]))
            if (!is.na(pid) && port.open(port))
                return(srv <<- list(port=port, pid=pid, log=log, docroot=DOCROOT, fixture="<binary>", args=args))
            if (!is.na(pid) && !pid.alive(pid)) break
        }
        if (!is.na(pid)) kill.server(list(pid=pid))
    }
    stop("could not start Rserve ", paste(args, collapse=" "), ":\n",
         paste(if (file.exists(log)) readLines(log, warn=FALSE), collapse="\n"))
}
server.log <- function(n=20) { l <- readLines(srv$log, warn=FALSE); paste(tail(l, n), collapse="\n") }

## unix only: process ids of the children of pid (and which of them are zombies)
ps.table <- function() {
    p <- suppressWarnings(system2("ps", c("-A", "-o", "pid=,ppid=,stat="), stdout=TRUE))
    p <- strsplit(trimws(p), "[[:space:]]+")
    data.frame(pid=as.integer(sapply(p, `[`, 1)), ppid=as.integer(sapply(p, `[`, 2)), stat=sapply(p, `[`, 3))
}
children <- function(pid) { p <- ps.table(); sort(p$pid[p$ppid == pid]) }
zombies  <- function(pid) { p <- ps.table(); sum(p$ppid == pid & grepl("Z", p$stat)) }
running  <- function(pid) { p <- ps.table(); sort(p$pid[p$ppid == pid & !grepl("Z", p$stat)]) }

## files served by the fixtures; created once per run
make.docroot <- function() {
    wl <- function(x, f) { con <- file(f, "wb"); on.exit(close(con)); writeLines(x, con) } # no CRLF on Windows
    docroot <- file.path(tempfile("wstest"), "root")
    dir.create(file.path(docroot, "sub"), recursive=TRUE)
    dir.create(file.path(docroot, "emptydir"))
    wl("hello world", file.path(docroot, "hello.txt"))
    wl("<h1>root</h1>", file.path(docroot, "index.html"))
    wl("<h1>sub</h1>", file.path(docroot, "sub", "index.html"))
    cat("0123456789", file=file.path(docroot, "digits.txt"))
    ## more than the socket buffers can hold, for clients that do not read the response
    writeBin(raw(32e6), file.path(docroot, "big.bin"))
    dir.create(file.path(docroot, "a b%"))
    wl("<h1>odd</h1>", file.path(docroot, "a b%", "index.html"))
    wl("plus", file.path(docroot, "a+b.txt"))
    wl("x", file.path(dirname(docroot), "secret-outside.txt"))
    wl("utf8", file.path(docroot, "café.txt"))
    docroot
}

## ---- tiny HTTP client -----------------------------------------------------
## Connections closed by the server stay in TIME_WAIT on its side. The client
## may pick the same port again for a new connection, which then gets reset,
## so a connect refused right away is retried (a server that is not listening
## refuses the retries as well). On failure reports how long the connect took
## (refused right away or timed out), whether the server is alive and the end
## of its log.
conn <- function(timeout=10, tries=3) {
    for (i in seq_len(tries)) {
        t0 <- Sys.time(); w <- character()
        con <- withCallingHandlers(
            tryCatch(socketConnection(HOST, srv$port, blocking=TRUE, open="r+b", timeout=timeout),
                     error=function(e) e),
            warning=function(x) { w <<- c(w, conditionMessage(x)); invokeRestart("muffleWarning") })
        if (!inherits(con, "error")) return(con)
        dt <- elapsed(t0)
        if (dt > 0.5 || i == tries || !server.alive()) break
        Sys.sleep(0.05)
    }
    stop(sprintf("cannot connect to port %d after %.2fs, attempt %d (%s; server %s), last lines of its log:\n%s",
                 srv$port, dt, i, paste(c(w, conditionMessage(con)), collapse="; "),
                 if (server.alive()) "alive" else "dead", server.log(5)), call.=FALSE)
}
send <- function(con, x) { writeBin(if (is.character(x)) charToRaw(x) else x, con); flush(con) }
rd <- function(con, n) readBin(con, "raw", n)

read.resp <- function(con, head.only=FALSE) {
    buf <- raw(0); crlf <- charToRaw("\r\n\r\n")
    repeat {
        b <- rd(con, 1)
        if (!length(b)) break
        buf <- c(buf, b)
        n <- length(buf)
        if (n >= 4 && all(buf[(n-3):n] == crlf)) break
    }
    txt <- rawToChar(buf[buf != 0])
    lines <- strsplit(sub("\r\n\r\n$", "", txt), "\r\n", fixed=TRUE)[[1]]
    first <- if (length(lines)) lines[1] else ""
    parts <- strsplit(first, " ", fixed=TRUE)[[1]]
    h <- list()
    for (l in lines[-1]) {
        i <- regexpr(":", l, fixed=TRUE)
        if (i > 0) h[[tolower(trimws(substr(l, 1, i - 1)))]] <- trimws(substr(l, i + 1, nchar(l)))
    }
    status <- if (length(parts) > 1) suppressWarnings(as.integer(parts[2])) else NA_integer_
    body <- raw(0)
    cl <- h[["content-length"]]
    if (!head.only && is.null(cl) && !isTRUE(status < 200L || status %in% c(204L, 304L))) {
        repeat { d <- rd(con, 65536); if (!length(d)) break; body <- c(body, d) } # body runs to EOF
    } else if (!head.only && !is.null(cl) && !isTRUE(status %in% c(204L, 304L))) {
        n <- as.integer(cl)
        while (length(body) < n) {
            d <- rd(con, n - length(body))
            if (!length(d)) break
            body <- c(body, d)
        }
    }
    structure(list(status=status, line=first, version=parts[1], headers=h, body=body,
                   text=rawToChar(body[body != 0])), class="resp")
}
print.resp <- function(x, ...) cat("<resp ", x$line, " [", paste(names(x$headers), collapse=","), "] ",
                                  substr(x$text, 1, 80), ">\n", sep="")
format.resp <- function(x, ...) paste0(x$line, " [", paste(names(x$headers), collapse=","), "] ", substr(x$text, 1, 80))

request <- function(method="GET", path="/", headers=NULL, body=NULL, version="1.1", raw=NULL,
                    close=TRUE, timeout=10) {
    con <- conn(timeout); on.exit(close(con))
    if (is.null(raw)) {
        h <- character()
        if (version == "1.1") h <- "Host: localhost"
        for (k in names(headers)) h <- c(h, paste0(k, ": ", headers[[k]]))
        if (!is.null(body) && !any(tolower(names(headers)) %in% c("content-length", "transfer-encoding")))
            h <- c(h, paste0("Content-Length: ", length(if (is.raw(body)) body else charToRaw(body))))
        if (close) h <- c(h, "Connection: close")
        raw <- c(charToRaw(paste0(method, " ", path, " HTTP/", version, "\r\n",
                                  paste(h, collapse="\r\n"), "\r\n\r\n")),
                 if (!is.null(body)) (if (is.raw(body)) body else charToRaw(body)))
    }
    send(con, raw)
    read.resp(con, head.only=(method == "HEAD"))
}
get <- function(path, ...) request("GET", path, ...)
rawreq <- function(s) request(raw=charToRaw(s))
## whether the peer has closed the connection (EOF) within the timeout
closed <- function(con) length(rd(con, 1)) == 0

## sends the requests (GET paths) in batches of `conc' connections that are
## all in flight at the same time, returns the list of responses (NULL on error)
par.get <- function(paths, conc=20, timeout=30) {
    res <- vector("list", length(paths))
    for (b in split(seq_along(paths), ceiling(seq_along(paths) / conc))) {
        cons <- lapply(b, function(i) tryCatch({
            con <- conn(timeout)
            send(con, paste0("GET ", paths[i], " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
            con }, error=function(e) NULL))
        for (k in seq_along(b)) if (!is.null(cons[[k]])) {
            res[b[k]] <- list(tryCatch(read.resp(cons[[k]]), error=function(e) NULL))
            close(cons[[k]])
        }
    }
    res
}
## "<status> <body>" of a response (as the old curl-based tests used), "000 " if failed
st <- function(r) if (is.null(r) || is.na(r$status)) "000 " else paste(r$status, r$text)

## mclapply() cannot fork on Windows, so use a PSOCK cluster there
par.lapply <- function(X, FUN) {
    if (!WIN) return(parallel::mclapply(X, FUN, mc.cores=length(X)))
    cl <- parallel::makeCluster(length(X)); on.exit(parallel::stopCluster(cl))
    parallel::clusterExport(cl, ls(globalenv()), envir=globalenv())
    parallel::parLapply(cl, X, FUN)
}
elapsed <- function(t0) as.numeric(difftime(Sys.time(), t0, units="secs"))
## polls cond (an expression evaluated in the caller) until it is TRUE, returns
## FALSE if it did not become TRUE within timeout seconds. Use it instead of a
## fixed sleep whenever there is something to wait for.
wait.for <- function(cond, timeout=10) {
    cond <- substitute(cond); env <- parent.frame(); t0 <- Sys.time()
    repeat {
        if (isTRUE(eval(cond, env))) return(TRUE)
        if (elapsed(t0) > timeout) return(FALSE)
        Sys.sleep(0.02)
    }
}

## ---- minimal test framework -----------------------------------------------
results <- logical()
skipped <- 0L
CONTEXT <- ""  # prefix of the test names, describes the current suite/configuration

## skip: reason why the test cannot succeed in this configuration (NULL = run it)
## restart: if the server dies during the test, the test fails and a new server
##          is started for the following tests. Use FALSE for tests that stop
##          the server on purpose.
test <- function(name, expr, skip=NULL, restart=TRUE) {
    full <- paste0(CONTEXT, name)
    if (nzchar(PATTERN) && !grepl(PATTERN, full)) return(invisible())
    if (!is.null(skip)) {
        cat(sprintf("%-62s skipped (%s)\n", name, skip))
        skipped <<- skipped + 1L
        return(invisible())
    }
    ## the body is evaluated as a function, so on.exit() works as expected
    ## and local variables don't leak into other tests
    fn <- function() NULL
    body(fn) <- substitute(expr)
    environment(fn) <- parent.frame()
    before <- getAllConnections()
    msg <- tryCatch({ fn(); NULL }, error=function(e) conditionMessage(e))
    ## close whatever the test left open (an idle connection would block a single-threaded server)
    for (i in setdiff(getAllConnections(), before)) try(close(getConnection(i)), silent=TRUE)
    died <- restart && !is.null(srv) && !server.alive()
    if (died)
        msg <- paste0(if (!is.null(msg)) paste0(msg, "\n"), "server died, last lines of its log:\n", server.log(5))
    cat(sprintf("%-62s %s\n", name, if (is.null(msg)) "ok" else "FAIL"))
    if (!is.null(msg)) cat("    ", gsub("\n", "\n     ", msg), "\n", sep="")
    results[full] <<- is.null(msg)
    ## don't let a crash take the following tests with it
    ## (if the restart fails, the error aborts the rest of the suite)
    if (died) {
        restart.server()
        cat("    (server restarted)\n")
    }
}
expect <- function(cond, info="") if (!isTRUE(cond)) stop("expectation failed: ", paste(format(info), collapse=" "), call.=FALSE)
expect.in <- function(x, set, info=NULL) expect(!is.na(x) && x %in% set, list(x, info))
expect.error <- function(expr) expect(inherits(try(expr, silent=TRUE), "try-error"), "no error")
## before checking that something did *not* happen (a handler was not called,
## the server did not crash), gives the server time to process what the client
## did. Rserve on Windows serves connections one after another, so there a
## completed request on a new connection proves it; otherwise (a forked child
## per connection) wait.
settle <- function(t=0.5) invisible(if (WIN) get("/settle") else Sys.sleep(t))
healthy <- function() { expect(server.alive(), "server process died"); expect(get("/echo")$status == 200, "server unhealthy") }
has <- function(txt, pat) grepl(pat, txt, fixed=TRUE)
