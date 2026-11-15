## OCAP idle tests: R's events while the OCAP loop is idle
## (ocap.idle.events, ocap.idle.interval, use.idle.callback).
##
## Usage: Rscript test/ocap/run.R [--lib=<lib>] [pattern]
##
## Each test starts the stand-alone Rserve binary of the installed package
## (or the one in --lib) in OCAP mode with a configuration of its own, and
## talks to it with RSclient. The server's oc.init() offers two
## capabilities: eval(code), which evaluates code in the global environment,
## and wait(), which sends an OOB message and returns how many Tcl timer
## ticks happened while the client took its time answering it.
##
## Needs the RSclient package; the event tests need tcltk (a Tcl timer is
## the probe: it only advances while R processes its events) and the later
## test needs later. Tests that cannot run are skipped, not failed.

args <- commandArgs(TRUE)
opt <- function(name, default=NULL) {
    a <- grep(paste0("^--", name, "="), args, value=TRUE)
    if (length(a)) sub("^--[^=]*=", "", a[1]) else default
}
LIB     <- opt("lib")
PATTERN <- paste(grep("^--", args, value=TRUE, invert=TRUE), collapse="|")
if (!is.null(LIB)) {
    LIB <- normalizePath(LIB, mustWork=TRUE)
    .libPaths(c(LIB, .libPaths()))
    ## the servers load Rserve's R code from there too
    Sys.setenv(R_LIBS=paste(c(LIB, Sys.getenv("R_LIBS")), collapse=.Platform$path.sep))
}
WIN <- .Platform$OS.type == "windows"
suppressMessages(library(Rserve))
if (!requireNamespace("RSclient", quietly=TRUE)) stop("these tests need the RSclient package")
cat("Testing Rserve ", format(packageVersion("Rserve")), " from ", dirname(find.package("Rserve")),
    "\nR ", R.version$major, ".", R.version$minor, " (", R.version$platform, ")\n", sep="")

RSERVE.BIN <- local({
    d <- file.path(find.package("Rserve"), "libs", .Platform$r_arch)
    f <- file.path(d, if (WIN) "Rserve.exe" else "Rserve")
    if (file.exists(f)) f else stop("stand-alone Rserve binary not found in ", d)
})
HAS.TCL   <- capabilities("tcltk") && !inherits(try(suppressWarnings(loadNamespace("tcltk")), silent=TRUE), "try-error")
HAS.LATER <- requireNamespace("later", quietly=TRUE)

## ---- server control ---------------------------------------------------------

## the server's R code: oc.init() and the probes it offers
INIT <- '
ticks <- 0L
tick <- NULL
idle.calls <- 0L
oc.init <- function(...) list(
    eval = Rserve::ocap(function(code) eval(parse(text=code), .GlobalEnv), "eval"),
    wait = Rserve::ocap(function() {
        t0 <- ticks
        Rserve::self.oobMessage(list("wait"))
        ticks - t0
    }, "wait")
)
'

srv <- NULL

pid.alive <- function(pid) {
    if (is.na(pid)) return(FALSE)
    if (!WIN) return(isTRUE(tools::pskill(pid, 0)))
    !is.na(tools::psnice(pid))
}
port.open <- function(port)
    tryCatch({ close(socketConnection("127.0.0.1", port, open="r+b", timeout=1)); TRUE },
             error=function(e) FALSE, warning=function(w) FALSE)

## starts Rserve with the configuration lines conf (in addition to the port,
## OCAP mode and the init code), waits until it listens, sets srv
start.ocap <- function(conf=character()) {
    dir <- tempfile("ocaptest")
    dir.create(dir)
    init <- file.path(dir, "init.R")
    pf <- file.path(dir, "rserve.pid")
    ## the server writes its own pid (pid.file is not supported on Windows)
    writeLines(c(sprintf('writeLines(as.character(Sys.getpid()), "%s")', gsub("\\\\", "/", pf)), INIT), init)
    log <- file.path(dir, "server.log")
    for (i in 1:20) {
        port <- sample(20000:60000, 1)
        cf <- file.path(dir, "Rserve.conf")
        writeLines(c(paste("port", port), "qap.oc enable", "oob enable",
                     paste("source", gsub("\\\\", "/", init)), conf), cf)
        unlink(c(pf, log))
        system2(file.path(R.home("bin"), "R"),
                c("CMD", shQuote(RSERVE.BIN), "--RS-conf", shQuote(cf), "--no-save"),
                stdout=log, stderr=log, wait=!WIN) # Rserve daemonizes on unix
        pid <- NA_integer_
        for (k in 1:150) {
            Sys.sleep(0.1)
            if (is.na(pid) && file.exists(pf) && length(l <- readLines(pf, warn=FALSE)))
                pid <- suppressWarnings(as.integer(l[1]))
            if (!is.na(pid) && port.open(port))
                return(srv <<- list(port=port, pid=pid, log=log))
            if (!is.na(pid) && !pid.alive(pid)) break
        }
        if (!is.na(pid) && pid.alive(pid)) tools::pskill(pid, tools::SIGKILL)
    }
    stop("could not start Rserve:\n", paste(if (file.exists(log)) readLines(log, warn=FALSE), collapse="\n"))
}
stop.ocap <- function() {
    if (!is.null(srv) && pid.alive(srv$pid)) tools::pskill(srv$pid, tools::SIGKILL)
    srv <<- NULL
}

## an OCAP connection: rs$eval(code) evaluates code in the server;
## rs$wait(seconds) calls wait() and answers its OOB message after seconds
connect <- function() {
    con <- RSclient::RS.connect(port=srv$port)
    caps <- attr(con, "capabilities")
    delay <- 0
    RSclient::RS.oobCallbacks(con, msg=function(code, what) { Sys.sleep(delay); "ok" })
    list(con=con,
         eval=function(code) RSclient::RS.eval.qap(con, as.call(list(caps$eval, code))),
         wait=function(seconds) { delay <<- seconds; RSclient::RS.eval.qap(con, as.call(list(caps$wait))) },
         close=function() RSclient::RS.close(con))
}

## a Tcl timer that counts its ticks in the server's `ticks` every `ms`
start.timer <- function(rs, ms)
    rs$eval(sprintf("library(tcltk); ticks <- 0L; tick <- function() { ticks <<- ticks + 1L; tcl('after', %d, tick) }; tcl('after', %d, tick); NULL", ms, ms))

## ticks of the timer after the server has been idle for `seconds`
idle.ticks <- function(rs, seconds) {
    t0 <- rs$eval("ticks")
    Sys.sleep(seconds)
    rs$eval("ticks") - t0
}

## ---- a minimal test framework ----------------------------------------------
results <- list()
test <- function(name, expr, skip=NULL) {
    if (nzchar(PATTERN) && !grepl(PATTERN, name)) return(invisible())
    if (!is.null(skip)) {
        cat(sprintf("SKIP  %s (%s)\n", name, skip))
        results[[name]] <<- NA
        return(invisible())
    }
    t0 <- proc.time()[[3]]
    r <- tryCatch({ force(expr); TRUE }, error=function(e) conditionMessage(e))
    stop.ocap()
    ok <- isTRUE(r)
    cat(sprintf("%s  %s (%.1fs)%s\n", if (ok) "ok  " else "FAIL", name, proc.time()[[3]] - t0,
                if (ok) "" else paste0(": ", r)))
    results[[name]] <<- ok
}
expect <- function(cond, info="") if (!isTRUE(cond)) stop("expectation failed: ", paste(format(info), collapse=" "), call.=FALSE)

no.tcl <- if (!HAS.TCL) "tcltk is not available"

## ---- tests -------------------------------------------------------------------

test("idle events are off by default", {
    start.ocap()
    rs <- connect(); on.exit(rs$close())
    start.timer(rs, 50)
    n <- idle.ticks(rs, 2)
    expect(n <= 2, list("ticks while idle:", n))
}, skip=no.tcl)

test("ocap.idle.events processes events while idle", {
    start.ocap("ocap.idle.events yes")
    rs <- connect(); on.exit(rs$close())
    start.timer(rs, 50)
    n <- idle.ticks(rs, 2)
    ## one tick per idle interval (200 ms) at most
    expect(n >= 5 && n <= 15, list("ticks in 2 s:", n))
}, skip=no.tcl)

test("ocap.idle.interval sets the granularity", {
    start.ocap(c("ocap.idle.events yes", "ocap.idle.interval 20"))
    rs <- connect(); on.exit(rs$close())
    start.timer(rs, 50)
    n <- idle.ticks(rs, 2)
    ## the 50 ms timer itself is now the limit (40 ticks in 2 s)
    expect(n >= 25, list("ticks in 2 s:", n))
}, skip=no.tcl)

test("events are processed while waiting for an OOB reply", {
    start.ocap(c("ocap.idle.events yes", "ocap.idle.interval 20"))
    rs <- connect(); on.exit(rs$close())
    start.timer(rs, 50)
    n <- rs$wait(1.5)
    expect(n >= 15, list("ticks while the client took 1.5 s to answer:", n))
    expect(identical(rs$eval("1 + 1"), 2))
}, skip=no.tcl)

test("an error in an event handler does not affect the server", {
    start.ocap(c("ocap.idle.events yes", "ocap.idle.interval 20"))
    rs <- connect(); on.exit(rs$close())
    rs$eval("library(tcltk); tcl('after', 50, function() stop('boom')); NULL")
    Sys.sleep(0.5)
    expect(identical(rs$eval("1 + 1"), 2))
    expect(pid.alive(srv$pid))
}, skip=no.tcl)

test("later callbacks run while idle", {
    start.ocap(c("ocap.idle.events yes", "ocap.idle.interval 20"))
    rs <- connect(); on.exit(rs$close())
    rs$eval("fired <- FALSE; later::later(function() fired <<- TRUE, 0.2); NULL")
    Sys.sleep(1)
    expect(isTRUE(rs$eval("fired")))
}, skip=if (!HAS.LATER) "later is not installed")

test("later callbacks do not run with idle events off", {
    start.ocap()
    rs <- connect(); on.exit(rs$close())
    rs$eval("fired <- FALSE; later::later(function() fired <<- TRUE, 0.2); NULL")
    Sys.sleep(1)
    expect(isFALSE(rs$eval("fired")))
}, skip=if (!HAS.LATER) "later is not installed")

test("use.idle.callback follows ocap.idle.interval", {
    start.ocap(c("use.idle.callback yes", "ocap.idle.interval 50"))
    rs <- connect(); on.exit(rs$close())
    rs$eval(".ocap.idle <- function() idle.calls <<- idle.calls + 1L; NULL")
    t0 <- rs$eval("idle.calls")
    Sys.sleep(1)
    n <- rs$eval("idle.calls") - t0
    expect(n >= 10, list("idle callbacks in 1 s:", n))
})

## ---- summary -----------------------------------------------------------------
r <- unlist(results)
cat(sprintf("\n%d passed, %d failed, %d skipped\n", sum(r, na.rm=TRUE), sum(!r, na.rm=TRUE), sum(is.na(r))))
if (any(!r, na.rm=TRUE)) {
    cat("failed:", paste(names(r)[!is.na(r) & !r], collapse=", "), "\n")
    quit(status=1)
}
