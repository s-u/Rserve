## Test driver for the HTTP/HTTPS server of Rserve. It tests the installed
## package, nothing is built or installed. Requires permission to bind local
## TCP ports.
##
## Usage: Rscript run.R [options] [pattern]
##   --suites=api,http,rawbody,tls,tlsclient,ws,simple   suites to run (default: all)
##   --lib=<path>     load Rserve from this library (also in the servers)
##   --slow           include slow tests
##   pattern          only run tests whose name, including the "[suite] "
##                    prefix, matches this regular expression
##
## Example: Rscript run.R --suites=http range
args <- commandArgs(TRUE)
opt <- function(name, default=NULL) {
    a <- grep(paste0("^--", name, "(=|$)"), args, value=TRUE)
    if (!length(a)) default else if (grepl("=", a[1])) sub("^--[^=]*=", "", a[1]) else TRUE
}
split.opt <- function(x) strsplit(x, ",", fixed=TRUE)[[1]]
known <- c("suites", "lib", "slow")
bad <- setdiff(sub("^--([^=]*).*", "\\1", grep("^--", args, value=TRUE)), known)
if (length(bad)) stop("unknown option(s): ", paste0("--", bad, collapse=", "))
SUITES  <- split.opt(opt("suites", "api,http,rawbody,tls,tlsclient,ws,simple"))
LIB     <- opt("lib")
SLOW    <- isTRUE(opt("slow", FALSE))
PATTERN <- paste(grep("^--", args, value=TRUE, invert=TRUE), collapse="|")

HERE <- local({
    a <- grep("^--file=", commandArgs(FALSE), value=TRUE)
    if (length(a)) dirname(normalizePath(sub("^--file=", "", a[1]))) else getwd()
})
if (!is.null(LIB)) {
    LIB <- normalizePath(LIB, mustWork=TRUE)
    .libPaths(c(LIB, .libPaths()))
}
suppressMessages(library(Rserve))
cat("Testing Rserve ", format(packageVersion("Rserve")), " from ", dirname(find.package("Rserve")),
    "\nR ", R.version$major, ".", R.version$minor, " (", R.version$platform, ")\n", sep="")

source(file.path(HERE, "helpers.R"))

## names of the tests in the files, so that suites without any tests matching
## the pattern don't have to start a server
matches <- function(label, files) {
    if (!nzchar(PATTERN)) return(TRUE)
    names <- unlist(lapply(files, function(f)
        regmatches(l <- readLines(file.path(HERE, f), warn=FALSE), regexpr('(?<=^test\\(")[^"]+', l, perl=TRUE))))
    any(grepl(PATTERN, paste0("[", label, "] ", names)))
}

## runs the test files with a fresh server started by `start' (a function
## returning the server or an error); each suite gets its own environment
## holding `vars'
run.suite <- function(label, files, start=NULL, skip=NULL, vars=list()) {
    if (!matches(label, files)) return(invisible())
    cat("\n==", label, "==\n")
    if (!is.null(skip)) {
        cat("skipped (", skip, ")\n", sep="")
        return(invisible())
    }
    CONTEXT <<- paste0("[", label, "] ")
    on.exit({ kill.server(); srv <<- NULL })
    if (!is.null(start)) {
        err <- tryCatch({ start(); NULL }, error=function(e) conditionMessage(e))
        if (!is.null(err)) {
            cat(err, "\n")
            results[paste0(CONTEXT, "server start")] <<- FALSE
            return(invisible())
        }
    }
    env <- list2env(vars, envir=new.env(parent=globalenv()))
    for (f in files) {
        err <- tryCatch({ source(file.path(HERE, f), local=env); NULL }, error=function(e) conditionMessage(e))
        if (!is.null(err)) {
            cat("Error in ", f, ": ", err, "\n", sep="")
            results[paste0(CONTEXT, f)] <<- FALSE
        }
    }
}

no.fork <- if (WIN) "needs fork(), not available on Windows"
## the TLS tests use the test certificates in ../tls/ and the openssl tool as the client
CERTS <- normalizePath(file.path(HERE, "..", "tls"), mustWork=FALSE)
OPENSSL <- Sys.getenv("OPENSSL", Sys.which("openssl"))
no.openssl <- if (!nzchar(OPENSSL)) "the openssl tool was not found (set OPENSSL)"
RSERVE.BIN <- local({ # the stand-alone Rserve binary
    d <- file.path(find.package("Rserve"), "libs", .Platform$r_arch)
    f <- file.path(d, if (WIN) "Rserve.exe" else "Rserve")
    if (file.exists(f)) f else ""
})
DOCROOT <- make.docroot()
tryCatch({
    if ("api" %in% SUITES)
        run.suite("api", "test-api.R")
    if ("http" %in% SUITES)
        run.suite("http", c("test-http.R", "test-conc.R"), function() start.server("server.R"))
    if ("rawbody" %in% SUITES)
        run.suite("rawbody", "test-rawbody.R", function() start.server("server.R", "--rawbody=1"))
    if ("tls" %in% SUITES)
        run.suite("tls", "test-tls.R", function() start.server("tls.R", paste0("--certs=", shQuote(CERTS))),
                  skip=no.openssl, vars=list(CLIENT=FALSE))
    if ("tlsclient" %in% SUITES)
        run.suite("tlsclient", "test-tls.R",
                  function() start.server("tls.R", c(paste0("--certs=", shQuote(CERTS)), "--client=match:xalice,alice,bob.example.org.x,bob.example.org")),
                  skip=no.openssl, vars=list(CLIENT=TRUE))
    if ("ws" %in% SUITES)
        run.suite("ws", "test-ws.R", function() start.server("ws.R"),
                  skip=if (WIN) "the WebSocket servers need fork()")
    if ("simple" %in% SUITES)
        run.suite("simple", "test-simple.R", function() start.binary(c("--RS-simple-http-only", shQuote(DOCROOT))),
                  skip=if (WIN) "stand-alone Rserve is not tested on Windows" else if (!nzchar(RSERVE.BIN)) "stand-alone Rserve binary not found")
}, finally={
    kill.server()
    unlink(dirname(DOCROOT), recursive=TRUE)
})

n.fail <- sum(!results)
cat(sprintf("\n%d tests, %d failed%s\n", length(results), n.fail,
            if (skipped) sprintf(", %d skipped", skipped) else ""))
if (n.fail) cat("Failed:\n", paste0("  ", names(results)[!results], "\n"), sep="")
quit(status=if (n.fail) 1L else 0L)
