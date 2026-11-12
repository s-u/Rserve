## Fixture for test-ws.R: HTTP with WebSocket upgrade on port, the
## stand-alone WebSocket server on port + 1 (both QAP and text protocols).
## Usage: Rscript ws.R --port=<port> --docroot=<dir> [--lib=<lib>]
args <- commandArgs(TRUE)
arg <- function(name, default=NULL) {
    a <- grep(paste0("^--", name, "="), args, value=TRUE)
    if (length(a)) sub("^--[^=]*=", "", a[1]) else default
}
if (!is.null(arg("lib"))) .libPaths(c(arg("lib"), .libPaths()))
cat("PID", Sys.getpid(), "\n"); flush(stdout()) # the driver needs the pid of the R process
port    <- as.integer(arg("port"))

library(Rserve)
.http.request <- function(url, query, body, headers)
    list(paste0("http:", url), "text/plain")
run.Rserve(http.port=port, websockets.port=port + 1L, websockets="enable", http.upgrade.websockets="enable",
           qap=FALSE, config.file=tempfile())
