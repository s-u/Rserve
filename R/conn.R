Rserve <- function(debug=FALSE, port, args=NULL, quote=(length(args) > 1), wait, ...) {
  args <- as.character(args)
  if (!isTRUE(quote) && length(args) > 1) args <- paste(args, collapse=' ')
  if (.Platform$OS.type == "windows") {
    arch <- .Platform$r_arch
    if (is.null(arch) || !nzchar(arch)) arch <- ""
    ffn <- if (debug) "Rserve_d.exe" else "Rserve.exe"
    fn <- shortPathName(if (nzchar(arch)) system.file("libs", arch, ffn, package="Rserve") else system.file(package="Rserve", ffn))
    if (!nchar(fn) || !file.exists(fn))
      stop("Cannot find ", ffn)
    else {
      if (!missing(port)) args <- c( args, "--RS-port", as.integer(port) )
      if (nzchar(arch)) arch <- paste("\\", arch, sep='')
      pad <- gsub("/", "\\", shortPathName(paste(R.home(),"\\bin",arch,";",sep='')), fixed=TRUE)
      if (charmatch(pad, Sys.getenv("PATH"), nomatch=0) == 0)
        Sys.setenv(PATH=paste(pad, Sys.getenv("PATH"), sep=''))
      fn <- if (isTRUE(quote)) paste(shQuote(c(fn, args), "cmd"), collapse=' ') else paste(shQuote(fn, "cmd"), paste(args, collapse=' '))
      cat("Starting Rserve...\n", fn, "\n")
      if (missing(wait)) wait <- FALSE
      return(invisible(system(fn, wait=wait, ...)))
    }
  }
  name <- if (!debug) "Rserve" else "Rserve.dbg"
  fn <- system.file(package="Rserve", "libs", .Platform$r_arch, name)
  if (!nchar(fn)) fn <- name
  if (!missing(port)) args <- c( args, "--RS-port", as.integer(port) )
  if (length(args)) fn <- paste(fn, paste(if (isTRUE(quote)) shQuote(args, "sh") else args, collapse=' '))
  cmd <- paste(file.path(R.home(),"bin","R"), "CMD", fn)
  if (!missing(port))
    cat("Starting Rserve on port", port, ":\n",cmd,"\n\n")
  else
    cat("Starting Rserve:\n",cmd,"\n\n")
  if (debug)
    cat("Note: debug version of Rserve doesn't daemonize so your R session will be blocked until you shut down Rserve.\n")
  if (missing(wait)) wait <- TRUE
  invisible(system(cmd, wait=wait, ...))
}

run.Rserve <- function(..., config.file="/etc/Rserve.conf") {
  if (is.null(run_Rserve)) stop("Runnig inside an embedded Rserve instance - starting Rserve recursively is not supported")
  .Call(run_Rserve, as.character(config.file), sapply(list(...), as.character))
}

self.ctrlEval <- function(expr) {
  if (!is.loaded("Rserve_ctrlEval")) stop("This command can only be run inside Rserve with r-control enabled")
  if (is.language(expr)) expr <- deparse(expr)
  if (!is.character(expr)) stop("expr must me a character vector, name, call or an expression")
  call <- getNativeSymbolInfo("Rserve_ctrlEval")
  invisible(.Call(call, paste(expr, collapse='\n')))
}

self.ctrlSource <- function(file) {
  if (!is.loaded("Rserve_ctrlSource")) stop("This command can only be run inside Rserve with r-control enabled")
  if (!is.character(file) || length(file) != 1) stop("`file' must be a string")
  call <- getNativeSymbolInfo("Rserve_ctrlSource")
  invisible(.Call(call, file))
}

self.oobSend <- function(what, code = 0L) {
  if (!is.loaded("Rserve_oobSend")) stop("This command can only be run inside Rserve with oob enabled")
  call <- getNativeSymbolInfo("Rserve_oobSend")
  invisible(.Call(call, what, code))
}

self.oobMessage <- function(what, code = 0L) {
  if (!is.loaded("Rserve_oobMsg")) stop("This command can only be run inside Rserve with oob enabled")
  call <- getNativeSymbolInfo("Rserve_oobMsg")
  invisible(.Call(call, what, code))
}

ocap <- function(fun, name=deparse(substitute(fun)))
  .Call(Rserve_oc_register, fun, name)

resolve.ocap <- function(ocap)
  .Call(Rserve_oc_resolve, ocap)
