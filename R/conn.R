Rserve <- function(debug=FALSE, port=6311, args=NULL) {
  if (.Platform$OS.type == "windows") {
    ffn <- if (debug) "Rserve_d.exe" else "Rserve.exe"
    fn <- system.file(package="Rserve", ffn)
    if (!nchar(fn) || !file.exists(fn))
      stop("Cannot find ", ffn)
    else {
      if ( port != 6311 ) fn <- paste( fn, "--RS-port", port )
      if ( !is.null(args) ) fn <- paste(fn, paste(args, collapse=' '))

      pad <- paste(R.home(),"\\bin;",sep='')
      if (!exists("Sys.setenv")) Sys.setenv <- Sys.putenv
      if (charmatch(pad, Sys.getenv("PATH"), nomatch=0) == 0)
        Sys.setenv(PATH=paste(pad, Sys.getenv("PATH"), sep=''))
      
      cat("Starting Rserve...\n", fn)
      system(fn, wait=FALSE)
      return(invisible(NULL))
    }
  }
  name <- if (!debug) "Rserve-bin.so" else "Rserve-dbg.so"
  fn <- system.file(package="Rserve", "libs", .Platform$r_arch, name)
  if (!nchar(fn)) fn <- if (!debug) "Rserve" else "Rserve.dbg"
  if ( port != 6311 ) fn <- paste( fn, "--RS-port", port )
  if ( !is.null(args) ) fn <- paste(fn, paste(args, collapse=' '))
  cmd <- paste(file.path(R.home(),"bin","R"),"CMD",fn)
  cat("Starting Rserve on port", port, ":\n",cmd,"\n\n")
  if (debug)
    cat("Note: debug version of Rserve doesn't daemonize so your R session will be blocked until you shut down Rserve.\n")
  system(cmd)
}

RSconnect <- function(host="localhost", port=6311) {
  c <- socketConnection(host,port,open="a+b",blocking=TRUE)
  a <- readBin(c,"raw",32)
  if (!length(a)) { close(c); stop("Attempt to connect to Rserve timed out, connection closed") }
  if (length(a) != 32 || !length(grep("^Rsrv01..QAP1",rawToChar(a))))
    stop("Invalid response from Rserve")
  return( c )
}

RSeval <- function(c, expr) {
  r <- if (is.character(expr)) serialize(parse(text=paste("{",paste(expr,collapse="\n"),"}"))[[1]],NULL) else serialize(expr, NULL)
  writeBin(c(0xf5L, length(r), 0L, 0L), c, endian="little")
  writeBin(r, c)
  b <- readBin(c,"int",4,signed=FALSE,endian="little")
  if (length(b)<4 || b[1] != 65537L) stop("remote evaluation failed")
  unserialize(readBin(c,"raw",b[2]))
}

RSassign <- function (c, obj, name = deparse(substitute(obj))) {
  r <- serialize(list(name, obj), NULL)
  writeBin(c(0xf6L,length(r),0L,0L), c, endian="little")
  writeBin(r, c)
  b <- readBin(c,"int",4,signed=FALSE,endian="little")
  if (length(b)<4 || b[1] != 65537L)
    stop("remote assign failed")
  invisible(obj)
}

RSclose <- function(c) close(c)

#--- the following code is VERY UNSAFE! It was used for a limited
#    purpose and donated by a good soul, but exact bitwise operations
#    are not supported by R, so it works only in a small range of
#    supported data. Also it makes some assumptions about the setup.


RSeval.old <- function(c, cmd) {
  r <- paste("serialize({", cmd[1], "},NULL)")
  sc <- charToRaw(as.character(r)[1])
  l <- length(sc) + 1
  writeBin(as.integer(c(3,l+4,0,0,4+l*256)), c, endian="little")
  writeBin(sc, c)
  writeBin(raw(1), c)
  b <- readBin(c,"int",4,signed=FALSE,endian="little")
  if (!length(b)) { close(c); stop("Rserve connection timed out and closed") }
  ##cat("header: ",b[1],", ",b[2],"\n")
  if (b[1]%%256 == 2 || b[2] < 12) stop("Eval failed with error: ",b[1]%/%0x1000000)
  a <- readBin(c,"int",3,signed=FALSE,endian="little")
  rawLen <- a[3]
  isLarge <- (a[1]%/%0x40000000)%%1
  prefix <- 12
  plt <- a[1]%%256
  sexpt <- a[2]%%256
  if (isLarge != 0) {
    isRawLarge <- (a[3]%/%0x40000000)%%1
    aa <- readBin(c, "int", 1+isRawLarge, signed=FALSE, endian="little")
    rawLen <- aa[1+isRawLarge]
    prefix <- 16+isRawLarge*4
    sexpt <- a[3]%%256
  }
  if (plt != 10)
    stop("Invalid response from eval, got return type ",plt," but expected 10 (SEXP)")
  if (sexpt != 0x25)
    stop("Invalid object from eval, got ",sexpt," but expected 37 (raw vector from serialization)")
  rp <- readBin(c,"raw",rawLen)
  ## read any padding that was there
  if (rawLen < b[2]-prefix) readBin(c,"raw",b[2]-prefix-rawLen)
  unserialize(rp)
}

# convert an array of unsigned integers into raw verctor safely
# by converting 16-bits at a time
.safe.int <- function(data) {
  r <- raw(length(data) * 4)
  j <- 1
  for (i in data) {
    hi <- as.integer(i / 0x10000 + 0.5)
    lo <- as.integer( (i - hi*0x10000) + 0.5)
    rs <- writeBin(c(lo, hi), raw(), endian="little")
    r[j] <- rs[1]
    r[j+1] <- rs[2]
    r[j+2] <- rs[5]
    r[j+3] <- rs[6]
    j <- j + 4
  }
  r
}

RSassign.old <- function ( c, obj, name = deparse(substitute(obj)) ) {
  so <- serialize(list(name=name, obj=obj), NULL)
  large <- (length(so) > 0x800000)
  if (large) stop("Cannot assign objects larger than 8MB.")
  ## the problem: R doesn't handle unsigned int and thus anything larger that 8MB
  ## will result in msb to be set and thus R will use NA instead, thinking it's an overflow
  ## .safe.int is supposed to work around it, but soemhow it's still not happy ...
  if (is.character(so)) so <- charToRaw(so)
  rn <- charToRaw(".tmp.RS.assign")
  sl <- length(rn) + 1
  slp <- sl %% 4
  if (slp) slp <- 4 - slp
  sl <- sl + slp

  # [DT_STR]<name><pad>[DT_SEXP][XT_RAW]<len><raw>
  
  pks <- 4 + sl + 8 + 4 + length(so)
  if (large) pks <- pks + 4
  ladd <- if (large) 8 else 0
  #cat("packet size:", (pks+ladd), "\n")
  
  writeBin(as.integer(c(0x20, pks + ladd, 0, 0, 4 + sl*256)), c, endian="little")
  writeBin(rn, c)
  writeBin(raw(slp+1), c)
  if (large) {
    lo <- length(so) %% 0x1000000
    hi <- length(so) / 0x1000000
    lo <- lo * 256 + 0x40
    writeBin(.safe.int(c(lo + 0xc0a, hi, lo + 0x425, hi, length(so))), c, endian="little")
  } else {
    writeBin(as.integer(c(0xa + (8 + length(so)) * 256 , 37 + (4 + length(so)) * 256, length(so))), c, endian="little")
  }
  #cat("writing data..\n")
  writeBin(so, c)
  #cat("awaiting response...\n")
  
  b <- readBin(c,"int",4,signed=FALSE,endian="little")
  if (!length(b)) { close(c); stop("Rserve connection timed out and closed") }
  #cat("header: ",b[1],", ",b[2],"\n")    
  msgLen <- b[2]
  if (msgLen > 0) a <- readBin(c,"raw",msgLen)
  if (b[1]%%256 != 1) stop("Assign failed with error: ",b[1]%/%0x1000000)
  RSeval(c, paste(".tmp.RS.assign<-unserialize(.tmp.RS.assign); assign(.tmp.RS.assign$name, .tmp.RS.assign$obj); rm(.tmp.RS.assign); TRUE", sep=''))
}

RSdetach <- function( c ) RSevalDetach( c, "" )

RSevalDetach <- function( c, cmd="" ) {
  # retrieve the host name from the connection (possibly unsafe!)
  host <- substr(strsplit(summary(c)$description,":")[[1]][1],3,999)
  if ( cmd != "" ) {
    r <- paste("serialize({", cmd[1], "},NULL)")
    l <- nchar(r[1])+1
    writeBin(as.integer(c(0x031,l+4,0,0,4+l*256)), c, endian="little")
    writeBin(as.character(r[1]), c)
    b <- readBin(c,"int",4,signed=FALSE,endian="little")
    if (b[1]%%256 == 2 || b[2] < 12) stop("Eval/detach failed with error: ",b[1]%/%0x1000000)
    ## We don't need "isLarge" because we never get large data back
  } else {
    l <- 0
    writeBin(as.integer(c(0x030,l+4,0,0,4+l*256)), c, endian="little")
    b <- readBin(c,"int",4,signed=FALSE,endian="little")
    if (b[1]%%256 != 1) stop("Detach failed with error: ",b[1]%/%0x1000000)
  }
  msgLen <- b[1]%/%256
  a <- readBin(c,"int",2,signed=FALSE,endian="little")
  if (!length(a)) { close(c); stop("Rserve connection timed out and closed") }
  ## a[1] is DT_INT, a[2] is the payload (port#)
  port <- a[ 2 ]
  readBin(c,"raw",4) ## this should be DT_BYTESTREAM
  key <- readBin(c,"raw",msgLen-12)
  RSclose(c)
  list( port=port, key=key, host=host )
}

RSattach <- function(session) {
  c <- socketConnection(session$host,session$port,open="a+b",blocking=TRUE)
  writeBin( session$key, c )
  b <- readBin(c,"int",4,signed=FALSE,endian="little")
  if (!length(b)) { close(c); stop("Rserve connection timed out and closed") }
  if (b[1]%%256 != 1) stop("Attach failed with error: ",b[1]%/%0x1000000)
  c
}

RSlogin <- function(c, user, pwd, silent=FALSE) {
  r <- paste(user,pwd,sep="\n")
  l <- nchar(r[1])+1
  writeBin(as.integer(c(1,l+4,0,0,4+l*256)), c, endian="little")
  writeBin(as.character(r[1]), c)
  b <- readBin(c,"int",4,signed=FALSE,endian="little")
  if (!length(b)) { close(c); stop("Rserve connection timed out and closed") }
  ##cat("header: ",b[1],", ",b[2],"\n")    
  msgLen <- b[2]
  if (msgLen > 0) a <- readBin(c,"raw",msgLen)
  if (b[1]%%256 != 1 && !silent) stop("Login failed with error: ",b[1]%/%0x1000000)
  invisible(b[1]%%256 == 1)
}

RSshutdown <- function(c, pwd=NULL) {
  # FIXME: we ignore pwd and don't check error status
  writeBin(as.integer(c(4, 0, 0, 0)), c, endian="little")
}
