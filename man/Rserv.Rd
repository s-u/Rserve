\name{Rserve}
\title{Server providing R functionality to applications via TCP/IP or local unix sockets}
\alias{Rserve}
\usage{
# R CMD Rserve [<parameters>]

Rserve(debug = FALSE, port, args = NULL, quote=(length(args) > 1), wait, ...)
}
\description{
Starts Rserve in daemon mode (unix only). Any additional parameters
not related to Rserve will be passed straight to the underlying R. For
configuration, usage and command line parameters please consult the
online documentation at http://www.rforge.net/Rserve.
Use \code{R CMD Rserve --help} for a brief help.

The \code{Rserve} function is provided for convenience only.

On Windows the \code{Rserve()} function sets up the \code{PATH} to
include the current R.DLL so that Rserve can be run.
}
\arguments{
\item{debug}{determines whether regular Rserve or debug version of
  Rserve (\code{Rserve.dbg}) should be started.}
\item{port}{port used by Rserve to listen for connections. If not
  specified, it will be taken from the configuration file (if present)
  or default to 6311}
\item{args}{further arguments passed to Rserve (as a string that will be
  passed to the \code{system} command - see \code{quote} below).}
\item{quote}{logical, if \code{TRUE} then arguments are quoted,
  otherwise they are just joined with spaces}
\item{wait}{wait argument for the \code{\link{system}} call. It defaults
  to \code{FALSE} on Windows and \code{TRUE} elsewhere.}
\item{\dots}{other arguments to be passes to \code{\link{system}}.}
}
\details{
  Rserve is not just a package, but an application. It is provided as a
  R package for convenience only. For details see
  http://www.rforge.net/Rserve
}
\note{
  \code{R CMD Rserve} will only work on unix when installed from
  \emph{sources} and with sufficient permissions to have write-rights in
  \code{$R_HOME/bin}. Binary installations have no way to write in
  \code{$R_HOME/bin} and thus \code{Rserve()} function described above
  is the only reliable way to start \code{Rserve} in that case.

  Java developers may want to see the \code{StartRserve} class in
  \code{java/Rserve/test} examples for easy way to start \code{Rserve}
  from Java.

  Rserve can be compiled with TLS/SSL support based on
  OpenSSL. Therefore the following statements may be true if Rserve
  binaries are shipped together with OpenSSL: This product includes
  software developed by the OpenSSL Project for use in the OpenSSL
  Toolkit (http://www.openssl.org/). This product includes cryptographic
  software written by Eric Young (eay@cryptsoft.com). This product
  includes software written by Tim Hudson (tjh@cryptsoft.com). They are
  not true otherwise.    
}
\seealso{\code{\link{run.Rserve}}}
\author{Simon Urbanek}
\keyword{interface}
