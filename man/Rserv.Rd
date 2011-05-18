\name{Rserve}
\title{Server providing R functionality to applications via TCP/IP or local unix sockets}
\alias{Rserve}
\usage{
# R CMD Rserve [<parameters>]

Rserve(debug = FALSE, port = 6311, args = NULL, quote=(length(args) > 1), wait, ...)
}
\synopsis{
Rserve(debug = FALSE, port = 6311, args = NULL, quote=(length(args) > 1), wait, ...)
}
\description{
Starts Rserve in daemon mode (unix only). Any additional parameters
not related to Rserve will be passed straight to the underlying R. For
configuration, usage and command line parameters please consult the
online documentation at http://www.rforge.net/Rserve.
Use \code{R CMD Rserve --help} for a brief help.

The \code{Rserve} function is provided for convenience only, it is
recommended to start Rserve directly from the command line, not from R
itself. Also note that the debug version of Rserve doesn't fork and thus
will block until closed.

On Windows the \code{Rserve()} function sets up the PATH to include the
current R.DLL so that Rserve can be run.
}
\arguments{
\item{debug}{determines whether regular Rserve or debug version of
  Rserve (\code{Rserve.dbg}) should be started.}
\item{port}{port used by Rserve to listen for connections}
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
\author{Simon Urbanek}
\keyword{interface}
