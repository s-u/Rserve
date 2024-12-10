\name{Rserve.http.add.static}
\alias{Rserve.http.add.static}
\alias{Rserve.http.rm.all.statics}
\title{
  Add static file handler to HTTP/HTTPS server
}
\description{
  \code{Rserve.http.add.static} installs a new static handler to be used by the
  HTTP/HTTPS servers. It will trigger only if the path prefix matches \code{prefix}
  and will map the subsequent portion of the path in the request URL to a file
  system location specified by \code{path}. If the resulting item in the file system
  is a directory, then \code{index} (if set) will be appended to the path and served
  instead (if it is a file).

  \code{Rserve.http.rm.all.statics} removes all static handlers from the current
  R session.
}
\usage{
Rserve.http.add.static(prefix, path, index = NULL, last = FALSE)
Rserve.http.rm.all.statics()
}
\arguments{
  \item{prefix}{string, path prefix for which this handler will be used}
  \item{path}{string, path in the filesystem used as root to serve the content}
  \item{index}{optional string, will be appended to the file system path if
  the target is a directory (typical value is \code{"index.html"}).}
  \item{last}{logical, if \code{FALSE} then processing continues to other handlers
  if the target does not exist. If \code{TRUE} then all requests for the prefix
  will be handled only by this handler, possible resulting in "404 not found"
  result if the reqeusted file does not exist.}
}
\details{
  The HTTP/HTTPS server supports both static and dynamic handlers. The typical use
  is to invoke \code{.http.request} function in R for dynamic handling, but it also
  supports static maps of URL paths to file system locations. The static handlers
  are checked first.

  \code{Rserve.http.add.static} installs a new static handler, adding it to the
  list of handlers. The handlers are consulted in the order that they are added.

  The static handler supports conditional GETs and relies on the file system
  modification times to determine if a file has been modified.
}
\value{
  The return value is considered experimental and may change in the future:
  Integer, number of active handlers (which is the same as the index of this handler).
}
\author{
 Simon Urbanek
}
\examples{
## standard handler serving all files in the current working directory
## and consults index.html in directories if no file is specified.
Rserve.http.add.static("/", getwd(), "index.html", TRUE)

## start the server with:
##   run.Rserve(http.port=8080, qap=FALSE)
}
\seealso{\code{\link{run.Rserve}}}
\keyword{interface}
