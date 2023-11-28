\name{ocap}
\title{Object Capability (OCAP) Functions}
\alias{ocap}
\alias{resolve.ocap}
\alias{Rserve.context}
\usage{
ocap(fun, name = deparse(substitute(fun)))
resolve.ocap(ocap)
Rserve.context(what)
}
\description{
  The following functions are only meaningful when used by code that
  is run inside Rserve in object-capability (OCAP) mode.
  See \href{https://github.com/s-u/Rserve/wiki/OCAP-mode}{Rserve Wiki}
  for details.

  \code{ocap} registers a function as a capability and returns the
  reference.

  \code{resolve.ocap} takes a capability reference and returns the
  function representing the capability.

  \code{Rserve.context} retrieves or sets the current context for
  out-of-band (OOB) messages (see also \code{\link{Rserve.eval}} for
  specifying contexts during evaluation).
}
\arguments{
  \item{fun}{function to register}
  \item{name}{description of the function, only for informational and
  logging purposes}
  \item{ocap}{reference previously obtained by a call to \code{ocap}}
  \item{what}{if present, sets the context to the supplied value. If
  missing, the function returns the current context}
}
\value{
  \code{ocap} returns the new capability reference, it will be an
  object of the class \code{"OCref"}.

  \code{resolve.ocap} returns the function corresponding to the
  reference or \code{NULL} if the reference does not exist. It will
  raise an error if \code{ocap} is not a valid \code{"OCref"} object.

  \code{Rserve.context} returns the current context
}
%\examples{
%}
\author{Simon Urbanek}
\keyword{interface}
