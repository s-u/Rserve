\name{ulog}
\title{Micro Logging}
\alias{ulog}
\usage{
ulog(...)
}
\description{
  \code{ulog} logs the supplied message using the \code{ulog}
  facility which typically corresponsed to syslog. See \code{ulog}
  Rserve configuration for the various endpoints supported by ulog
  (local, UDP/TCP remote, ...).

  This function is guaranteed to be silent regardless of the ulog
  setting and is intended to have minimal performance impact.

  Note: if Rserve is compiled with \code{-DULOG_STDERR} (also
  implied in the debug build) then ulog messages are also emitted
  on \code{stderr} with \code{"ULOG: "} prefix.

  Please note that this \code{ulog} function is governed by the Rserve
  settings, and NOT the \code{ulog} package settings. The latter is a
  general port of the \code{ulog} logging facility to R, while
  \code{Rserve::ulog} is specific to to the Rserve process.
}
\arguments{
  \item{...}{message to log}
}
\value{
  The logged string constructed from the message, invisibly
}
\examples{
ulog("INFO: My application started")
}
\author{Simon Urbanek}
\keyword{interface}
