\name{Rserve}
\title{Server providing R functionality to applications via TCP/IP or local unix sockets}
\alias{Rserve}
\usage{
R CMD Rserve [<parameters>]
}
\description{
Starts R server in daemon mode (unix only). Any additional parameters
not related to Rserve will be passed straight to the underlying R. For
configuration, usage and command line parameters please consult the
online documentation at http://www.rosuda.org/Rserve. Use \code{R CMD Rserve
--help} for a brief help.
}
\arguments{
}
\details{
Rserve is not a library, but an application. It is provided as a R package for convenience only. For details see http://www.rosuda.org/Rserve
}
\author{Simon Urbanek}
\keyword{Rserve}
