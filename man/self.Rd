\name{self}
\title{Functions usable for R code run inside Rserve}
\alias{self.ctrlEval}
\alias{self.ctrlSource}
\usage{
self.ctrlEval(expr)
self.ctrlSource(file)
}
\description{
  The following functions can only be used inside Rserve, they cannot be
  used in stand-alone R. They interact with special features of Rserve.
  All commands below will succeed only if Rserve has been started with
  \code{r-control enable} configuration setting for security reasons.
  
  \code{self.ctrlEval} issues a control command to the Rserve parent
  instance that evaluates the given expression in the server. The
  expression is only queued for evaluation which will happen
  asynchronously in the server (see \code{\link{RSserverEval}} for
  details). Note that the current session is unaffected by the command.

  \code{self.ctrlSource} issues a control command to the Rserve parent
  instance to source the given file in the server, see
  \code{\link{RSserverSource}} for details.
}
\arguments{
  \item{expr}{R expression to evaluate remotely}
  \item{file}{path to a file that will be sourced into the main instance}
}
\value{
  Both functions return \code{TRUE} (invisibly).
}
\examples{
\dontrun{
  self.ctrlEval("a <- rnorm(10)")
}
}
\author{Simon Urbanek}
\keyword{interface}
