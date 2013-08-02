\name{self}
\title{Functions usable for R code run inside Rserve}
\alias{self.ctrlEval}
\alias{self.ctrlSource}
\alias{self.oobSend}
\alias{self.oobMessage}
\usage{
self.ctrlEval(expr)
self.ctrlSource(file)
self.oobSend(what, code = 0L)
self.oobMessage(what, code = 0L)
}
\description{
  The following functions can only be used inside Rserve, they cannot be
  used in stand-alone R. They interact with special features of Rserve.
  All commands below will succeed only if Rserve has been started with
  \code{r-control enable} configuration setting for security reasons.
  
  \code{self.ctrlEval} issues a control command to the Rserve parent
  instance that evaluates the given expression in the server. The
  expression is only queued for evaluation which will happen
  asynchronously in the server (see \code{RSserverEval} in
  \code{RSclient} package for details). Note that the current session is
  unaffected by the command.

  \code{self.ctrlSource} issues a control command to the Rserve parent
  instance to source the given file in the server, see
  \code{RSserverSource} in the \code{RSclient} package for details.

  \code{self.oobSend} sends a out-of-band (OOB) message with the encoded
  content of \code{what} to the client connected to this session. The
  OOB facility must be enabled in the Rserve configuration (using
  \code{oob enable}) and the client must support OOB messages for this
  to be meaningful. This facility is not used by Rserve itself, it is
  offered to specialized applications (e.g. \code{Cairo} supports
  asynchronous notification of web clients using WebSockets-QAP1 tunnel
  to dynamically update graphics on the web during evaluation).

  \code{self.oobMessage} is like \code{self.oobSend} except that it
  waits for a response and returns the response.
}
\arguments{
  \item{expr}{R expression to evaluate remotely}
  \item{file}{path to a file that will be sourced into the main
    instance}
  \item{what}{object to include as the payload fo the message}
  \item{code}{user-defined message code that will be ORed with the
  \code{OOB_SEND}/\code{OOB_MSG} message code}
}
\value{
  \code{oobMessage} returns data contained in the response message.
  
  All other functions return \code{TRUE} (invisibly).
}
\examples{
\dontrun{
  self.ctrlEval("a <- rnorm(10)")
  self.oobSend(list("url","http://foo/bar"))
}
}
\author{Simon Urbanek}
\keyword{interface}
