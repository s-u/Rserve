\name{Rclient}
\title{Functions to talk to an Rserve}
\alias{RSconnect}
\alias{RSclose}
\alias{RSeval}
\alias{RSeval.old}
\alias{RSlogin}
\alias{RSdetach}
\alias{RSevalDetach}
\alias{RSattach}
\alias{RSassign}
\alias{RSassign.old}
\alias{RSshutdown}
\usage{
RSconnect(host = "localhost", port = 6311)
RSlogin(c, user, pwd, silent = FALSE)
RSeval(c, expr)
RSeval.old(c, cmd)
RSclose(c)
RSshutdown(c, pwd = NULL)
RSdetach(c)
RSevalDetach(c, cmd = "")
RSattach(session)
RSassign(c, obj, name = deparse(substitute(obj)) )
RSassign.old(c, obj, name = deparse(substitute(obj)) )
}
\description{
  Rserve is a server providing R functionality via sockets. The
  following functions allow another R session to start new Rserve
  sessions and evaluate commands. The support is very rudimentary and
  uses only a fraction of the funtionality provided by Rserve. The
  typical use of Rserve is to connect to other applications, not
  necessarily to connect two R processes. However, it is not uncommon to
  have a cluster of Rserve machines so the following functions provide a
  simple client access.

  For more complete cilent implementation see \code{src/clients}
  directory of the Rserve distribution which show a C/C++ client. Also
  available from the Rserve pages is a Java client
  (\code{JRclient}). See \code{http://rosuda.org/Rserve} for details.
}
\arguments{
  \item{host}{host to connect to}
  \item{port}{TCP port to connect to}
  \item{c}{Rserve connection}
  \item{user}{username for authentication}
  \item{pwd}{password for authentication}
  \item{cmd}{command (as string) to evaluate}
  \item{silent}{flag indicating whether a failure should raise an error
    or not}
  \item{session}{session object as returned by \code{RSdetach} or
    \code{RSevalDetach}}
  \item{obj}{value to assign}
  \item{name}{name to assign to on the remote side}
  \item{expr}{R expression to evaluate remotely}
}
\details{
  \code{RSconnect} creates a connection to a Rserve. The returned handle
  is to be used in all subsequent calls to client functions. The session
  associated witht he connection is alive until closed via
  \code{RSclose}.

  \code{RSlogin} performs authentication with the Rserve. Currently this
  simple client supports only plain text authentication, encryption is
  not supported.

  \code{RSclose} closes the Rserve connection.

  \code{RSeval} evaluates the supplied expression
  remotely. \code{expr} can be either a string or any R
  expression. Use \code{\link{quote}} to use unevaluated
  expressions. The implementation of \code{RSeval} is very efficient
  in that it does not require any buffer on the remote side and uses
  native R serialization as the protocol. See exmples below for
  correct use.

  \code{RSeval.old} is deprecated and present only for compatibility
  with older Rserve implementations. It evaluates the string in the
  remote Rserve and returns
  the result. Note that you will have to load the same packages on both
  ends if the result is an (S3/S4) object such that corresponding
  classes and methods are available. Also note that the result is
  transported on the network so sending huge results can be slow. Thus
  consider sending only relebant parts or keep the results on the other
  end if pertinent.

  \code{RSdetach} detaches from the current Rserve connection. The
  connection is closed but can be restored by using \code{RSattach} with
  the value returned by \code{RSdetach}. Technically the R on the other
  end is still running and waiting to be atached.

  \code{RSshutdown} terminates the server gracefully. It should be
  immediately followed by \code{RSclose} since the server closes the
  connection. It can be issued only on a valid (authenticated)
  connection. The password parameter is currently ignored since
  password-protected shutdown is not yet supported. Please note that
  you should not terminate servers that you did not start.

  \code{RSevalDetach} same as \code{RSdetach} but allows asynchronous
  evaluation of the command. The remote Rserve is instructed to evaluate
  the command after the connection is detached. Please note that the
  session cannot be attached until the evaluation finished. Therefore it
  is advisable to use another session when attaching to verify the
  status of the detached session where necessary.

  \code{RSattach} resume connection to an existing session in
  Rserve. The \code{session} argument must have been previously returned
  from the \code{RSdetach} or \code{RSevalDetach} comment.

  \code{RSassign} pushes an object to Rserve and assigns it to the given
  name. Note that the name can be an (unevaluated) R expression itself
  thus allowing constructs such as \code{RSassign(c, 1:5,
  quote(a$foo))} which will result in \code{a$foo <- 1:5}
  remotely. However, character names are interpreted literarly.
}
\examples{
\dontrun{
  c <- RSconnect()
  data(stackloss)
  RSassign(c, stackloss)
  RSeval(c, quote(library(MASS)))
  RSeval(c, quote(rlm(stack.loss ~ ., stackloss)$coeff))
  RSeval(c, "getwd()")
  
  image <- RSeval(c, quote(try({
    attach(stackloss)
    library(Cairo)
    Cairo(file="plot.png")
    plot(Air.Flow,stack.loss,col=2,pch=19,cex=2)
    dev.off()
    readBin("plot.png", "raw", 999999)})))
  if (inherits(image, "try-error"))
    stop(image)
}
}
\author{Simon Urbanek}
\keyword{interface}
