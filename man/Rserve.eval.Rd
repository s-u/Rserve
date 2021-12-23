\name{Rserve.eval}
\alias{Rserve.eval}
\title{Evaluate expressions in a REPL-like fashion}
\description{
  \code{Rserve.eval} evaluates a given expression in a way that is very
  close to the behavior on the console Read/Evaluate/Print Loop (REPL).
  Among other things this means printing the result of each expression
  if visible. The function is guaranteed to not raise an error and in
  case of an error it returns an object of class
  \code{Rserve-eval-error} with details including the error and the
  stack trace.
}
\usage{
Rserve.eval(what, where = .GlobalEnv, last.value = FALSE, exp.value = FALSE,
            context = NULL, handlers = list(error=.save.condition))
}
\arguments{
  \item{what}{expressions to evaluate}
  \item{where}{environment to evaluate in}
  \item{last.value}{logical, if \code{TRUE} then the result of the
    evaluation is returned, otherwise the evaluation is only performed
    for its side-efects and returns \code{TRUE} instead.}
  \item{exp.value}{logical, it \code{TRUE} then an error object will
    include the actual expression that triggered the error, otherwise
    it will only store the index of the expression in \code{what}.}
  \item{context}{optional object that will be used as the Rserve context
    for the duration of the evaluation
    (see \code{\link{Rserve.context}}).}
  \item{handlers}{optional named list of calling handlers to register
    for the duration of the evaluation. The default is to register an
    \code{error} handlers which stores the error condition so it can
    be reported in the result - see below.}
}
\details{
  If \code{what} contains one or more expressions, they are evaluated
  one by one while printing the result of each if visible. Upon error
  subsequent expressions are not evaluated. If \code{what} is not an
  expression then the only a single evaluation of \code{what} is
  performed and the result is not printed.

  The main purpose of this function is to implement console front-ends
  where the front-end uses \code{parse()} + \code{Rserve.eval()} to
  simulate the action of a GUI. Because the function returns in all
  circumstances it allows clients to rely on a well-define messaging
  behavior.
}
\value{
  If the evaluation triggered an error, the result is an object of class
  \code{Rserve-eval-error} with components:
  \item{error}{character, error message}
  \item{traceback}{list of contexts in the traceback}
  \item{expression}{if \code{what} contains multiple expressions then
  this will be either an index to the expression that caused the error
  (\code{exp.value=FALSE}) or the actual expression (otherwise).}
  \item{context}{current Rserve context, \code{NULL} if none has been set}
  \item{condition}{if any condition has been saved via
    \code{.save.condition} (which is the default) then on error the
    captured condition object is stored here, \code{NULL} otherwise}

  If the evaluation finished without an error then the result is either
  \code{TRUE} if \code{last.value=FALSE} or the value of the last
  expression otherwise.
}
\note{
  Rserve versions up to 1.8-10 did not include the \code{condition}
  component, no calling handlers were registered and there was no
  \code{condition} component in the result. To replicate that behavior
  or if you don't need that information, you can set
  \code{handlers=NULL} which removes the overhead of adding calling
  handlers.

  No error checking is performed on the
  \code{handlers} parameter, so make sure it is avalid, named list of
  functions, otherwise an error will occur at evaluation time.
}
\author{
  Simon Urbanek
}
\examples{
  g <- function() stop("foo")
  f <- function() g()
  (Rserve.eval(expression(f())))
  (Rserve.eval(parse(text="1:5\n1+1")))
  (Rserve.eval(quote(1+1), last.value=TRUE))

  error_with_condition = function(object = NULL) {
    cond = errorCondition("this is a custom error with condition",
                          object = object, 
                          class = "CustomError")
    stop(cond)
  }
  str(Rserve.eval(quote(error_with_condition("hello")), last.value = TRUE))
}
\keyword{manip}
