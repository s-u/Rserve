\name{run.Rserve}
\alias{run.Rserve}
\title{
  Start Rserve within the current R process.
}
\description{
  \code{run.Rserve} makes the current R process into an Rserve
  instance. Rserve takes over until it is shut down or receives a user
  interrupt signal. The main difference between \code{\link{Rserve}} and
  \code{run.Rserve} is that \code{Rserve} starts a new process, whereas
  \code{run.Rserve} turns the current R session into Rserve. This is only
  possible if there are no UI elements or other parts that could
  interfere with the prepation of \code{Rserve}.
}
\usage{
run.Rserve(..., config.file = "/etc/Rserve.conf")
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{\dots}{
    all named arguments are treated as entries that would be otherwise
    present in the configuration file. So argument \code{foo="bar"}
    has the same meaning as \code{foo bar} in the configuration
    file. The only exception is that logical values can be used instead
    of \code{enable}/\code{disable}. Some settings such as \code{uid} are
    not relevant and thus ignored.
  }
  \item{config.file}{
    path of the configuration file to load in the Rserve. It will be
    loaded before the above settings and is optional, i.e. if the
    file is not present or readable it will be ignored.
  }
}
%\details{
%}
\value{
  Returns \code{TRUE} after the Rserve was shut down.
}
%\references{
%}
\author{Simon Urbanek}
\seealso{
\code{\link{Rserve}}
}
\keyword{interface}
