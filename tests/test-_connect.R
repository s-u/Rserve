#require("Rserve")
library("RSclient")

if (!isTRUE(2 == 2)) stop("R basic test")

Rserve::Rserve(args = "--vanilla --RS-enable-control")

c = RS.connect()

if (!isTRUE(RS.eval(c,{1+1}) == 2)) stop("Rserve basic test")

RS.close(c)
