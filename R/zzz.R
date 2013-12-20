## we have to load the dylib/so/DLL by hand
## because it is optional in case we're loaded
## into an embedded Rserve instance

.register <- c("Rserve_ctrlEval", "Rserve_ctrlSource",
	       "Rserve_oobSend", "Rserve_oobMsg",
	       "Rserve_oc_register", "Rserve_oc_resolve", "run_Rserve")

.onLoad <- function(libname, pkgname) {
    env <- environment(.onLoad)
    ## unless we are runnning in an embedded Rserve (which provides
    ## registration in the "(embedding)" domain)
    ## we have to load the package dylib
    if (!isTRUE(tryCatch(getNativeSymbolInfo(.register[1L])$package[["name"]] == "(embedding)",
        error=function(...) FALSE)))
        library.dynam(pkgname, pkgname, libname)
    for (i in .register)
        env[[i]] <- tryCatch(getNativeSymbolInfo(i), error=function(...) NULL)
}
