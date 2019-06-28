## we have to load the dylib/so/DLL by hand
## because it is optional in case we're loaded
## into an embedded Rserve instance

.register <- c("Rserve_ctrlEval", "Rserve_ctrlSource", "Rserve_fork_compute", "Rserve_kill_compute",
	       "Rserve_oobSend", "Rserve_oobMsg", "Rserve_ulog", "Rserve_forward_stdio", "Rserve_eval",
	       "Rserve_oc_register", "Rserve_oc_resolve", "run_Rserve", "Rserve_get_context", "Rserve_set_context")

.onLoad <- function(libname, pkgname) {
    env <- environment(.onLoad)
    ## unless we are runnning in an embedded Rserve (which provides
    ## registration in the "(embedding)" domain)
    ## we have to load the package dylib

    ## R 3.6.0 broke NativeSymbolInfo by renaming the `package` to `dll` so we now have to check both
    pkg <- function(o) if (is.null(o$package)) o$dll else o$package

    if (!isTRUE(tryCatch(pkg(getNativeSymbolInfo(.register[1L]))[["name"]] == "(embedding)",
        error=function(...) FALSE)))
        library.dynam(pkgname, pkgname, libname)
    for (i in .register)
        env[[i]] <- tryCatch(getNativeSymbolInfo(i), error=function(...) NULL)
}
