libarch <- if (nzchar(R_ARCH)) paste("libs", R_ARCH, sep='') else "libs"
dest <- file.path(R_PACKAGE_DIR, libarch)
## the last two on unix are for compatibility only
files <- if (WINDOWS) c("Rserve.exe", "Rserve_d.exe") else c("Rserve","Rserve.dbg")
files <- c(files, paste("Rserve",SHLIB_EXT,sep=''))
## all files are optional in case the package is built without the server
files <- files[file.exists(files)]
if (length(files)) {
  dir.create(dest, recursive = TRUE, showWarnings = FALSE)
  file.copy(files, dest, overwrite = TRUE)
  if (length(grep("^darwin", R.version$os))) {
    message('generating debug symbols (dSYM)')
    dylib <- Sys.glob(paste(dest, "/*", SHLIB_EXT, sep=''))
    if (length(dylib)) for (file in dylib) try(system(paste("dsymutil ", file, sep='')), silent=TRUE)
  }
}
