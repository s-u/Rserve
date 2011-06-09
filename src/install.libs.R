libarch <- if (nzchar(R_ARCH)) paste("libs", R_ARCH, sep='') else "libs"
dest <- file.path(R_PACKAGE_DIR, libarch)
## the last two on unix are for compatibility only
files <- if (WINDOWS) c("Rserve.exe", "Rserve_d.exe") else c("Rserve","Rserve.dbg",paste(c("Rserve-bin","Rserve-dbg"),SHLIB_EXT,sep=''))
## all files are optional in case the package is built without the server
files <- files[file.exists(files)]
if (length(files)) {
  dir.create(dest, recursive = TRUE, showWarnings = FALSE)
  file.copy(files, dest, overwrite = TRUE)
}
