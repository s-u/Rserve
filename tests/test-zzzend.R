library("RSclient")

c = RS.connect()


try(RS.server.shutdown(c))
RS.close(c)

# hard end... (to be sure)
if (.Platform$OS == "windows") {
  system("taskkill /F /IM Rserve.exe")
} else {
  system("killall Rserve")
}
