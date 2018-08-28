echo on

javac -cp REngine-1.8.jar;RserveEngine-1.8.jar RserveBug.java

taskkill /f /t /im Rserve.exe

Rscript -e "sessionInfo(); install.packages('../Rserve_1.7-5.zip',repos=NULL,type='binary'); packageDescription('Rserve'); Rserve::Rserve(args='--vanilla --RS-enable-control')"

java -cp .;REngine-1.8.jar;RserveEngine-1.8.jar RserveBug
SET RET=%ERRORLEVEL%

taskkill /f /t /im Rserve.exe

exit /B %RET%
