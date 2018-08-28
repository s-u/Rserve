#!/bin/bash

javac -cp REngine-1.8.jar:RserveEngine-1.8.jar RserveBug.java

killall Rserve

Rscript -e "sessionInfo(); packageDescription('Rserve'); Rserve::Rserve(args='--vanilla --RS-enable-control')"

java -cp .:REngine-1.8.jar:RserveEngine-1.8.jar RserveBug
RET=$?

killall Rserve

exit $RET
