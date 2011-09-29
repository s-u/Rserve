This directory contains various Rserve clients:

cxx       - minimal C++ client

java-new  - Java client based on the REngine API. This is the actively
	    developed Java client as it is more flexible and
	    consistent than the older JRclient. It supports multiple
	    back-ends such as Rserve or JRI.

java-old  - old Java client (JRclient). This was the first
	    implementation of a Java cilent, but has been now replaced
	    by the REngine API. It is still maitained for
	    compatibility with older programs, but it will be phased
	    out eventually.

php       - minimal PHP client and example code that can be used to
	    run FastRWeb via PHP instead of CGI
	    NOTE: a more complete PHP client written by
	    Clement Turbelin based on this minimal version is
	    available from http://code.google.com/p/rserve-php
