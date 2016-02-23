# [Rserve](http://www.rforge.net/Rserve/)

Rserve is a TCP/IP server which allows other programs to use facilities of [R](http://www.r-project.org) from various languages without the need to initialize R or link against R library. Every connection has a separate workspace and working directory. Client-side implementations are available for popular languages such as C/C++, PHP and Java. Rserve supports remote connection, authentication and file transfer. Typical use is to integrate R backend for computation of statstical models, plots etc. in other applications.

The following Java code illustrates the easy integration of Rserve:

```java
RConnection c = new RConnection();
double d[] = c.eval("rnorm(10)").asDoubles();
```

`d` now contains 10 random samples from the N(0,1) distribution if there is a runing Rserve on the local machine. The RConnection doesn't have to be created more than once for subsequent commands (however, each thread must have its own connection object unless synchronized explicitly).

As a side note - if you are looking just for a way to access R from Java in one application without the need for the client/server concept, you may want to have a look at [JRI](http://www.rforge.net/JRI). It uses JNI to link R directly into Java.

The original Rserve paper is available in the [DSC-2003 proceedings](http://www.ci.tuwien.ac.at/Conferences/DSC-2003/Proceedings/Urbanek.pdf). Please cite that paper when using Rserve.

NOTE: Rserve is perfect as a back-end for web services and is often used that way. See also [FastRWeb](http://www.rforge.net/FastRWeb).

## Features of Rserve
 * fast - no initialization of R is necessary
 * binary transport - the transport protocol sends R objects as binary data, not just R text output.
 * automatic type conversion - most R data types are converted into native data types, e.g. the result of rnorm(10) will be double[10] in C/Java. Java client also provides classes for new R types such as RBool, RList etc.
 * persistent - each connection has its own namespace and working directory. Every object you create is persistent until the connection is closed. The client doesn't have to fetch or store intermediate results.
 * client independence - since the client is not linked to R there are no threading issues like in RSJava etc.
 * security - Rserve provides some basic security by supporting encrypted user/password authentication with server challenge. Rserve can be also configured to accept local connections only.
 * file transfer - the Rserve protocol allows to transfer files between the client and the server. This way Rserve can be used as a remote server even for task such as generating plot images etc.
 * configurable - one configuration file is used to control settings and to enable/disable features such as authorization, remote access or file transfer.

## What Rserve is NOT
Rserve provides no callback functionality. Your application could implement callbacks via TCP/IP and the R sockets but it is not a part of Rserve.
Rserve is not a telnet frontend to R. The printed output is not transported (except via capture.output). Rserve uses binary protocol for transport of objects for better speed.
Rserve is thread safe across connections, but eval methods are not thread safe within one connection. This means that multiple threads should not use the same connection unless they guarantee that no eval calls are run in parallel.
You can read more about the Rserve in the documentation section. Once you read at least the introduction, you can go to the download section to get the necessary files.

## Authors
Rserve was developed by Simon Urbanek, but anyone interested is welcome to check out the developer section and contribute to the project.

## License
The sources are licensed under GPL.
