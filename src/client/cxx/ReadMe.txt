This directory contains a sample C++ client for Rserve

You can compile this client without R. Just run "configure" in the
Rserve directory, a corresponding Makefile will be automatically
generated.
Win32: There is no configure for Windows, but there is a special
Makefile.win to build it - use "make -f Makefile.win" - it requires
MinGW (or compatible) and GNU make.

This C++ interface is experimental and does not come in form of a
library, it is left to the user to build one or just use it in static
form. Rconnection.h and Rconnection.cc is all that's needed. This
directory also contains two little examples:

* demo1.cc
This (rather silly) example demonstrates the basic use of the
API, such as assigning contents, evaluating expressions and fetching
various parts of the data.

* rcons.cc
A very simple console to Rserve. It uses the os_print method to print
the results and its attributes. It is helpful if you want to
understand how R and Rserve stores various expressions.

* rcmd.cc
This program "sources" all files specified on the command line into
a Rserve session and prints its output. It is something like a 'fast'
version of R CMD BATCH. It's very simple, so look at the code if
you want a more sophisticated behavior.

The entire C++ interface handles only the most basic types such as
lists, vectors, doubles, integers and strings. Look at the sources
to see how to implement other types if necessary (although there
isn't too much missing, maybe logical vectors ...).

A word about the memory allocation of the objects here: in most cases
the memory is allocated by the Rmessage object that receives the
evaluated expression for R. All further Rexp objects are just
pointers inside that message. For convenience there is one "main"
Rexp, which knows about the message and automaically deallocates it
upon its own destruction. This means that from user's point of view
there is always only *one* object which can be deleted, namely the
one returned by 'eval'. The user should *never* delete any object
obtained indirectly from another Rexp. Complex Rexps, such as Rvector
always return direct pointers to their content. This applies also to
pointer to other types obtained from Rexp such as doubleArray of
Rdouble. You should always copy this content if you plan to make
modifications. This approach was taken to provide very fast access to
all objects returned from Rserve. Usually noting needs to be copied
- this is imporant, because the objects could be quite large.

Please feel free to contribute to this project. I don't use this C++
interface myself, therefore it is left to the users to extend it
further. All low-level handling is implemented, therefore it is much
easier to add high-level functionality.

see also: http://www.rosuda.org/Rserve/

Simon Urbanek, Sept 2004
