# Process this file with autoconf to produce a configure script.
AC_INIT([Rserve],[1.8],[Simon.Urbanek@r-project.org])
AC_CONFIG_SRCDIR([src/Rserv.c])
AC_CONFIG_HEADER([src/config.h])

# find R home and set CC/CFLAGS
: ${R_HOME=`R RHOME`}
if test -z "${R_HOME}"; then
  echo "could not determine R_HOME"
  exit 1
fi

AC_ARG_WITH([server],
	AS_HELP_STRING(--with-server,[compile Rserve server (default is @<:@yes@:>@). Given that this is the main functionality of Rserve, the only reason to disable the server is to configure R or C++ client separately.]),
	[with_server=$withval], [with_server=yes])

AC_ARG_WITH([client],
	AS_HELP_STRING(--with-client,[compile additional C/C++ Rserve client (default is @<:@no@:>@). The client can be always compiled manually regardless of this setting.]),
	[with_client=$withval], [with_client=no])

AC_ARG_ENABLE([ipv6],
[AC_HELP_STRING([--enable-ipv6],
		[enable the use of IPv6 protocol. @<:@no@:>@])],
[want_ipv6="${enableval}"],
[want_ipv6=no])

RLD=`${R_HOME}/bin/R CMD config --ldflags 2>/dev/null`
has_R_shlib=no
if test -n "$RLD"; then
   has_R_shlib=yes
fi

AC_ARG_ENABLE([threads],
[AC_HELP_STRING([--enable-threads],
                [enable the use of threads in code than may benefit from it.
		Currently, it is only used in stdout/err forwarding, it does not
		enable the threaded server.
                @<:@auto@:>@])],
[want_threads="${enableval}"],
[want_threads=auto])

AC_MSG_CHECKING([whether to compile the server])
if test "${with_server}" = yes; then
   AC_MSG_RESULT(yes)
   if test "${has_R_shlib}" = no; then
      AC_MSG_ERROR([R was configured without --enable-R-shlib or --enable-R-static-lib

*** Rserve requires R (shared or static) library.                       ***
*** Please install R library or compile R with either --enable-R-shlib  ***
*** or --enable-R-static-lib support                                    ***

 Alternatively use --without-server if you wish to build only Rserve client.

])
   fi
else
   AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([whether to compile the client])
if test "${with_client}" = yes; then
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
fi

AM_CONDITIONAL(WITH_SERVER, [test "x${with_server}" = xyes])
AM_CONDITIONAL(WITH_CLIENT, [test "x${with_client}" = xyes])

CC=`${R_HOME}/bin/R CMD config CC`;
CXX=`${R_HOME}/bin/R CMD config CXX`;
CPPFLAGS="${CPPFLAGS} ${PKG_CPPFLAGS}"
CFLAGS=`${R_HOME}/bin/R CMD config CFLAGS`
CXXFLAGS=`${R_HOME}/bin/R CMD config CXXFLAGS`
RINC=`${R_HOME}/bin/R CMD config --cppflags`
LIBS="${LIBS} ${PKG_LIBS}"
AC_SUBST(R_HOME)
AC_SUBST(RINC)
AC_SUBST(RLD)

AC_ARG_VAR([OPENSSL_INCLUDES],[optional path to the include directory for OpenSSL headers])
AC_ARG_VAR([PKG_CPPFLAGS],[additional pre-processor flags])
AC_ARG_VAR([PKG_LIBS],[additional linker library flags])
if test "x${OPENSSL_INCLUDES}" != x; then
   CPPFLAGS="${CPPFLAGS} -I${OPENSSL_INCLUDES}"
fi

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([limits.h string.h memory.h sys/time.h unistd.h])
AC_CHECK_HEADERS([sys/stat.h sys/types.h sys/socket.h sys/un.h netinet/in.h netinet/tcp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_BIGENDIAN(AC_DEFINE(BS_BIG_ENDIAN, 1, [Defined if the platform is big-endian]),
	       AC_DEFINE(BS_LITTLE_ENDIAN, 1, [Defined if the platform is little-endian]),
	       [	        
AC_MSG_RESULT(endianness unknown - will rely solely on compiler macros)
AC_MSG_CHECKING([whether compiler sets endianness macros])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#if defined __LITTLE_ENDIAN__ || defined _LITTLE_ENDIAN_ || defined __BIG_ENDIAN__ || defined _BIG_ENDIAN_
#define BS_OK 1
#else
cannot determine compiler's endianness
#endif
])],[AC_MSG_RESULT(yes)],[
AC_MSG_RESULT(no)
AC_MSG_ERROR([Cannot determine endianness neither from the compiler nor using a test.
Try adding -D_BIG_ENDIAN_ or -D_LITTLE_ENDIAN_ to PKG_CPPFLAGS.
])])
])
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memset mkdir rmdir select socket srandomdev])

# Check whether we can use crypt (and if we do if it's in the crypt library)
AC_SEARCH_LIBS(crypt, crypt,
		      [AC_DEFINE(HAS_CRYPT, 1, [If defined Rserve supports unix crypt password encryption.])])
AC_CHECK_HEADERS([crypt.h])

# socket related stuff - indroduced first due to Solaris
# socklen_t - note that we don't try to find an equivalent!
# we'll use BSD-style int in case this one isn't defined.
# that should be fine for all major platforms.
AC_CHECK_TYPE(socklen_t,,
    AC_DEFINE(socklen_t, int, [Define to `int' if neither <sys/types.h> nor <sys/socket.h> define.]),
    [
#include <sys/types.h>
#include <sys/socket.h>
    ])
# connect may need -lsocket and/or -lnsl (e.g. on Solaris)
AC_CHECK_FUNCS(connect)
if test x"$ac_cv_func_connect" = x"no"; then
    case "$LIBS" in
    *-lnsl*) ;;
    *) AC_CHECK_LIB(nsl_s, printf) ;;
    esac
    case "$LIBS" in
    *-lnsl*) ;;
    *) AC_CHECK_LIB(nsl, printf) ;;
    esac
    case "$LIBS" in
    *-lsocket*) ;;
    *) AC_CHECK_LIB(socket, connect) ;;
    esac
    case "$LIBS" in
    *-linet*) ;;
    *) AC_CHECK_LIB(inet, connect) ;;
    esac
    dnl We can't just call AC_CHECK_FUNCS(connect) here, because the value
    dnl has been cached.
    if test x"$ac_cv_lib_socket_connect" = x"yes" || 
       test x"$ac_cv_lib_inet_connect" = x"yes"; then
        # ac_cv_func_connect=yes
        # don't!  it would cause AC_CHECK_FUNC to succeed next time configure is run
        AC_DEFINE(HAVE_CONNECT, 1, [ ])
    fi
fi

# IPv6
have_ipv6=no
AC_MSG_CHECKING([whether to enable IPv6])
if test "$want_ipv6" = yes; then
AC_MSG_RESULT([yes])
AC_MSG_CHECKING([for working IPv6 sockets])
AC_LINK_IFELSE([AC_LANG_SOURCE([
#include <sys/socket.h>
#include <netinet/in.h>
int main(void) {
    struct sockaddr_in6 sin;
    int i = socket(PF_INET6, SOCK_STREAM, 0);
    sin.sin6_family = AF_INET6;
    sin.sin6_addr = in6addr_any;
    return 0;
}
])],[AC_MSG_RESULT(yes)
have_ipv6=yes],[AC_MSG_RESULT(no)])
else
AC_MSG_RESULT([no])
fi
if test "$have_ipv6" = yes; then
   AC_DEFINE(HAVE_IPV6, 1, [IPv6 support present and enabled])
fi

# on some platforms libR expects dl code in the binary
AC_CHECK_LIB(dl, dlopen)

# check RSA/crypto
AC_CHECK_HEADER([openssl/rsa.h],
[AC_SEARCH_LIBS(RSA_generate_key, [crypto ssl openssl], [AC_DEFINE(HAVE_RSA, 1, [RSA crypto support])])])

# check SSL support
AC_CHECK_HEADER([openssl/ssl.h],
[AC_SEARCH_LIBS(SSL_CTX_load_verify_locations, [ssl openssl], [AC_DEFINE(HAVE_TLS, 1, [TLS/SSL support])])])

# check threads
AC_MSG_CHECKING([whether threads are desired])
if test "$want_threads" != no; then
   AC_MSG_RESULT([yes])
   AC_MSG_CHECKING([for working threads support])
   AX_PTHREAD([
     LIBS="$PTHREAD_LIBS $LIBS"
     ## we don't want to mess with CFLAGS so we (ab)use CPPFLAGS
     CPPFLAGS="$CPPFLAGS $PTHREAD_CFLAGS" 
     ## and we ignore PTHREAD_CC since we have to use R's settings
     with_threads=yes
     AC_MSG_RESULT([yes])
   ], [
     AC_MSG_RESULT([no])
     if test "$want_threads" = yes; then
       AC_MSG_ERROR([Threads were requested, but no working threads support was found])
     fi 
     with_threads=no
   ])
else
   AC_MSG_RESULT([no])
   with_threads=no
fi

if test x"$with_threads" = xyes; then
   AC_DEFINE(WITH_THREADS, 1, [set if threads can be used])
fi

AC_CONFIG_FILES([src/Makevars])
AC_CONFIG_FILES([src/client/cxx/Makefile])
AC_OUTPUT
