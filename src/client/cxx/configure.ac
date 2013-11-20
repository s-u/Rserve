# Process this file with autoconf to produce a configure script.
AC_INIT([Rserve-cxx-client],[0.1],[Simon.Urbanek@r-project.org])
AC_CONFIG_SRCDIR([Rconnection.cc])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_CXX
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([string.h memory.h sys/time.h unistd.h])
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
AC_CHECK_FUNCS([memset mkdir rmdir select socket])

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

# on some platforms libR expects dl code in the binary
AC_CHECK_LIB(dl, dlopen)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
