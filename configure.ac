# Process this file with autoconf to produce a configure script.
AC_INIT(Rserve, 0.4, Simon.Urbanek@r-project.org)
AC_CONFIG_SRCDIR([src/Rserv.c])
AC_CONFIG_HEADER([src/config.h])

# find R home and set CC/CFLAGS
: ${R_HOME=`R RHOME`}
if test -z "${R_HOME}"; then
  echo "could not determine R_HOME"
  exit 1
fi
CC=`${R_HOME}/bin/R CMD config CC`;
CXX=`${R_HOME}/bin/R CMD config CXX`;
CFLAGS=`${R_HOME}/bin/R CMD config CFLAGS`
CXXFLAGS=`${R_HOME}/bin/R CMD config CXXFLAGS`
AC_SUBST(R_HOME)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([string.h memory.h sys/time.h unistd.h])
AC_CHECK_HEADERS([sys/stat.h sys/types.h sys/socket.h sys/un.h netinet/in.h netinet/tcp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
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

AC_MSG_CHECKING([endianess])
AC_TRY_RUN(
	[
int main(void) { int i=0x12345678; return (*((char*)&i)==0x78)?0:1; }
	],
	[AC_MSG_RESULT(intel-like)],
	[
		AC_MSG_RESULT(PPC-like)
		AC_DEFINE(SWAPEND, 1, [Must be defined for platforms with bytesex inverse to intel style])
	]
)

AC_MSG_CHECKING([for readline support])
AC_CHECK_HEADERS(readline/readline.h readline/history.h,
	[
		AC_MSG_CHECKING([for readline libraries])
		LINK_READLINE="-lreadline"
		AC_CHECK_LIB(ncurses, tputs, SFTPLIB="-lncurses $LINK_READLINE" ,
			[AC_CHECK_LIB(curses, tputs, LINK_READLINE="-lcurses $LINK_READLINE" ,
				[AC_CHECK_LIB(termcap, tputs, LINK_READLINE="-ltermcap $LINK_READLINE")
				])
			])

		PRESERVE_LIBS="$LIBS"
		LIBS="$LIBS $LINK_READLINE"
		AC_TRY_RUN(
			[  
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
int main() { add_history(rl_library_version); return 0; }
			],
			[
				AC_MSG_RESULT(yes)
				AC_DEFINE(READLINE, 1, [Defined if readline is supported])
			],AC_MSG_RESULT(no))
		LIBS="$PRESERVE_LIBS"
	])

AC_SUBST(LINK_READLINE)

AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([src/client/Makefile])
AC_OUTPUT
