#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([analyzer_data_v5.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_INIT_AUTOMAKE

PKG_CHECK_MODULES([GLIB], [glib-2.0])


# Checks for libraries.
AC_CHECK_LIB([crypt], [main])
AC_CHECK_LIB([pq], [main])
AC_CHECK_HEADER([glib.h])
PKG_CHECK_MODULES([glib], [glib-2.0 >= 2.28])
AC_CHECK_LIB([glib], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h locale.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])


CFLAGS="$CFLAGS $GLIB_CFLAGS -std=gnu99 $(echo '${UFLAGS}')"
CPPFLAGS="$CPPFLAGS $GLIB_CPPFLAG"
LDFLAGS="$LDFLAGS $GLIB_LDFLAGS"

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm bzero inet_ntoa pow select setlocale socket strerror])



AC_CONFIG_FILES([Makefile])
AC_OUTPUT
