# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2007-2018 ANSSI. All Rights Reserved.
dnl Process this file with autoconf to produce a configure script.
AC_INIT(src/vsctl.c)

dnl Checks for programs.
AC_PROG_CC

[
if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall -Wextra -Werror \
	-Wstrict-prototypes -Wmissing-prototypes \
	-Wcast-qual -Wcast-align -Wpointer-arith \
	-Wnested-externs"
fi
]

AC_ARG_WITH(kernel-includes,
        AC_HELP_STRING([--with-kernel-includes=path],
                [Use path for kernel includes (default: /usr/src/linux/include)]),
                [KERNEL_INCLUDES=$withval],
                [KERNEL_INCLUDES=/usr/src/linux/include])
AC_SUBST(KERNEL_INCLUDES)

dnl Check for static option
AC_ARG_ENABLE(static,   
		AC_HELP_STRING([--enable-static], [static support]),
			[static=$enableval], [static=no])
AC_SUBST(static)

dnl Check for debug option
AC_ARG_ENABLE(debug,   
		AC_HELP_STRING([--enable-debug], [debugging output]),
			[debug=$enableval], [debug=no])
AC_SUBST(debug)

dnl Check for testing option
AC_ARG_ENABLE(testing,   
		AC_HELP_STRING([--enable-testing], [testing support]),
			[testing=$enableval], [testing=no])
AC_SUBST(testing)

if test -z "$PKG_CONFIG"; then
  PKG_CONFIG=pkg-config
fi
AC_SUBST(PKG_CONFIG)

AC_MSG_CHECKING(that pkg-config runs)
if "$PKG_CONFIG" --version > /dev/null 2>&1 ; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  AC_MSG_ERROR([*** $PKG_CONFIG missing ***

\'$PKG_CONFIG --version\' failed to run - make sure it is inside one of the
directories in your PATH environment variable!

pkg-config comes with the developement packages for GTK+-2.2, available at:

    http://www.gtk.org])
fi

AC_DEFUN(BUILD_DEPENDS, [
AC_MSG_CHECKING(that $1 (version >= $2) is installed)
if "$PKG_CONFIG" --atleast-version=$2 $1 ; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  if "$PKG_CONFIG" --exists $1 ; then
    ERRSTR=`"$PKG_CONFIG"  --modversion $1`
    AC_MSG_ERROR(Current version is only $ERRSTR)
  else
    AC_MSG_ERROR(Package is not installed)
  fi
fi
])

BUILD_DEPENDS(clip-vserver, 4.1.7)
BUILD_DEPENDS(clip, 1.2.6)

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h sys/socket.h sys/un.h)
AC_CHECK_HEADERS(clip/clip.h)
AC_CHECK_HEADERS(clip/clip-vserver.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T

dnl Checks for library functions.
AC_CHECK_FUNCS(chroot)

AC_OUTPUT(Makefile src/Makefile scripts/Makefile man/Makefile)
