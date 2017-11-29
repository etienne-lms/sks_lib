AC_PREREQ(2.59)
AC_INIT([optee-cryptoki], [0.0.0], [optee@linaro.org])

# foreign: avoid having to have some GNU mandated files (AUTHORS, COPYING, etc)
# TODO: more permissive option?
# subdir-objects: source may be in subdirectories.
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_FILES([Makefile
		 lib/Makefile
		 optee_cryptoki.pc])

# Libtool versioning format:
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info
LIBVER_CURRENT=0
LIBVER_REVISION=0
LIBVER_AGE=0
AC_SUBST([LIBVER_CURRENT])
AC_SUBST([LIBVER_REVISION])
AC_SUBST([LIBVER_AGE])

# Some warning flags we would like to always apply on build components
WARNINGCFLAGS="\\
	-Wall -Wbad-function-cast -Wcast-align \\
	-Werror-implicit-function-declaration -Wextra \\
	-Wfloat-equal -Wformat-nonliteral -Wformat-security \\
	-Wformat=2 -Winit-self -Wmissing-declarations \\
	-Wmissing-format-attribute -Wmissing-include-dirs \\
	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs \\
	-Wpointer-arith -Wshadow -Wstrict-prototypes \\
	-Wswitch-default -Wunsafe-loop-optimizations \\
	-Wwrite-strings -Werror \\
	"
AC_SUBST([WARNINGCFLAGS])

dnl checks for programs
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_CC_C99
AC_PROG_LIBTOOL
AC_PROG_MKDIR_P
AC_PROG_LN_S
PKG_PROG_PKG_CONFIG
AC_SUBST([pkgconfigdir], [$libdir/pkgconfig])

dnl checks for libraries

AC_MSG_CHECKING([if we have the OP-TEE Client library support])
TEEC_LIBS=error
AC_CHECK_LIB(teec, TEEC_CreateContext, TEEC_LIBS="-lteec")
AC_SUBST(TEEC_LIBS)

dnl checks for headers
dnl checks for types
dnl checks for structures
dnl checks for compiler characteristics
dnl checks for library functions
dnl checks for system services

AC_OUTPUT
