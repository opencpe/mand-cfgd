dnl # This Source Code Form is subject to the terms of the Mozilla Public
dnl # License, v. 2.0. If a copy of the MPL was not distributed with this
dnl # file, You can obtain one at http://mozilla.org/MPL/2.0/.

dnl #   standard Autoconf prolog

AC_PREREQ(2.59)

AC_INIT(cfgd, [1.0])
AC_CONFIG_SRCDIR(src/cfgd.c)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(1.9)

AC_SRCDIR_PREFIX(srcdir_prefix)
AC_HEADLINE(dnl
OpenCPE configuration deamon for OpenWRT, dnl
[Released under MPL 2.0])
AC_CONFIG_PARAM(config.param)
AM_CONFIG_HEADER(config.h)
AC_PREFIX_DEFAULT(/usr)
AC_PLATFORM(PLATFORM)

dnl ##
dnl ##  BUILD TOOLS
dnl ##

AC_MSG_PART(Build Tools)

AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CPP
AC_DISABLE_SHARED
AC_PROG_INSTALL
AC_SET_MAKE
AC_CHECK_DEBUGGING

AC_MSG_PART(Configure libtool)
AM_PROG_LIBTOOL

dnl ##
dnl ##   MANDATORY PLATFORM ENVIRONMENT
dnl ##

AC_MSG_PART(Mandatory Platform Environment)

AC_HEADER_STDC
AC_ISC_POSIX
AC_C_BIGENDIAN

AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h])
AC_CHECK_FUNCS(strcpy strdup strcmp free malloc open read close fprintf)
AC_CHECK_LIBM

AM_MAINTAINER_MODE

AC_MSG_PART(required libraries)
AC_CHECK_LIB([ev], [event_init],,             AC_MSG_ERROR(Required library ev missing))
AC_CHECK_HEADERS([talloc.h talloc/talloc.h])
AC_CHECK_LIB([talloc], [talloc_named_const],, AC_MSG_ERROR(Required library talloc missing))
AC_CHECK_LIB([dmutils], [logx],,              AC_MSG_ERROR(Required library dmutils missing))
AC_CHECK_HEADER([mand/logx.h])
AC_CHECK_LIB([dmconfig], [dm_init_socket],,   AC_MSG_ERROR(Required library dmconfig missing))
AC_CHECK_HEADER([libdmconfig/dmconfig.h])

AC_CONFIG_FILES([
        Makefile
        src/Makefile
])
AC_OUTPUT
