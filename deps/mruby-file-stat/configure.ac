#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT()

AC_PROG_CC

AC_CONFIG_SRCDIR([src/file-stat.c])
AC_CONFIG_HEADERS([config.h])

AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_CHECK_MEMBERS([struct stat.st_blocks])
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([struct stat.st_birthtimespec])

AC_CHECK_FUNCS(getgroups)
AC_CHECK_FUNCS(lstat)

AC_OUTPUT
