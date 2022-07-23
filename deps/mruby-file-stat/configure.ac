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

AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_atimespec])
AC_CHECK_MEMBERS([struct stat.st_atimensec])
AC_CHECK_MEMBERS([struct stat.st_mtim])
AC_CHECK_MEMBERS([struct stat.st_mtimespec])
AC_CHECK_MEMBERS([struct stat.st_mtimensec])
AC_CHECK_MEMBERS([struct stat.st_ctim])
AC_CHECK_MEMBERS([struct stat.st_ctimespec])
AC_CHECK_MEMBERS([struct stat.st_ctimensec])
AC_CHECK_MEMBERS([struct stat.st_birthtimespec])

AC_CHECK_FUNCS(getgroups)
AC_CHECK_FUNCS(lstat)

AC_CHECK_HEADERS(sys/sysmacros.h)

AC_OUTPUT
