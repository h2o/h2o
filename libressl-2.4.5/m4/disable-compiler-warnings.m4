AC_DEFUN([DISABLE_COMPILER_WARNINGS], [
# Clang throws a lot of warnings when it does not understand a flag. Disable
# this warning for now so other warnings are visible.
AC_MSG_CHECKING([if compiling with clang])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[
#ifndef __clang__
	not clang
#endif
	]])],
	[CLANG=yes],
	[CLANG=no]
)
AC_MSG_RESULT([$CLANG])
AS_IF([test "x$CLANG" = "xyes"], [CLANG_FLAGS=-Qunused-arguments])
CFLAGS="$CFLAGS $CLANG_FLAGS"
LDFLAGS="$LDFLAGS $CLANG_FLAGS"

# Removing the dependency on -Wno-pointer-sign should be a goal. These are
# largely unsigned char */char* mismatches in asn1 functions.
save_cflags="$CFLAGS"
CFLAGS=-Wno-pointer-sign
AC_MSG_CHECKING([whether CC supports -Wno-pointer-sign])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	[AC_MSG_RESULT([yes])]
	[AM_CFLAGS=-Wno-pointer-sign],
	[AC_MSG_RESULT([no])]
)
CFLAGS="$save_cflags $AM_CFLAGS"
])
