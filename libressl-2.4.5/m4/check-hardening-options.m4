
AC_DEFUN([CHECK_CFLAG], [
	 AC_LANG_ASSERT(C)
	 AC_MSG_CHECKING([if $saved_CC supports "$1"])
	 old_cflags="$CFLAGS"
	 CFLAGS="$1 -Wall -Werror"
	 AC_TRY_LINK([
		      #include <stdio.h>
		      ],
		     [printf("Hello")],
		     AC_MSG_RESULT([yes])
		     CFLAGS=$old_cflags
		     HARDEN_CFLAGS="$HARDEN_CFLAGS $1",
		     AC_MSG_RESULT([no])
		     CFLAGS=$old_cflags
		     [$2])
])

AC_DEFUN([CHECK_LDFLAG], [
	 AC_LANG_ASSERT(C)
	 AC_MSG_CHECKING([if $saved_LD supports "$1"])
	 old_ldflags="$LDFLAGS"
	 LDFLAGS="$1 -Wall -Werror"
	 AC_TRY_LINK([
		      #include <stdio.h>
		      ],
		     [printf("Hello")],
		     AC_MSG_RESULT([yes])
		     LDFLAGS=$old_ldflags
		     HARDEN_LDFLAGS="$HARDEN_LDFLAGS $1",
		     AC_MSG_RESULT([no])
		     LDFLAGS=$old_ldflags
		     [$2])
])

AC_DEFUN([DISABLE_AS_EXECUTABLE_STACK], [
	save_cflags="$CFLAGS"
	CFLAGS=
	AC_MSG_CHECKING([whether AS supports .note.GNU-stack])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	__asm__(".section .note.GNU-stack,\"\",@progbits");]])],
		[AC_MSG_RESULT([yes])]
		[AM_CFLAGS=-DHAVE_GNU_STACK],
		[AC_MSG_RESULT([no])]
	)
	CFLAGS="$save_cflags $AM_CFLAGS"
])


AC_DEFUN([CHECK_C_HARDENING_OPTIONS], [

	AC_ARG_ENABLE([hardening],
		[AS_HELP_STRING([--disable-hardening],
				[Disable options to frustrate memory corruption exploits])],
		[], [enable_hardening=yes])

	AC_ARG_ENABLE([windows-ssp],
		[AS_HELP_STRING([--enable-windows-ssp],
				[Enable building the stack smashing protection on
				 Windows. This currently distributing libssp-0.dll.])])

	# We want to check for compiler flag support. Prior to clang v5.1, there was no
	# way to make clang's "argument unused" warning fatal.  So we invoke the
	# compiler through a wrapper script that greps for this message.
	saved_CC="$CC"
	saved_LD="$LD"
	flag_wrap="$srcdir/scripts/wrap-compiler-for-flag-check"
	CC="$flag_wrap $CC"
	LD="$flag_wrap $LD"

	AS_IF([test "x$enable_hardening" = "xyes"], [
		# Tell GCC to NOT optimize based on signed arithmetic overflow
		CHECK_CFLAG([[-fno-strict-overflow]])

		# _FORTIFY_SOURCE replaces builtin functions with safer versions.
		CHECK_CFLAG([[-D_FORTIFY_SOURCE=2]])

		# Enable read only relocations
		CHECK_LDFLAG([[-Wl,-z,relro]])
		CHECK_LDFLAG([[-Wl,-z,now]])

		# Windows security flags
		AS_IF([test "x$HOST_OS" = "xwin"], [
			CHECK_LDFLAG([[-Wl,--nxcompat]])
			CHECK_LDFLAG([[-Wl,--dynamicbase]])
			CHECK_LDFLAG([[-Wl,--high-entropy-va]])
		])

		# Use stack-protector-strong if available; if not, fallback to
		# stack-protector-all which is considered to be overkill
		AS_IF([test "x$enable_windows_ssp" = "xyes" -o "x$HOST_OS" != "xwin"], [
			CHECK_CFLAG([[-fstack-protector-strong]],
				CHECK_CFLAG([[-fstack-protector-all]],
					AC_MSG_WARN([compiler does not appear to support stack protection])
				)
			)
			AS_IF([test "x$HOST_OS" = "xwin"], [
				AC_SEARCH_LIBS([__stack_chk_guard],[ssp])
			])
		])
	])

	# Restore CC, LD
	CC="$saved_CC"
	LD="$saved_LD"

	CFLAGS="$CFLAGS $HARDEN_CFLAGS"
	LDFLAGS="$LDFLAGS $HARDEN_LDFLAGS"
])
