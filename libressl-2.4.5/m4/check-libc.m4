AC_DEFUN([CHECK_LIBC_COMPAT], [
# Check for libc headers
AC_CHECK_HEADERS([err.h readpassphrase.h])
# Check for general libc functions
AC_CHECK_FUNCS([asprintf inet_pton memmem readpassphrase reallocarray])
AC_CHECK_FUNCS([strlcat strlcpy strndup strnlen strsep strtonum])
AC_CHECK_FUNCS([timegm _mkgmtime])
AM_CONDITIONAL([HAVE_ASPRINTF], [test "x$ac_cv_func_asprintf" = xyes])
AM_CONDITIONAL([HAVE_INET_PTON], [test "x$ac_cv_func_inet_pton" = xyes])
AM_CONDITIONAL([HAVE_MEMMEM], [test "x$ac_cv_func_memmem" = xyes])
AM_CONDITIONAL([HAVE_READPASSPHRASE], [test "x$ac_cv_func_readpassphrase" = xyes])
AM_CONDITIONAL([HAVE_REALLOCARRAY], [test "x$ac_cv_func_reallocarray" = xyes])
AM_CONDITIONAL([HAVE_STRLCAT], [test "x$ac_cv_func_strlcat" = xyes])
AM_CONDITIONAL([HAVE_STRLCPY], [test "x$ac_cv_func_strlcpy" = xyes])
AM_CONDITIONAL([HAVE_STRNDUP], [test "x$ac_cv_func_strndup" = xyes])
AM_CONDITIONAL([HAVE_STRNLEN], [test "x$ac_cv_func_strnlen" = xyes])
AM_CONDITIONAL([HAVE_STRSEP], [test "x$ac_cv_func_strsep" = xyes])
AM_CONDITIONAL([HAVE_STRTONUM], [test "x$ac_cv_func_strtonum" = xyes])
AM_CONDITIONAL([HAVE_TIMEGM], [test "x$ac_cv_func_timegm" = xyes])
])

AC_DEFUN([CHECK_SYSCALL_COMPAT], [
AC_CHECK_FUNCS([accept4 pledge poll])
AM_CONDITIONAL([HAVE_ACCEPT4], [test "x$ac_cv_func_accept4" = xyes])
AM_CONDITIONAL([HAVE_PLEDGE], [test "x$ac_cv_func_pledge" = xyes])
AM_CONDITIONAL([HAVE_POLL], [test "x$ac_cv_func_poll" = xyes])
])

AC_DEFUN([CHECK_B64_NTOP], [
AC_SEARCH_LIBS([b64_ntop],[resolv])
AC_SEARCH_LIBS([__b64_ntop],[resolv])
AC_CACHE_CHECK([for b64_ntop], ac_cv_have_b64_ntop_arg, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
		]], [[ b64_ntop(NULL, 0, NULL, 0); ]])],
	[ ac_cv_have_b64_ntop_arg="yes" ],
	[ ac_cv_have_b64_ntop_arg="no"
	])
])
AM_CONDITIONAL([HAVE_B64_NTOP], [test "x$ac_cv_func_b64_ntop_arg" = xyes])
])

AC_DEFUN([CHECK_CRYPTO_COMPAT], [
# Check crypto-related libc functions and syscalls
AC_CHECK_FUNCS([arc4random arc4random_buf arc4random_uniform])
AC_CHECK_FUNCS([explicit_bzero getauxval])

AC_CACHE_CHECK([for getentropy], ac_cv_func_getentropy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <unistd.h>

/*
 * Explanation:
 *
 *   - iOS <= 10.1 fails because of missing sys/random.h
 *
 *   - in macOS 10.12 getentropy is not tagged as introduced in
 *     10.12 so we cannot use it for target < 10.12
 */
#ifdef __APPLE__
#  include <AvailabilityMacros.h>
#  include <TargetConditionals.h>

# if (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR)
#  include <sys/random.h> /* Not available as of iOS <= 10.1 */
# else

#  include <sys/random.h> /* Pre 10.12 systems should die here */

/* Based on: https://gitweb.torproject.org/tor.git/commit/?id=16fcbd21 */
#  ifndef MAC_OS_X_VERSION_10_12
#    define MAC_OS_X_VERSION_10_12 101200 /* Robustness */
#  endif
#  if defined(MAC_OS_X_VERSION_MIN_REQUIRED)
#    if MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_12
#      error "Targeting on Mac OSX 10.11 or earlier"
#    endif
#  endif

# endif
#endif /* __APPLE__ */
		]], [[
	char buffer;
	(void)getentropy(&buffer, sizeof (buffer));
]])],
	[ ac_cv_func_getentropy="yes" ],
	[ ac_cv_func_getentropy="no"
	])
])

AC_CHECK_FUNCS([timingsafe_bcmp timingsafe_memcmp])
AM_CONDITIONAL([HAVE_ARC4RANDOM], [test "x$ac_cv_func_arc4random" = xyes])
AM_CONDITIONAL([HAVE_ARC4RANDOM_BUF], [test "x$ac_cv_func_arc4random_buf" = xyes])
AM_CONDITIONAL([HAVE_ARC4RANDOM_UNIFORM], [test "x$ac_cv_func_arc4random_uniform" = xyes])
AM_CONDITIONAL([HAVE_EXPLICIT_BZERO], [test "x$ac_cv_func_explicit_bzero" = xyes])
AM_CONDITIONAL([HAVE_GETENTROPY], [test "x$ac_cv_func_getentropy" = xyes])
AM_CONDITIONAL([HAVE_TIMINGSAFE_BCMP], [test "x$ac_cv_func_timingsafe_bcmp" = xyes])
AM_CONDITIONAL([HAVE_TIMINGSAFE_MEMCMP], [test "x$ac_cv_func_timingsafe_memcmp" = xyes])

# Override arc4random_buf implementations with known issues
AM_CONDITIONAL([HAVE_ARC4RANDOM_BUF],
	[test "x$USE_BUILTIN_ARC4RANDOM" != xyes \
	   -a "x$ac_cv_func_arc4random_buf" = xyes])

# Check for getentropy fallback dependencies
AC_CHECK_FUNC([getauxval])
AC_SEARCH_LIBS([clock_gettime],[rt posix4])
AC_CHECK_FUNC([clock_gettime])
AC_SEARCH_LIBS([dl_iterate_phdr],[dl])
AC_CHECK_FUNC([dl_iterate_phdr])
])

AC_DEFUN([CHECK_VA_COPY], [
AC_CACHE_CHECK([whether va_copy exists], ac_cv_have_va_copy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdarg.h>
va_list x,y;
		]], [[ va_copy(x,y); ]])],
	[ ac_cv_have_va_copy="yes" ],
	[ ac_cv_have_va_copy="no"
	])
])
if test "x$ac_cv_have_va_copy" = "xyes" ; then
	AC_DEFINE([HAVE_VA_COPY], [1], [Define if va_copy exists])
fi

AC_CACHE_CHECK([whether __va_copy exists], ac_cv_have___va_copy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdarg.h>
va_list x,y;
		]], [[ __va_copy(x,y); ]])],
	[ ac_cv_have___va_copy="yes" ], [ ac_cv_have___va_copy="no"
	])
])
if test "x$ac_cv_have___va_copy" = "xyes" ; then
	AC_DEFINE([HAVE___VA_COPY], [1], [Define if __va_copy exists])
fi
])
