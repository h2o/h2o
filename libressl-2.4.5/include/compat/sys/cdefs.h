/*
 * Public domain
 * sys/cdefs.h compatibility shim
 */

#ifndef LIBCRYPTOCOMPAT_SYS_CDEFS_H
#define LIBCRYPTOCOMPAT_SYS_CDEFS_H

#ifdef _WIN32

#define __warn_references(sym,msg)

#else

#include_next <sys/cdefs.h>

#ifndef __warn_references

#if defined(__GNUC__)  && defined (HAS_GNU_WARNING_LONG)
#define __warn_references(sym,msg)          \
  __asm__(".section .gnu.warning." __STRING(sym)  \
         " ; .ascii \"" msg "\" ; .text");
#else
#define __warn_references(sym,msg)
#endif

#endif /* __warn_references */

#endif /* _WIN32 */

#endif /* LIBCRYPTOCOMPAT_SYS_CDEFS_H */
