/*
** mruby/throw.h - mruby exception throwing handler
**
** See Copyright Notice in mruby.h
*/

#ifndef MRB_THROW_H
#define MRB_THROW_H

#if defined(MRB_ENABLE_CXX_EXCEPTION) && !defined(__cplusplus)
#error Trying to use C++ exception handling in C code
#endif

#if defined(MRB_ENABLE_CXX_EXCEPTION) && defined(__cplusplus)

#define MRB_TRY(buf) do { try {
#define MRB_CATCH(buf) } catch(mrb_jmpbuf_impl e) { if (e != (buf)->impl) { throw e; }
#define MRB_END_EXC(buf)  } } while(0)

#define MRB_THROW(buf) throw((buf)->impl)
typedef mrb_int mrb_jmpbuf_impl;

#else

#include <setjmp.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define MRB_SETJMP _setjmp
#define MRB_LONGJMP _longjmp
#else
#define MRB_SETJMP setjmp
#define MRB_LONGJMP longjmp
#endif

#define MRB_TRY(buf) do { if (MRB_SETJMP((buf)->impl) == 0) {
#define MRB_CATCH(buf) } else {
#define MRB_END_EXC(buf) } } while(0)

#define MRB_THROW(buf) MRB_LONGJMP((buf)->impl, 1);
#define mrb_jmpbuf_impl jmp_buf

#endif

struct mrb_jmpbuf {
  mrb_jmpbuf_impl impl;

#if defined(MRB_ENABLE_CXX_EXCEPTION) && defined(__cplusplus)
  static mrb_int jmpbuf_id;
  mrb_jmpbuf() : impl(jmpbuf_id++) {}
#endif
};

#endif  /* MRB_THROW_H */
