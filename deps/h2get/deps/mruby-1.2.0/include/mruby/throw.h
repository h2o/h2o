/*
** mruby/throw.h - mruby exception throwing handler
**
** See Copyright Notice in mruby.h
*/

#ifndef MRB_THROW_H
#define MRB_THROW_H

#ifdef MRB_ENABLE_CXX_EXCEPTION

#define MRB_TRY(buf) do { try {
#define MRB_CATCH(buf) } catch(mrb_jmpbuf_impl e) { if (e != (buf)->impl) { throw e; }
#define MRB_END_EXC(buf)  } } while(0)

#define MRB_THROW(buf) throw((buf)->impl)
typedef mrb_int mrb_jmpbuf_impl;

#else

#include <setjmp.h>

#define MRB_TRY(buf) do { if (setjmp((buf)->impl) == 0) {
#define MRB_CATCH(buf) } else {
#define MRB_END_EXC(buf) } } while(0)

#define MRB_THROW(buf) longjmp((buf)->impl, 1);
#define mrb_jmpbuf_impl jmp_buf

#endif

struct mrb_jmpbuf {
  mrb_jmpbuf_impl impl;

#ifdef MRB_ENABLE_CXX_EXCEPTION
  static mrb_int jmpbuf_id;
  mrb_jmpbuf() : impl(jmpbuf_id++) {}
#endif
};

#endif  /* MRB_THROW_H */
