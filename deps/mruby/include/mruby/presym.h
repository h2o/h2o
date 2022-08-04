/**
** @file mruby/presym.h - Preallocated Symbols
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_PRESYM_H
#define MRUBY_PRESYM_H

#if defined(MRB_NO_PRESYM)
# include <mruby/presym/disable.h>
#elif !defined(MRB_PRESYM_SCANNING)
# include <mruby/presym/enable.h>
#endif

/*
 * Where `mrb_intern_lit` is allowed for symbol interning, it is directly
 * replaced by the symbol ID if presym is enabled by using the following
 * macros.
 *
 *   MRB_OPSYM(xor)  //=> ^      (Operator)
 *   MRB_CVSYM(xor)  //=> @@xor  (Class Variable)
 *   MRB_IVSYM(xor)  //=> @xor   (Instance Variable)
 *   MRB_SYM_B(xor)  //=> xor!   (Method with Bang)
 *   MRB_SYM_Q(xor)  //=> xor?   (Method with Question mark)
 *   MRB_SYM_E(xor)  //=> xor=   (Method with Equal)
 *   MRB_SYM(xor)    //=> xor    (Word characters)
 *
 * For `MRB_OPSYM`, specify the names corresponding to operators (see
 * `MRuby::Presym::OPERATORS` in `lib/mruby/presym.rb` for the names that
 * can be specified for it). Other than that, describe only word characters
 * excluding leading and ending punctuations.
 *
 * These macros are expanded to `mrb_intern_lit` if presym is disabled,
 * therefore the mruby state variable is required. The above macros can be
 * used when the variable name is `mrb`. If you want to use other variable
 * names, you need to use macros with `_2` suffix, such as `MRB_SYM_2`.
 */

#endif  /* MRUBY_PRESYM_H */
