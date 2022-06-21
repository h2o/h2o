#include <mruby.h>
#include <mruby/array.h>
#include <mruby/string.h>
#ifdef MRB_USE_ALL_SYMBOLS
# include <mruby/presym.h>
#endif

/*
 *  call-seq:
 *     Symbol.all_symbols    => array
 *
 *  Returns an array of all the symbols currently in Ruby's symbol
 *  table.
 *
 *     Symbol.all_symbols.size    #=> 903
 *     Symbol.all_symbols[1,20]   #=> [:floor, :ARGV, :Binding, :symlink,
 *                                     :chown, :EOFError, :$;, :String,
 *                                     :LOCK_SH, :"setuid?", :$<,
 *                                     :default_proc, :compact, :extend,
 *                                     :Tms, :getwd, :$=, :ThreadGroup,
 *                                     :wait2, :$>]
 */
#ifdef MRB_USE_ALL_SYMBOLS
static mrb_value
mrb_sym_all_symbols(mrb_state *mrb, mrb_value self)
{
  mrb_sym i, lim;
  mrb_value ary = mrb_ary_new_capa(mrb, mrb->symidx);

  for (i=1; i<=MRB_PRESYM_MAX; i++) {
    mrb_ary_push(mrb, ary, mrb_symbol_value(i));
  }
  for (i=1, lim=mrb->symidx+1; i<lim; i++) {
    mrb_ary_push(mrb, ary, mrb_symbol_value(i+MRB_PRESYM_MAX));
  }

  return ary;
}
#endif

/*
 * call-seq:
 *   sym.length    -> integer
 *
 * Same as <code>sym.to_s.length</code>.
 */
static mrb_value
mrb_sym_length(mrb_state *mrb, mrb_value self)
{
  mrb_int len;
#ifdef MRB_UTF8_STRING
  mrb_int byte_len;
  const char *name = mrb_sym_name_len(mrb, mrb_symbol(self), &byte_len);
  len = mrb_utf8_strlen(name, byte_len);
#else
  mrb_sym_name_len(mrb, mrb_symbol(self), &len);
#endif
  return mrb_fixnum_value(len);
}

void
mrb_mruby_symbol_ext_gem_init(mrb_state* mrb)
{
  struct RClass *s = mrb->symbol_class;
#ifdef MRB_USE_ALL_SYMBOLS
  mrb_define_class_method(mrb, s, "all_symbols", mrb_sym_all_symbols, MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, s, "length", mrb_sym_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "size", mrb_sym_length, MRB_ARGS_NONE());
}

void
mrb_mruby_symbol_ext_gem_final(mrb_state* mrb)
{
}
