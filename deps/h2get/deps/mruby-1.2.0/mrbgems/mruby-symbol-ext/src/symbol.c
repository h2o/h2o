#include "mruby.h"
#include "mruby/khash.h"
#include "mruby/array.h"

typedef struct symbol_name {
  size_t len;
  const char *name;
} symbol_name;

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
static mrb_value
mrb_sym_all_symbols(mrb_state *mrb, mrb_value self)
{
  mrb_sym i, lim;
  mrb_value ary = mrb_ary_new_capa(mrb, mrb->symidx);

  for (i=1, lim=mrb->symidx+1; i<lim; i++) {
    mrb_ary_push(mrb, ary, mrb_symbol_value(i));
  }

  return ary;
}

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
  mrb_sym2name_len(mrb, mrb_symbol(self), &len);
  return mrb_fixnum_value(len);
}

void
mrb_mruby_symbol_ext_gem_init(mrb_state* mrb)
{
  struct RClass *s = mrb->symbol_class;
  mrb_define_class_method(mrb, s, "all_symbols", mrb_sym_all_symbols, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "length", mrb_sym_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "size", mrb_sym_length, MRB_ARGS_NONE());
}

void
mrb_mruby_symbol_ext_gem_final(mrb_state* mrb)
{
}
