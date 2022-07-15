/**
** @file mruby/internal.h - Functions only called from within the library
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_INTERNAL_H
#define MRUBY_INTERNAL_H

#ifdef MRUBY_ARRAY_H
void mrb_ary_decref(mrb_state*, mrb_shared_array*);
mrb_value mrb_ary_subseq(mrb_state *mrb, mrb_value ary, mrb_int beg, mrb_int len);
#endif

#ifdef MRUBY_CLASS_H
struct RClass *mrb_vm_define_class(mrb_state*, mrb_value, mrb_value, mrb_sym);
struct RClass *mrb_vm_define_module(mrb_state*, mrb_value, mrb_sym);
mrb_value mrb_instance_new(mrb_state *mrb, mrb_value cv);
void mrb_class_name_class(mrb_state*, struct RClass*, struct RClass*, mrb_sym);
mrb_bool mrb_const_name_p(mrb_state*, const char*, mrb_int);
mrb_value mrb_class_find_path(mrb_state*, struct RClass*);
mrb_value mrb_mod_to_s(mrb_state *, mrb_value);
void mrb_method_added(mrb_state *mrb, struct RClass *c, mrb_sym mid);
#endif

/* debug */
size_t mrb_packed_int_len(uint32_t num);
size_t mrb_packed_int_encode(uint32_t num, uint8_t *p, uint8_t *pend);
uint32_t mrb_packed_int_decode(const uint8_t *p, const uint8_t **newpos);

/* dump */
#ifdef MRUBY_IREP_H
int mrb_dump_irep(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, uint8_t **bin, size_t *bin_size);
#ifndef MRB_NO_STDIO
int mrb_dump_irep_cfunc(mrb_state *mrb, const mrb_irep*, uint8_t flags, FILE *f, const char *initname);
int mrb_dump_irep_cstruct(mrb_state *mrb, const mrb_irep*, uint8_t flags, FILE *f, const char *initname);
#endif
#endif

/* error */
mrb_value mrb_exc_inspect(mrb_state *mrb, mrb_value exc);
mrb_value mrb_exc_backtrace(mrb_state *mrb, mrb_value exc);
mrb_value mrb_get_backtrace(mrb_state *mrb);
void mrb_exc_mesg_set(mrb_state *mrb, struct RException *exc, mrb_value mesg);
mrb_value mrb_exc_mesg_get(mrb_state *mrb, struct RException *exc);

/* gc */
void mrb_gc_mark_mt(mrb_state*, struct RClass*);
size_t mrb_gc_mark_mt_size(mrb_state*, struct RClass*);
void mrb_gc_free_mt(mrb_state*, struct RClass*);

/* hash */
size_t mrb_hash_memsize(mrb_value obj);
void mrb_gc_mark_hash(mrb_state*, struct RHash*);
size_t mrb_gc_mark_hash_size(mrb_state*, struct RHash*);
void mrb_gc_free_hash(mrb_state*, struct RHash*);

/* irep */
struct mrb_insn_data mrb_decode_insn(const mrb_code *pc);
#ifdef MRUBY_IREP_H
void mrb_irep_free(mrb_state*, struct mrb_irep*);
void mrb_irep_remove_lv(mrb_state *mrb, mrb_irep *irep);

static inline const struct mrb_irep_catch_handler *
mrb_irep_catch_handler_table(const struct mrb_irep *irep)
{
  if (irep->clen > 0) {
    return (const struct mrb_irep_catch_handler*)(irep->iseq + irep->ilen);
  }
  else {
    return (const struct mrb_irep_catch_handler*)NULL;
  }
}
#endif

/* numeric */
mrb_int mrb_div_int(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_int_add(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_int_sub(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_int_mul(mrb_state *mrb, mrb_value x, mrb_value y);
void mrb_int_zerodiv(mrb_state *mrb);
void mrb_int_overflow(mrb_state *mrb, const char *reason);

#ifdef MRB_USE_COMPLEX
mrb_value mrb_complex_new(mrb_state *mrb, mrb_float x, mrb_float y);
mrb_value mrb_complex_add(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_complex_sub(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_complex_mul(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_complex_div(mrb_state *mrb, mrb_value x, mrb_value y);
#endif
#ifdef MRB_USE_RATIONAL
mrb_value mrb_rational_new(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_rational_add(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_rational_sub(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_rational_mul(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_rational_div(mrb_state *mrb, mrb_value x, mrb_value y);
#endif

#ifdef MRUBY_PROC_H
struct RProc *mrb_closure_new(mrb_state*, const mrb_irep*);
void mrb_proc_copy(mrb_state *mrb, struct RProc *a, struct RProc *b);
mrb_int mrb_proc_arity(const struct RProc *p);
#endif

/* range */
#ifdef MRUBY_RANGE_H
mrb_value mrb_get_values_at(mrb_state *mrb, mrb_value obj, mrb_int olen, mrb_int argc, const mrb_value *argv, mrb_value (*func)(mrb_state*, mrb_value, mrb_int));
void mrb_gc_mark_range(mrb_state *mrb, struct RRange *r);
#endif

/* string */
void mrb_gc_free_str(mrb_state*, struct RString*);
uint32_t mrb_str_hash(mrb_state *mrb, mrb_value str);
mrb_value mrb_str_dump(mrb_state *mrb, mrb_value str);
mrb_value mrb_str_inspect(mrb_state *mrb, mrb_value str);
mrb_bool mrb_str_beg_len(mrb_int str_len, mrb_int *begp, mrb_int *lenp);
mrb_value mrb_str_byte_subseq(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len);
mrb_value mrb_str_aref(mrb_state *mrb, mrb_value str, mrb_value idx, mrb_value len);

#ifdef MRB_UTF8_STRING
mrb_int mrb_utf8len(const char *str, const char *end);
mrb_int mrb_utf8_strlen(const char *str, mrb_int byte_len);
#endif

/* variable */
mrb_value mrb_vm_special_get(mrb_state*, mrb_sym);
void mrb_vm_special_set(mrb_state*, mrb_sym, mrb_value);
mrb_value mrb_vm_cv_get(mrb_state*, mrb_sym);
void mrb_vm_cv_set(mrb_state*, mrb_sym, mrb_value);
mrb_value mrb_vm_const_get(mrb_state*, mrb_sym);
void mrb_vm_const_set(mrb_state*, mrb_sym, mrb_value);
size_t mrb_obj_iv_tbl_memsize(mrb_value);
mrb_value mrb_obj_iv_inspect(mrb_state*, struct RObject*);
void mrb_obj_iv_set_force(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v);
mrb_value mrb_mod_constants(mrb_state *mrb, mrb_value mod);
mrb_value mrb_f_global_variables(mrb_state *mrb, mrb_value self);
mrb_value mrb_obj_instance_variables(mrb_state*, mrb_value);
mrb_value mrb_mod_class_variables(mrb_state*, mrb_value);
mrb_value mrb_mod_cv_get(mrb_state *mrb, struct RClass * c, mrb_sym sym);
mrb_bool mrb_mod_cv_defined(mrb_state *mrb, struct RClass * c, mrb_sym sym);
mrb_bool mrb_ident_p(const char *s, mrb_int len);

/* GC functions */
void mrb_gc_mark_gv(mrb_state*);
void mrb_gc_free_gv(mrb_state*);
void mrb_gc_mark_iv(mrb_state*, struct RObject*);
size_t mrb_gc_mark_iv_size(mrb_state*, struct RObject*);
void mrb_gc_free_iv(mrb_state*, struct RObject*);

/* VM */
mrb_int mrb_ci_bidx(mrb_callinfo *ci);

#ifdef MRB_USE_BIGINT
mrb_value mrb_bint_new_int(mrb_state *mrb, mrb_int x);
mrb_value mrb_bint_new_str(mrb_state *mrb, const char *x, mrb_int len, mrb_int base);
mrb_value mrb_as_bint(mrb_state *mrb, mrb_value x);
mrb_value mrb_bint_add(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_sub(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_mul(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_div(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_divmod(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_add_ii(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_bint_sub_ii(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_bint_mul_ii(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_bint_div_ii(mrb_state *mrb, mrb_int x, mrb_int y);
mrb_value mrb_bint_mod(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_rem(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_pow(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_powm(mrb_state *mrb, mrb_value x, mrb_int y, mrb_value z);
mrb_value mrb_bint_and(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_or(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_xor(mrb_state *mrb, mrb_value x, mrb_value y);
mrb_value mrb_bint_rev(mrb_state *mrb, mrb_value x);
mrb_value mrb_bint_lshift(mrb_state *mrb, mrb_value x, mrb_int width);
mrb_value mrb_bint_rshift(mrb_state *mrb, mrb_value x, mrb_int width);
mrb_value mrb_bint_to_s(mrb_state *mrb, mrb_value x, mrb_int base);
#ifndef MRB_NO_FLOAT
mrb_value mrb_bint_new_float(mrb_state *mrb, mrb_float x);
mrb_float mrb_bint_as_float(mrb_state *mrb, mrb_value x);
#endif
mrb_int mrb_bint_as_int(mrb_state *mrb, mrb_value x);
mrb_int mrb_bint_cmp(mrb_state *mrb, mrb_value x, mrb_value y);
void mrb_gc_free_bint(mrb_state *mrb, struct RBasic *x);
#endif

#endif  /* MRUBY_INTERNAL_H */
