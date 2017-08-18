/*
** symbol.c - Symbol class
**
** See Copyright Notice in mruby.h
*/

#include <limits.h>
#include <string.h>
#include <mruby.h>
#include <mruby/khash.h>
#include <mruby/string.h>
#include <mruby/dump.h>
#include <mruby/class.h>

/* ------------------------------------------------------ */
typedef struct symbol_name {
  mrb_bool lit : 1;
  uint16_t len;
  const char *name;
} symbol_name;

static inline khint_t
sym_hash_func(mrb_state *mrb, mrb_sym s)
{
  khint_t h = 0;
  size_t i, len = mrb->symtbl[s].len;
  const char *p = mrb->symtbl[s].name;

  for (i=0; i<len; i++) {
    h = (h << 5) - h + *p++;
  }
  return h;
}
#define sym_hash_equal(mrb,a, b) (mrb->symtbl[a].len == mrb->symtbl[b].len && memcmp(mrb->symtbl[a].name, mrb->symtbl[b].name, mrb->symtbl[a].len) == 0)

KHASH_DECLARE(n2s, mrb_sym, mrb_sym, FALSE)
KHASH_DEFINE (n2s, mrb_sym, mrb_sym, FALSE, sym_hash_func, sym_hash_equal)
/* ------------------------------------------------------ */

static void
sym_validate_len(mrb_state *mrb, size_t len)
{
  if (len >= RITE_LV_NULL_MARK) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "symbol length too long");
  }
}

static mrb_sym
sym_intern(mrb_state *mrb, const char *name, size_t len, mrb_bool lit)
{
  khash_t(n2s) *h = mrb->name2sym;
  symbol_name *sname = mrb->symtbl; /* symtbl[0] for working memory */
  khiter_t k;
  mrb_sym sym;
  char *p;

  sym_validate_len(mrb, len);
  if (sname) {
    sname->lit = lit;
    sname->len = (uint16_t)len;
    sname->name = name;
    k = kh_get(n2s, mrb, h, 0);
    if (k != kh_end(h))
      return kh_key(h, k);
  }

  /* registering a new symbol */
  sym = ++mrb->symidx;
  if (mrb->symcapa < sym) {
    if (mrb->symcapa == 0) mrb->symcapa = 100;
    else mrb->symcapa = (size_t)(mrb->symcapa * 1.2);
    mrb->symtbl = (symbol_name*)mrb_realloc(mrb, mrb->symtbl, sizeof(symbol_name)*(mrb->symcapa+1));
  }
  sname = &mrb->symtbl[sym];
  sname->len = (uint16_t)len;
  if (lit || mrb_ro_data_p(name)) {
    sname->name = name;
    sname->lit = TRUE;
  }
  else {
    p = (char *)mrb_malloc(mrb, len+1);
    memcpy(p, name, len);
    p[len] = 0;
    sname->name = (const char*)p;
    sname->lit = FALSE;
  }
  kh_put(n2s, mrb, h, sym);

  return sym;
}

MRB_API mrb_sym
mrb_intern(mrb_state *mrb, const char *name, size_t len)
{
  return sym_intern(mrb, name, len, FALSE);
}

MRB_API mrb_sym
mrb_intern_static(mrb_state *mrb, const char *name, size_t len)
{
  return sym_intern(mrb, name, len, TRUE);
}

MRB_API mrb_sym
mrb_intern_cstr(mrb_state *mrb, const char *name)
{
  return mrb_intern(mrb, name, strlen(name));
}

MRB_API mrb_sym
mrb_intern_str(mrb_state *mrb, mrb_value str)
{
  return mrb_intern(mrb, RSTRING_PTR(str), RSTRING_LEN(str));
}

MRB_API mrb_value
mrb_check_intern(mrb_state *mrb, const char *name, size_t len)
{
  khash_t(n2s) *h = mrb->name2sym;
  symbol_name *sname = mrb->symtbl;
  khiter_t k;

  sym_validate_len(mrb, len);
  sname->len = (uint16_t)len;
  sname->name = name;

  k = kh_get(n2s, mrb, h, 0);
  if (k != kh_end(h)) {
    return mrb_symbol_value(kh_key(h, k));
  }
  return mrb_nil_value();
}

MRB_API mrb_value
mrb_check_intern_cstr(mrb_state *mrb, const char *name)
{
  return mrb_check_intern(mrb, name, (mrb_int)strlen(name));
}

MRB_API mrb_value
mrb_check_intern_str(mrb_state *mrb, mrb_value str)
{
  return mrb_check_intern(mrb, RSTRING_PTR(str), RSTRING_LEN(str));
}

/* lenp must be a pointer to a size_t variable */
MRB_API const char*
mrb_sym2name_len(mrb_state *mrb, mrb_sym sym, mrb_int *lenp)
{
  if (sym == 0 || mrb->symidx < sym) {
    if (lenp) *lenp = 0;
    return NULL;
  }

  if (lenp) *lenp = mrb->symtbl[sym].len;
  return mrb->symtbl[sym].name;
}

void
mrb_free_symtbl(mrb_state *mrb)
{
  mrb_sym i, lim;

  for (i=1, lim=mrb->symidx+1; i<lim; i++) {
    if (!mrb->symtbl[i].lit) {
      mrb_free(mrb, (char*)mrb->symtbl[i].name);
    }
  }
  mrb_free(mrb, mrb->symtbl);
  kh_destroy(n2s, mrb, mrb->name2sym);
}

void
mrb_init_symtbl(mrb_state *mrb)
{
  mrb->name2sym = kh_init(n2s, mrb);
}

/**********************************************************************
 * Document-class: Symbol
 *
 *  <code>Symbol</code> objects represent names and some strings
 *  inside the Ruby
 *  interpreter. They are generated using the <code>:name</code> and
 *  <code>:"string"</code> literals
 *  syntax, and by the various <code>to_sym</code> methods. The same
 *  <code>Symbol</code> object will be created for a given name or string
 *  for the duration of a program's execution, regardless of the context
 *  or meaning of that name. Thus if <code>Fred</code> is a constant in
 *  one context, a method in another, and a class in a third, the
 *  <code>Symbol</code> <code>:Fred</code> will be the same object in
 *  all three contexts.
 *
 *     module One
 *       class Fred
 *       end
 *       $f1 = :Fred
 *     end
 *     module Two
 *       Fred = 1
 *       $f2 = :Fred
 *     end
 *     def Fred()
 *     end
 *     $f3 = :Fred
 *     $f1.object_id   #=> 2514190
 *     $f2.object_id   #=> 2514190
 *     $f3.object_id   #=> 2514190
 *
 */


/* 15.2.11.3.1  */
/*
 *  call-seq:
 *     sym == obj   -> true or false
 *
 *  Equality---If <i>sym</i> and <i>obj</i> are exactly the same
 *  symbol, returns <code>true</code>.
 */

static mrb_value
sym_equal(mrb_state *mrb, mrb_value sym1)
{
  mrb_value sym2;

  mrb_get_args(mrb, "o", &sym2);

  return mrb_bool_value(mrb_obj_equal(mrb, sym1, sym2));
}

/* 15.2.11.3.2  */
/* 15.2.11.3.3  */
/*
 *  call-seq:
 *     sym.id2name   -> string
 *     sym.to_s      -> string
 *
 *  Returns the name or string corresponding to <i>sym</i>.
 *
 *     :fred.id2name   #=> "fred"
 */
static mrb_value
mrb_sym_to_s(mrb_state *mrb, mrb_value sym)
{
  mrb_sym id = mrb_symbol(sym);
  const char *p;
  mrb_int len;

  p = mrb_sym2name_len(mrb, id, &len);
  return mrb_str_new_static(mrb, p, len);
}

/* 15.2.11.3.4  */
/*
 * call-seq:
 *   sym.to_sym   -> sym
 *   sym.intern   -> sym
 *
 * In general, <code>to_sym</code> returns the <code>Symbol</code> corresponding
 * to an object. As <i>sym</i> is already a symbol, <code>self</code> is returned
 * in this case.
 */

static mrb_value
sym_to_sym(mrb_state *mrb, mrb_value sym)
{
  return sym;
}

/* 15.2.11.3.5(x)  */
/*
 *  call-seq:
 *     sym.inspect    -> string
 *
 *  Returns the representation of <i>sym</i> as a symbol literal.
 *
 *     :fred.inspect   #=> ":fred"
 */

#if __STDC__
# define SIGN_EXTEND_CHAR(c) ((signed char)(c))
#else  /* not __STDC__ */
/* As in Harbison and Steele.  */
# define SIGN_EXTEND_CHAR(c) ((((unsigned char)(c)) ^ 128) - 128)
#endif
#define is_identchar(c) (SIGN_EXTEND_CHAR(c)!=-1&&(ISALNUM(c) || (c) == '_'))

static mrb_bool
is_special_global_name(const char* m)
{
  switch (*m) {
    case '~': case '*': case '$': case '?': case '!': case '@':
    case '/': case '\\': case ';': case ',': case '.': case '=':
    case ':': case '<': case '>': case '\"':
    case '&': case '`': case '\'': case '+':
    case '0':
      ++m;
      break;
    case '-':
      ++m;
      if (is_identchar(*m)) m += 1;
      break;
    default:
      if (!ISDIGIT(*m)) return FALSE;
      do ++m; while (ISDIGIT(*m));
      break;
  }
  return !*m;
}

static mrb_bool
symname_p(const char *name)
{
  const char *m = name;
  mrb_bool localid = FALSE;

  if (!m) return FALSE;
  switch (*m) {
    case '\0':
      return FALSE;

    case '$':
      if (is_special_global_name(++m)) return TRUE;
      goto id;

    case '@':
      if (*++m == '@') ++m;
      goto id;

    case '<':
      switch (*++m) {
        case '<': ++m; break;
        case '=': if (*++m == '>') ++m; break;
        default: break;
      }
      break;

    case '>':
      switch (*++m) {
        case '>': case '=': ++m; break;
        default: break;
      }
      break;

    case '=':
      switch (*++m) {
        case '~': ++m; break;
        case '=': if (*++m == '=') ++m; break;
        default: return FALSE;
      }
      break;

    case '*':
      if (*++m == '*') ++m;
      break;
    case '!':
      switch (*++m) {
        case '=': case '~': ++m;
      }
      break;
    case '+': case '-':
      if (*++m == '@') ++m;
      break;
    case '|':
      if (*++m == '|') ++m;
      break;
    case '&':
      if (*++m == '&') ++m;
      break;

    case '^': case '/': case '%': case '~': case '`':
      ++m;
      break;

    case '[':
      if (*++m != ']') return FALSE;
      if (*++m == '=') ++m;
      break;

    default:
      localid = !ISUPPER(*m);
id:
      if (*m != '_' && !ISALPHA(*m)) return FALSE;
      while (is_identchar(*m)) m += 1;
      if (localid) {
        switch (*m) {
          case '!': case '?': case '=': ++m;
          default: break;
            }
        }
      break;
  }
  return *m ? FALSE : TRUE;
}

static mrb_value
sym_inspect(mrb_state *mrb, mrb_value sym)
{
  mrb_value str;
  const char *name;
  mrb_int len;
  mrb_sym id = mrb_symbol(sym);
  char *sp;

  name = mrb_sym2name_len(mrb, id, &len);
  str = mrb_str_new(mrb, 0, len+1);
  sp = RSTRING_PTR(str);
  RSTRING_PTR(str)[0] = ':';
  memcpy(sp+1, name, len);
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  if (!symname_p(name) || strlen(name) != (size_t)len) {
    str = mrb_str_dump(mrb, str);
    sp = RSTRING_PTR(str);
    sp[0] = ':';
    sp[1] = '"';
  }
  return str;
}

MRB_API mrb_value
mrb_sym2str(mrb_state *mrb, mrb_sym sym)
{
  mrb_int len;
  const char *name = mrb_sym2name_len(mrb, sym, &len);

  if (!name) return mrb_undef_value(); /* can't happen */
  return mrb_str_new_static(mrb, name, len);
}

MRB_API const char*
mrb_sym2name(mrb_state *mrb, mrb_sym sym)
{
  mrb_int len;
  const char *name = mrb_sym2name_len(mrb, sym, &len);

  if (!name) return NULL;
  if (symname_p(name) && strlen(name) == (size_t)len) {
    return name;
  }
  else {
    mrb_value str = mrb_str_dump(mrb, mrb_str_new_static(mrb, name, len));
    return RSTRING_PTR(str);
  }
}

#define lesser(a,b) (((a)>(b))?(b):(a))

static mrb_value
sym_cmp(mrb_state *mrb, mrb_value s1)
{
  mrb_value s2;
  mrb_sym sym1, sym2;

  mrb_get_args(mrb, "o", &s2);
  if (mrb_type(s2) != MRB_TT_SYMBOL) return mrb_nil_value();
  sym1 = mrb_symbol(s1);
  sym2 = mrb_symbol(s2);
  if (sym1 == sym2) return mrb_fixnum_value(0);
  else {
    const char *p1, *p2;
    int retval;
    mrb_int len, len1, len2;

    p1 = mrb_sym2name_len(mrb, sym1, &len1);
    p2 = mrb_sym2name_len(mrb, sym2, &len2);
    len = lesser(len1, len2);
    retval = memcmp(p1, p2, len);
    if (retval == 0) {
      if (len1 == len2) return mrb_fixnum_value(0);
      if (len1 > len2)  return mrb_fixnum_value(1);
      return mrb_fixnum_value(-1);
    }
    if (retval > 0) return mrb_fixnum_value(1);
    return mrb_fixnum_value(-1);
  }
}

void
mrb_init_symbol(mrb_state *mrb)
{
  struct RClass *sym;

  mrb->symbol_class = sym = mrb_define_class(mrb, "Symbol", mrb->object_class);                 /* 15.2.11 */
  MRB_SET_INSTANCE_TT(sym, MRB_TT_SYMBOL);
  mrb_undef_class_method(mrb,  sym, "new");

  mrb_define_method(mrb, sym, "===",             sym_equal,      MRB_ARGS_REQ(1));              /* 15.2.11.3.1  */
  mrb_define_method(mrb, sym, "id2name",         mrb_sym_to_s,   MRB_ARGS_NONE());              /* 15.2.11.3.2  */
  mrb_define_method(mrb, sym, "to_s",            mrb_sym_to_s,   MRB_ARGS_NONE());              /* 15.2.11.3.3  */
  mrb_define_method(mrb, sym, "to_sym",          sym_to_sym,     MRB_ARGS_NONE());              /* 15.2.11.3.4  */
  mrb_define_method(mrb, sym, "inspect",         sym_inspect,    MRB_ARGS_NONE());              /* 15.2.11.3.5(x)  */
  mrb_define_method(mrb, sym, "<=>",             sym_cmp,        MRB_ARGS_REQ(1));
}
