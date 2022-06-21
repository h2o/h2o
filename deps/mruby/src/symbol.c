/*
** symbol.c - Symbol class
**
** See Copyright Notice in mruby.h
*/

#include <string.h>
#include <mruby.h>
#include <mruby/khash.h>
#include <mruby/string.h>
#include <mruby/dump.h>
#include <mruby/class.h>
#include <mruby/presym.h>

#ifndef MRB_NO_PRESYM

#ifndef MRB_PRESYM_SCANNING
/* const uint16_t presym_length_table[]   */
/* const char * const presym_name_table[] */
# include <mruby/presym/table.h>
#endif

static mrb_sym
presym_find(const char *name, size_t len)
{
  if (presym_length_table[MRB_PRESYM_MAX-1] < len) return 0;

  mrb_sym start, idx, presym_size = MRB_PRESYM_MAX;
  int cmp;
  for (start = 0; presym_size != 0; presym_size/=2) {
    idx = start+presym_size/2;
    cmp = (int)len-(int)presym_length_table[idx];
    if (cmp == 0) {
      cmp = memcmp(name, presym_name_table[idx], len);
      if (cmp == 0) return idx+1;
    }
    if (0 < cmp) {
      start = ++idx;
      --presym_size;
    }
  }
  return 0;
}

static const char*
presym_sym2name(mrb_sym sym, mrb_int *lenp)
{
  if (sym > MRB_PRESYM_MAX) return NULL;
  if (lenp) *lenp = presym_length_table[sym-1];
  return presym_name_table[sym-1];
}

#endif  /* MRB_NO_PRESYM */

/* ------------------------------------------------------ */
static void
sym_validate_len(mrb_state *mrb, size_t len)
{
  if (len >= UINT16_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "symbol length too long");
  }
}

#ifdef MRB_USE_ALL_SYMBOLS
# define SYMBOL_INLINE_P(sym) FALSE
# define sym_inline_pack(name, len) 0
# define sym_inline_unpack(sym, buf, lenp) NULL
#else
# define SYMBOL_INLINE_P(sym) ((sym) >= (1<<24))

static const char pack_table[] = "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static mrb_sym
sym_inline_pack(const char *name, size_t len)
{
#if defined(MRB_WORD_BOXING) && defined(MRB_32BIT) && !defined(MRB_WORDBOX_NO_FLOAT_TRUNCATE)
  const size_t pack_length_max = 4;
#else
  const size_t pack_length_max = 5;
#endif

  char c;
  const char *p;
  size_t i;
  mrb_sym sym = 0;

  if (len > pack_length_max) return 0; /* too long */
  if (len == 0) return 0; /* empty string */
  for (i=0; i<len; i++) {
    uint32_t bits;

    c = name[i];
    if (c == 0) return 0;       /* NUL in name */
    p = strchr(pack_table, (int)c);
    if (p == 0) return 0;       /* non alnum char */
    bits = (uint32_t)(p - pack_table)+1;
    sym |= bits<<(24-i*6);
  }
  mrb_assert(SYMBOL_INLINE_P(sym));
  return sym;
}

static const char*
sym_inline_unpack(mrb_sym sym, char *buf, mrb_int *lenp)
{
  int i;

  mrb_assert(SYMBOL_INLINE_P(sym));

  for (i=0; i<5; i++) {
    uint32_t bits = sym>>(24-i*6) & 0x3f;
    if (bits == 0) break;
    buf[i] = pack_table[bits-1];;
  }
  buf[i] = '\0';
  if (lenp) *lenp = i;
  return buf;
}
#endif

static uint8_t
symhash(const char *key, size_t len)
{
    uint32_t hash, i;

    for(hash = i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash & 0xff;
}

size_t mrb_packed_int_len(uint32_t num);
size_t mrb_packed_int_encode(uint32_t num, uint8_t *p, uint8_t *pend);
uint32_t mrb_packed_int_decode(uint8_t *p, uint8_t **newpos);

#define sym_lit_p(mrb, i) (mrb->symflags[i>>3]&(1<<(i&7)))
#define sym_lit_set(mrb, i) mrb->symflags[i>>3]|=(1<<(i&7))
#define sym_flags_clear(mrb, i) mrb->symflags[i>>3]&=~(1<<(i&7))
#define sym_len(mrb, i) (size_t)(sym_lit_p(mrb, i)?strlen(mrb->symtbl[i]):mrb_packed_int_decode(mrb->symtbl[i],NULL))

static mrb_bool
sym_check(mrb_state *mrb, const char *name, size_t len, mrb_sym i)
{
  const char *symname = mrb->symtbl[i];
  size_t symlen;

  if (sym_lit_p(mrb, i)) {
    symlen = strlen(symname);
  }
  else {
    /* length in BER */
    symlen = mrb_packed_int_decode((uint8_t*)symname, (uint8_t**)&symname);
  }
  if (len == symlen && memcmp(symname, name, len) == 0) {
    return TRUE;
  }
  return FALSE;
}

static mrb_sym
find_symbol(mrb_state *mrb, const char *name, size_t len, uint8_t *hashp)
{
  mrb_sym i;
  uint8_t hash;

#ifndef MRB_NO_PRESYM
  /* presym */
  i = presym_find(name, len);
  if (i > 0) return i;
#endif

  /* inline symbol */
  i = sym_inline_pack(name, len);
  if (i > 0) return i;

  hash = symhash(name, len);
  if (hashp) *hashp = hash;

  i = mrb->symhash[hash];
  if (i == 0) return 0;
  for (;;) {
    if (sym_check(mrb, name, len, i)) {
      return (i+MRB_PRESYM_MAX);
    }
    uint8_t diff = mrb->symlink[i];
    if (diff == 0xff) {
      i -= 0xff;
      while (i > 0) {
        if (sym_check(mrb, name, len, i)) {
          return (i+MRB_PRESYM_MAX);
        }
        i--;
      }
      return 0;
    }
    if (diff == 0) return 0;
    i -= diff;
  }
  return 0;
}

static mrb_sym
sym_intern(mrb_state *mrb, const char *name, size_t len, mrb_bool lit)
{
  mrb_sym sym;
  uint8_t hash;

  sym_validate_len(mrb, len);
  sym = find_symbol(mrb, name, len, &hash);
  if (sym > 0) return sym;

  /* registering a new symbol */
  sym = mrb->symidx + 1;
  if (mrb->symcapa <= sym) {
    size_t symcapa = mrb->symcapa;
    if (symcapa == 0) symcapa = 100;
    else symcapa = (size_t)(symcapa * 6 / 5);
    mrb->symtbl = (const char**)mrb_realloc(mrb, mrb->symtbl, sizeof(char*)*symcapa);
    mrb->symflags = (uint8_t*)mrb_realloc(mrb, mrb->symflags, symcapa/8+1);
    memset(mrb->symflags+mrb->symcapa/8+1, 0, (symcapa-mrb->symcapa)/8);
    mrb->symlink = (uint8_t*)mrb_realloc(mrb, mrb->symlink, symcapa);
    mrb->symcapa = symcapa;
  }
  sym_flags_clear(mrb, sym);
  if ((lit || mrb_ro_data_p(name)) && strlen(name) == len) {
    sym_lit_set(mrb, sym);
    mrb->symtbl[sym] = name;
  }
  else {
    int ilen = mrb_packed_int_len(len);
    char *p = (char *)mrb_malloc(mrb, len+ilen+1);
    mrb_packed_int_encode(len, (uint8_t*)p, (uint8_t*)p+ilen);
    memcpy(p+ilen, name, len);
    p[ilen+len] = 0;
    mrb->symtbl[sym] = p;
  }
  if (mrb->symhash[hash]) {
    mrb_sym i = sym - mrb->symhash[hash];
    if (i > 0xff)
      mrb->symlink[sym] = 0xff;
    else
      mrb->symlink[sym] = i;
  }
  else {
    mrb->symlink[sym] = 0;
  }
  mrb->symhash[hash] = mrb->symidx = sym;

  return (sym+MRB_PRESYM_MAX);
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

MRB_API mrb_sym
mrb_intern_check(mrb_state *mrb, const char *name, size_t len)
{
  mrb_sym sym;

  sym_validate_len(mrb, len);
  sym = find_symbol(mrb, name, len, NULL);
  if (sym > 0) return sym;
  return 0;
}

MRB_API mrb_value
mrb_check_intern(mrb_state *mrb, const char *name, size_t len)
{
  mrb_sym sym = mrb_intern_check(mrb, name, len);
  if (sym == 0) return mrb_nil_value();
  return mrb_symbol_value(sym);
}

MRB_API mrb_sym
mrb_intern_check_cstr(mrb_state *mrb, const char *name)
{
  return mrb_intern_check(mrb, name, strlen(name));
}

MRB_API mrb_value
mrb_check_intern_cstr(mrb_state *mrb, const char *name)
{
  mrb_sym sym = mrb_intern_check_cstr(mrb, name);
  if (sym == 0) return mrb_nil_value();
  return mrb_symbol_value(sym);
}

MRB_API mrb_sym
mrb_intern_check_str(mrb_state *mrb, mrb_value str)
{
  return mrb_intern_check(mrb, RSTRING_PTR(str), RSTRING_LEN(str));
}

MRB_API mrb_value
mrb_check_intern_str(mrb_state *mrb, mrb_value str)
{
  mrb_sym sym = mrb_intern_check_str(mrb, str);
  if (sym == 0) return mrb_nil_value();
  return mrb_symbol_value(sym);
}

static const char*
sym2name_len(mrb_state *mrb, mrb_sym sym, char *buf, mrb_int *lenp)
{
  if (sym == 0) goto outofsym;
  if (SYMBOL_INLINE_P(sym)) return sym_inline_unpack(sym, buf, lenp);

#ifndef MRB_NO_PRESYM
  {
    const char *name = presym_sym2name(sym, lenp);
    if (name) return name;
  }
#endif
  sym -= MRB_PRESYM_MAX;

  if (mrb->symidx < sym) {
  outofsym:
    if (lenp) *lenp = 0;
    return NULL;
  }

  const char *symname = mrb->symtbl[sym];
  if (!sym_lit_p(mrb, sym)) {
    size_t len = mrb_packed_int_decode((uint8_t*)symname, (uint8_t**)&symname);
    if (lenp) *lenp = (mrb_int)len;
  }
  else if (lenp) {
    *lenp = (mrb_int)strlen(symname);
  }
  return symname;
}

MRB_API const char*
mrb_sym_name_len(mrb_state *mrb, mrb_sym sym, mrb_int *lenp)
{
#ifdef MRB_USE_ALL_SYMBOLS
  return sym2name_len(mrb, sym, NULL, lenp);
#else
  return sym2name_len(mrb, sym, mrb->symbuf, lenp);
#endif
}

void
mrb_free_symtbl(mrb_state *mrb)
{
  mrb_sym i, lim;

  for (i=1, lim=mrb->symidx+1; i<lim; i++) {
    if (!sym_lit_p(mrb, i)) {
      mrb_free(mrb, (char*)mrb->symtbl[i]);
    }
  }
  mrb_free(mrb, mrb->symtbl);
  mrb_free(mrb, mrb->symlink);
  mrb_free(mrb, mrb->symflags);
}

void
mrb_init_symtbl(mrb_state *mrb)
{
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

/* 15.2.11.3.2  */
/* 15.2.11.3.3  */
/*
 *  call-seq:
 *     sym.to_s      -> string
 *
 *  Returns the name or string corresponding to <i>sym</i>.
 *
 *     :fred.to_s   #=> "fred"
 */
static mrb_value
sym_to_s(mrb_state *mrb, mrb_value sym)
{
  return mrb_sym_str(mrb, mrb_symbol(sym));
}

/*
 *  call-seq:
 *     sym.name   -> string
 *
 *  Returns the name or string corresponding to <i>sym</i>. Unlike #to_s, the
 *  returned string is frozen.
 *
 *     :fred.name         #=> "fred"
 *     :fred.name.frozen? #=> true
 */
static mrb_value
sym_name(mrb_state *mrb, mrb_value vsym)
{
  mrb_sym sym = mrb_symbol(vsym);
  mrb_int len;
  const char *name = mrb_sym_name_len(mrb, sym, &len);

  mrb_assert(name != NULL);
  if (SYMBOL_INLINE_P(sym)) {
    return mrb_str_new_frozen(mrb, name, len);
  }
  return mrb_str_new_static_frozen(mrb, name, len);
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

  name = mrb_sym_name_len(mrb, id, &len);
  str = mrb_str_new(mrb, NULL, len+1);
  sp = RSTRING_PTR(str);
  sp[0] = ':';
  memcpy(sp+1, name, len);
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  if (!symname_p(name) || strlen(name) != (size_t)len) {
    str = mrb_str_inspect(mrb, str);
    sp = RSTRING_PTR(str);
    sp[0] = ':';
    sp[1] = '"';
  }
#ifdef MRB_UTF8_STRING
  if (SYMBOL_INLINE_P(id)) RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
#endif
  return str;
}

MRB_API mrb_value
mrb_sym_str(mrb_state *mrb, mrb_sym sym)
{
  mrb_int len;
  const char *name = mrb_sym_name_len(mrb, sym, &len);

  if (!name) return mrb_undef_value(); /* can't happen */
  if (SYMBOL_INLINE_P(sym)) {
    mrb_value str = mrb_str_new(mrb, name, len);
    RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
    return str;
  }
  return mrb_str_new_static(mrb, name, len);
}

static const char*
sym_cstr(mrb_state *mrb, mrb_sym sym, mrb_bool dump)
{
  mrb_int len;
  const char *name = mrb_sym_name_len(mrb, sym, &len);

  if (!name) return NULL;
  if (strlen(name) == (size_t)len && (!dump || symname_p(name))) {
    return name;
  }
  else {
    mrb_value str = mrb_str_new_static(mrb, name, len);
    str = mrb_str_dump(mrb, str);
    return RSTRING_PTR(str);
  }
}

MRB_API const char*
mrb_sym_name(mrb_state *mrb, mrb_sym sym)
{
  return sym_cstr(mrb, sym, FALSE);
}

MRB_API const char*
mrb_sym_dump(mrb_state *mrb, mrb_sym sym)
{
  return sym_cstr(mrb, sym, TRUE);
}

#define lesser(a,b) (((a)>(b))?(b):(a))

static mrb_value
sym_cmp(mrb_state *mrb, mrb_value s1)
{
  mrb_value s2 = mrb_get_arg1(mrb);
  mrb_sym sym1, sym2;

  if (!mrb_symbol_p(s2)) return mrb_nil_value();
  sym1 = mrb_symbol(s1);
  sym2 = mrb_symbol(s2);
  if (sym1 == sym2) return mrb_fixnum_value(0);
  else {
    const char *p1, *p2;
    int retval;
    mrb_int len, len1, len2;
    char buf1[8], buf2[8];

    p1 = sym2name_len(mrb, sym1, buf1, &len1);
    p2 = sym2name_len(mrb, sym2, buf2, &len2);
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

  mrb->symbol_class = sym = mrb_define_class(mrb, "Symbol", mrb->object_class);  /* 15.2.11 */
  MRB_SET_INSTANCE_TT(sym, MRB_TT_SYMBOL);
  mrb_undef_class_method(mrb,  sym, "new");

  mrb_define_method(mrb, sym, "to_s",    sym_to_s,    MRB_ARGS_NONE());          /* 15.2.11.3.3 */
  mrb_define_method(mrb, sym, "name",    sym_name,    MRB_ARGS_NONE());
  mrb_define_method(mrb, sym, "to_sym",  sym_to_sym,  MRB_ARGS_NONE());          /* 15.2.11.3.4 */
  mrb_define_method(mrb, sym, "inspect", sym_inspect, MRB_ARGS_NONE());          /* 15.2.11.3.5(x) */
  mrb_define_method(mrb, sym, "<=>",     sym_cmp,     MRB_ARGS_REQ(1));
}
