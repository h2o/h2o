/*
** cdump.c - mruby binary dumper (in C)
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/string.h>
#include <mruby/dump.h>
#include <mruby/irep.h>
#include <mruby/debug.h>

#include <string.h>

#ifndef MRB_NO_STDIO

#ifndef MRB_NO_FLOAT
#include <mruby/endian.h>
#define MRB_FLOAT_FMT "%.17g"
#endif

static int
cdump_pool(mrb_state *mrb, const mrb_pool_value *p, FILE *fp)
{
  if (p->tt & IREP_TT_NFLAG) {  /* number */
    switch (p->tt) {
#ifdef MRB_64BIT
    case IREP_TT_INT64:
      if (p->u.i64 < INT32_MIN || INT32_MAX < p->u.i64) {
        fprintf(fp, "{IREP_TT_INT64, {.i64=%" PRId64 "}},\n", p->u.i64);
      }
      else {
        fprintf(fp, "{IREP_TT_INT32, {.i32=%" PRId32 "}},\n", (int32_t)p->u.i64);
      }
      break;
#endif
    case IREP_TT_INT32:
      fprintf(fp, "{IREP_TT_INT32, {.i32=%" PRId32 "}},\n", p->u.i32);
      break;
    case IREP_TT_FLOAT:
#ifndef MRB_NO_FLOAT
      if (p->u.f == 0) {
        fprintf(fp, "{IREP_TT_FLOAT, {.f=%#.1f}},\n", p->u.f);
      }
      else {
        fprintf(fp, "{IREP_TT_FLOAT, {.f=" MRB_FLOAT_FMT "}},\n", p->u.f);
      }
#endif
      break;
    case IREP_TT_BIGINT:
      {
        const char *s = p->u.str;
        int len = s[0]+2;
        fputs("{IREP_TT_BIGINT, {\"", fp);
        for (int i=0; i<len; i++) {
          fprintf(fp, "\\x%02x", (int)s[i]&0xff);
        }
        fputs("\"}},\n", fp);
      }
      break;
    }
  }
  else {                        /* string */
    int i, len = p->tt>>2;
    const char *s = p->u.str;
    fprintf(fp, "{IREP_TT_STR|(%d<<2), {\"", len);
    for (i=0; i<len; i++) {
      fprintf(fp, "\\x%02x", (int)s[i]&0xff);
    }
    fputs("\"}},\n", fp);
  }
  return MRB_DUMP_OK;
}

static mrb_bool
sym_name_word_p(const char *name, mrb_int len)
{
  if (len == 0) return FALSE;
  if (name[0] != '_' && !ISALPHA(name[0])) return FALSE;
  for (int i = 1; i < len; i++) {
    if (name[i] != '_' && !ISALNUM(name[i])) return FALSE;
  }
  return TRUE;
}

static mrb_bool
sym_name_with_equal_p(const char *name, mrb_int len)
{
  return len >= 2 && name[len-1] == '=' && sym_name_word_p(name, len-1);
}

static mrb_bool
sym_name_with_question_mark_p(const char *name, mrb_int len)
{
  return len >= 2 && name[len-1] == '?' && sym_name_word_p(name, len-1);
}

static mrb_bool
sym_name_with_bang_p(const char *name, mrb_int len)
{
  return len >= 2 && name[len-1] == '!' && sym_name_word_p(name, len-1);
}

static mrb_bool
sym_name_ivar_p(const char *name, mrb_int len)
{
  return len >= 2 && name[0] == '@' && sym_name_word_p(name+1, len-1);
}

static mrb_bool
sym_name_cvar_p(const char *name, mrb_int len)
{
  return len >= 3 && name[0] == '@' && sym_name_ivar_p(name+1, len-1);
}

#define OPERATOR_SYMBOL(sym_name, name) {name, sym_name, sizeof(sym_name)-1}
struct operator_symbol {
  const char *name;
  const char *sym_name;
  uint16_t sym_name_len;
};
static const struct operator_symbol operator_table[] = {
  OPERATOR_SYMBOL("!", "not"),
  OPERATOR_SYMBOL("%", "mod"),
  OPERATOR_SYMBOL("&", "and"),
  OPERATOR_SYMBOL("*", "mul"),
  OPERATOR_SYMBOL("+", "add"),
  OPERATOR_SYMBOL("-", "sub"),
  OPERATOR_SYMBOL("/", "div"),
  OPERATOR_SYMBOL("<", "lt"),
  OPERATOR_SYMBOL(">", "gt"),
  OPERATOR_SYMBOL("^", "xor"),
  OPERATOR_SYMBOL("`", "tick"),
  OPERATOR_SYMBOL("|", "or"),
  OPERATOR_SYMBOL("~", "neg"),
  OPERATOR_SYMBOL("!=", "neq"),
  OPERATOR_SYMBOL("!~", "nmatch"),
  OPERATOR_SYMBOL("&&", "andand"),
  OPERATOR_SYMBOL("**", "pow"),
  OPERATOR_SYMBOL("+@", "plus"),
  OPERATOR_SYMBOL("-@", "minus"),
  OPERATOR_SYMBOL("<<", "lshift"),
  OPERATOR_SYMBOL("<=", "le"),
  OPERATOR_SYMBOL("==", "eq"),
  OPERATOR_SYMBOL("=~", "match"),
  OPERATOR_SYMBOL(">=", "ge"),
  OPERATOR_SYMBOL(">>", "rshift"),
  OPERATOR_SYMBOL("[]", "aref"),
  OPERATOR_SYMBOL("||", "oror"),
  OPERATOR_SYMBOL("<=>", "cmp"),
  OPERATOR_SYMBOL("===", "eqq"),
  OPERATOR_SYMBOL("[]=", "aset"),
};

static const char*
sym_operator_name(const char *sym_name, mrb_int len)
{
  mrb_sym table_size = sizeof(operator_table)/sizeof(struct operator_symbol);
  if (operator_table[table_size-1].sym_name_len < len) return NULL;

  mrb_sym start, idx;
  int cmp;
  const struct operator_symbol *op_sym;
  for (start = 0; table_size != 0; table_size/=2) {
    idx = start+table_size/2;
    op_sym = &operator_table[idx];
    cmp = (int)len-(int)op_sym->sym_name_len;
    if (cmp == 0) {
      cmp = memcmp(sym_name, op_sym->sym_name, len);
      if (cmp == 0) return op_sym->name;
    }
    if (0 < cmp) {
      start = ++idx;
      --table_size;
    }
  }
  return NULL;
}

static const char*
sym_var_name(mrb_state *mrb, const char *initname, const char *key, int n)
{
  char buf[32];
  mrb_value s = mrb_str_new_cstr(mrb, initname);
  mrb_str_cat_lit(mrb, s, "_");
  mrb_str_cat_cstr(mrb, s, key);
  mrb_str_cat_lit(mrb, s, "_");
  snprintf(buf, sizeof(buf), "%d", n);
  mrb_str_cat_cstr(mrb, s, buf);
  return RSTRING_PTR(s);
}

static int
cdump_sym(mrb_state *mrb, mrb_sym sym, const char *var_name, int idx, mrb_value init_syms_code, FILE *fp)
{
  if (sym == 0) return MRB_DUMP_INVALID_ARGUMENT;

  mrb_int len;
  const char *name = mrb_sym_name_len(mrb, sym, &len), *op_name;
  if (!name) return MRB_DUMP_INVALID_ARGUMENT;
  if (sym_name_word_p(name, len)) {
    fprintf(fp, "MRB_SYM(%s)", name);
  }
  else if (sym_name_with_equal_p(name, len)) {
    fprintf(fp, "MRB_SYM_E(%.*s)", (int)(len-1), name);
  }
  else if (sym_name_with_question_mark_p(name, len)) {
    fprintf(fp, "MRB_SYM_Q(%.*s)", (int)(len-1), name);
  }
  else if (sym_name_with_bang_p(name, len)) {
    fprintf(fp, "MRB_SYM_B(%.*s)", (int)(len-1), name);
  }
  else if (sym_name_ivar_p(name, len)) {
    fprintf(fp, "MRB_IVSYM(%s)", name+1);
  }
  else if (sym_name_cvar_p(name, len)) {
    fprintf(fp, "MRB_CVSYM(%s)", name+2);
  }
  else if ((op_name = sym_operator_name(name, len))) {
    fprintf(fp, "MRB_OPSYM(%s)", op_name);
  }
  else {
    char buf[32];
    mrb_value name_obj = mrb_str_new(mrb, name, len);
    mrb_str_cat_lit(mrb, init_syms_code, "  ");
    mrb_str_cat_cstr(mrb, init_syms_code, var_name);
    snprintf(buf, sizeof(buf), "[%d] = ", idx);
    mrb_str_cat_cstr(mrb, init_syms_code, buf);
    mrb_str_cat_lit(mrb, init_syms_code, "mrb_intern_lit(mrb, ");
    mrb_str_cat_str(mrb, init_syms_code, mrb_str_dump(mrb, name_obj));
    mrb_str_cat_lit(mrb, init_syms_code, ");\n");
    fputs("0", fp);
  }
  fputs(", ", fp);
  return MRB_DUMP_OK;
}

static int
cdump_syms(mrb_state *mrb, const char *name, const char *key, int n, int syms_len, const mrb_sym *syms, mrb_value init_syms_code, FILE *fp)
{
  int ai = mrb_gc_arena_save(mrb);
  mrb_int code_len = RSTRING_LEN(init_syms_code);
  const char *var_name = sym_var_name(mrb, name, key, n);
  fprintf(fp, "mrb_DEFINE_SYMS_VAR(%s, %d, (", var_name, syms_len);
  for (int i=0; i<syms_len; i++) {
    cdump_sym(mrb, syms[i], var_name, i, init_syms_code, fp);
  }
  fputs("), ", fp);
  if (code_len == RSTRING_LEN(init_syms_code)) fputs("const", fp);
  fputs(");\n", fp);
  mrb_gc_arena_restore(mrb, ai);
  return MRB_DUMP_OK;
}

//Handle the simple/common case of debug_info:
// - 1 file associated with a single irep
// - mrb_debug_line_ary format only
static int
simple_debug_info(mrb_irep_debug_info *info)
{
  if (!info || info->flen != 1) {
    return 0;
  }
  return 1;
}

//Adds debug information to c-structs and
//adds filenames in init_syms_code block
static int
cdump_debug(mrb_state *mrb, const char *name, int n, mrb_irep_debug_info *info,
    mrb_value init_syms_code, FILE *fp)
{
  char buffer[256];
  const char *filename;
  mrb_int file_len;
  int len, i;
  const char *line_type = "mrb_debug_line_ary";

  if (!simple_debug_info(info))
    return MRB_DUMP_INVALID_IREP;

  len = info->files[0]->line_entry_count;

  filename = mrb_sym_name_len(mrb, info->files[0]->filename_sym, &file_len);
  snprintf(buffer, sizeof(buffer), "  %s_debug_file_%d.filename_sym = mrb_intern_lit(mrb,\"",
      name, n);
  mrb_str_cat_cstr(mrb, init_syms_code, buffer);
  mrb_str_cat_cstr(mrb, init_syms_code, filename);
  mrb_str_cat_cstr(mrb, init_syms_code, "\");\n");

  switch (info->files[0]->line_type) {
  case mrb_debug_line_ary:
    fprintf(fp, "static uint16_t %s_debug_lines_%d[%d] = {", name, n, len);
    for (i=0; i<len; i++) {
      if (i%10 == 0) fputs("\n", fp);
      fprintf(fp, "0x%04x,", info->files[0]->lines.ary[i]);
    }
    fputs("};\n", fp);
    break;

  case mrb_debug_line_flat_map:
    line_type = "mrb_debug_line_flat_map";
    fprintf(fp, "static struct mrb_irep_debug_info_line %s_debug_lines_%d[%d] = {", name, n, len);
    for (i=0; i<len; i++) {
      mrb_irep_debug_info_line *fmap = &info->files[0]->lines.flat_map[i];
      fprintf(fp, "\t{.start_pos=0x%04x,.line=%d},\n", fmap->start_pos, fmap->line);
    }
    fputs("};\n", fp);
    break;

  case mrb_debug_line_packed_map:
    line_type = "mrb_debug_line_packed_map";
    fprintf(fp, "static char %s_debug_lines_%d[] = \"", name, n);
    uint8_t *pmap = info->files[0]->lines.packed_map;
    for (i=0; i<len; i++) {
      fprintf(fp, "\\x%02x", pmap[i]&0xff);
    }
    fputs("\";\n", fp);
    break;
  }
  fprintf(fp, "static mrb_irep_debug_info_file %s_debug_file_%d = {\n", name, n);
  fprintf(fp, "%d, %d, %d, %s, {%s_debug_lines_%d}};\n",
          info->files[0]->start_pos,
          info->files[0]->filename_sym,
          info->files[0]->line_entry_count,
          line_type,
          name,n);
  fprintf(fp, "static mrb_irep_debug_info_file *%s_debug_file_%d_ = &%s_debug_file_%d;\n", name, n, name, n);

  fprintf(fp, "static mrb_irep_debug_info %s_debug_%d = {\n", name, n);
  fprintf(fp, "%d, %d, &%s_debug_file_%d_};\n", info->pc_count, info->flen, name, n);

  return MRB_DUMP_OK;
}

static int
cdump_irep_struct(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, FILE *fp, const char *name, int n, mrb_value init_syms_code, int *mp)
{
  int i, len;
  int max = *mp;
  int debug_available = 0;

  /* dump reps */
  if (irep->reps) {
    for (i=0,len=irep->rlen; i<len; i++) {
      *mp += len;
      if (cdump_irep_struct(mrb, irep->reps[i], flags, fp, name, max+i, init_syms_code, mp) != MRB_DUMP_OK)
        return MRB_DUMP_INVALID_ARGUMENT;
    }
    fprintf(fp,   "static const mrb_irep *%s_reps_%d[%d] = {\n", name, n, len);
    for (i=0,len=irep->rlen; i<len; i++) {
      fprintf(fp,   "  &%s_irep_%d,\n", name, max+i);
    }
    fputs("};\n", fp);
  }
  /* dump pool */
  if (irep->pool) {
    len=irep->plen;
    fprintf(fp,   "static const mrb_pool_value %s_pool_%d[%d] = {\n", name, n, len);
    for (i=0; i<len; i++) {
      if (cdump_pool(mrb, &irep->pool[i], fp) != MRB_DUMP_OK)
        return MRB_DUMP_INVALID_ARGUMENT;
    }
    fputs("};\n", fp);
  }
  /* dump syms */
  if (irep->syms) {
    cdump_syms(mrb, name, "syms", n, irep->slen, irep->syms, init_syms_code, fp);
  }
  /* dump iseq */
  len=irep->ilen+sizeof(struct mrb_irep_catch_handler)*irep->clen;
  fprintf(fp,   "static const mrb_code %s_iseq_%d[%d] = {", name, n, len);
  for (i=0; i<len; i++) {
    if (i%20 == 0) fputs("\n", fp);
    fprintf(fp, "0x%02x,", irep->iseq[i]);
  }
  fputs("};\n", fp);
  /* dump lv */
  if (irep->lv) {
    cdump_syms(mrb, name, "lv", n, irep->nlocals-1, irep->lv, init_syms_code, fp);
  }
  /* dump debug */
  if (flags & MRB_DUMP_DEBUG_INFO) {
    if(cdump_debug(mrb, name, n, irep->debug_info,
                init_syms_code, fp) == MRB_DUMP_OK) {
      debug_available = 1;
    }
  }


  /* dump irep */
  fprintf(fp, "static const mrb_irep %s_irep_%d = {\n", name, n);
  fprintf(fp,   "  %d,%d,%d,\n", irep->nlocals, irep->nregs, irep->clen);
  fprintf(fp,   "  MRB_IREP_STATIC,%s_iseq_%d,\n", name, n);
  if (irep->pool) {
    fprintf(fp, "  %s_pool_%d,", name, n);
  }
  else {
    fputs(      "  NULL,", fp);
  }
  if (irep->syms) {
    fprintf(fp, "%s_syms_%d,", name, n);
  }
  else {
    fputs(      "NULL,", fp);
  }
  if (irep->reps) {
    fprintf(fp, "%s_reps_%d,\n", name, n);
  }
  else {
    fputs(      "NULL,\n", fp);
  }
  if (irep->lv) {
    fprintf(fp, "  %s_lv_%d,\n", name, n);
  }
  else {
    fputs(      "  NULL,\t\t\t\t\t/* lv */\n", fp);
  }
  if(debug_available) {
    fprintf(fp, "  &%s_debug_%d,\n", name, n);
  }
  else {
    fputs("  NULL,\t\t\t\t\t/* debug_info */\n", fp);
  }
  fprintf(fp,   "  %d,%d,%d,%d,0\n};\n", irep->ilen, irep->plen, irep->slen, irep->rlen);

  return MRB_DUMP_OK;
}

int
mrb_dump_irep_cstruct(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, FILE *fp, const char *initname)
{
  if (fp == NULL || initname == NULL || initname[0] == '\0') {
    return MRB_DUMP_INVALID_ARGUMENT;
  }
  if (fprintf(fp, "#include <mruby.h>\n"
                  "#include <mruby/irep.h>\n"
                  "#include <mruby/debug.h>\n"
                  "#include <mruby/proc.h>\n"
                  "#include <mruby/presym.h>\n"
                  "\n") < 0) {
    return MRB_DUMP_WRITE_FAULT;
  }
  fputs("#define mrb_BRACED(...) {__VA_ARGS__}\n", fp);
  fputs("#define mrb_DEFINE_SYMS_VAR(name, len, syms, qualifier) \\\n", fp);
  fputs("  static qualifier mrb_sym name[len] = mrb_BRACED syms\n", fp);
  fputs("\n", fp);
  mrb_value init_syms_code = mrb_str_new_capa(mrb, 0);
  int max = 1;
  int n = cdump_irep_struct(mrb, irep, flags, fp, initname, 0, init_syms_code, &max);
  if (n != MRB_DUMP_OK) return n;
  fprintf(fp,
          "%s\n"
          "const struct RProc %s[] = {{\n",
          (flags & MRB_DUMP_STATIC) ? "static"
                                    : "#ifdef __cplusplus\n"
                                      "extern\n"
                                      "#endif",
          initname);
  fprintf(fp, "NULL,NULL,MRB_TT_PROC,MRB_GC_RED,0,{&%s_irep_0},NULL,{NULL},\n}};\n", initname);
  fputs("static void\n", fp);
  fprintf(fp, "%s_init_syms(mrb_state *mrb)\n", initname);
  fputs("{\n", fp);
  fputs(RSTRING_PTR(init_syms_code), fp);
  fputs("}\n", fp);
  return MRB_DUMP_OK;
}
#endif
