/*
** dump.c - mruby binary dumper (mrbc binary format)
**
** See Copyright Notice in mruby.h
*/

#include <string.h>
#include <limits.h>
#include <math.h>
#include <mruby/dump.h>
#include <mruby/string.h>
#include <mruby/irep.h>
#include <mruby/debug.h>

#ifndef MRB_NO_FLOAT
#include <mruby/endian.h>
#define MRB_FLOAT_FMT "%.17g"
#endif

static size_t get_irep_record_size_1(mrb_state *mrb, const mrb_irep *irep);

#if UINT32_MAX > SIZE_MAX
# error This code cannot be built on your environment.
#endif

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

static size_t
get_irep_header_size(mrb_state *mrb)
{
  size_t size = 0;

  size += sizeof(uint32_t) * 1;
  size += sizeof(uint16_t) * 3;

  return size;
}

static ptrdiff_t
write_irep_header(mrb_state *mrb, const mrb_irep *irep, uint8_t *buf)
{
  uint8_t *cur = buf;

  cur += uint32_to_bin((uint32_t)get_irep_record_size_1(mrb, irep), cur);  /* record size */
  cur += uint16_to_bin((uint16_t)irep->nlocals, cur);  /* number of local variable */
  cur += uint16_to_bin((uint16_t)irep->nregs, cur);  /* number of register variable */
  cur += uint16_to_bin((uint16_t)irep->rlen, cur);  /* number of child irep */

  return cur - buf;
}

static size_t
get_iseq_block_size(mrb_state *mrb, const mrb_irep *irep)
{
  size_t size = 0;

  size += sizeof(uint16_t); /* clen */
  size += sizeof(uint16_t); /* ilen */
  size += irep->ilen * sizeof(mrb_code); /* iseq(n) */
  size += irep->clen * sizeof(struct mrb_irep_catch_handler);

  return size;
}

static ptrdiff_t
write_iseq_block(mrb_state *mrb, const mrb_irep *irep, uint8_t *buf, uint8_t flags)
{
  uint8_t *cur = buf;
  size_t seqlen = irep->ilen * sizeof(mrb_code) +
                  irep->clen * sizeof(struct mrb_irep_catch_handler);

  cur += uint16_to_bin(irep->clen, cur); /* number of catch handlers */
  cur += uint16_to_bin(irep->ilen, cur); /* number of opcode */
  memcpy(cur, irep->iseq, seqlen);
  cur += seqlen;

  return cur - buf;
}

#ifndef MRB_NO_FLOAT
static void
dump_float(mrb_state *mrb, uint8_t *buf, mrb_float f)
{
  /* dump IEEE754 binary in little endian */
  union {
    double f;
    char s[sizeof(double)];
  } u = {.f = (double)f};

  if (littleendian) {
    memcpy(buf, u.s, sizeof(double));
  }
  else {
    size_t i;

    for (i=0; i<sizeof(double); i++) {
      buf[i] = u.s[sizeof(double)-i-1];
    }
  }
}
#endif

static size_t
get_pool_block_size(mrb_state *mrb, const mrb_irep *irep)
{
  int pool_no;
  size_t size = 0;

  size += sizeof(uint16_t); /* plen */
  size += irep->plen * sizeof(uint8_t); /* len(n) */

  for (pool_no = 0; pool_no < irep->plen; pool_no++) {
    int ai = mrb_gc_arena_save(mrb);

    switch (irep->pool[pool_no].tt) {
    case IREP_TT_INT64:
#ifdef MRB_64BIT
      {
        int64_t i = irep->pool[pool_no].u.i64;

        if (i < INT32_MIN || INT32_MAX < i)
          size += 8;
        else
          size += 4;
      }
      break;
#else
      /* fall through */
#endif
    case IREP_TT_INT32:
      size += 4;                /* 32bits = 4bytes */
      break;

    case IREP_TT_FLOAT:
#ifndef MRB_NO_FLOAT
      {
        size += sizeof(double);
      }
#endif
      break;

    default: /*  packed IREP_TT_STRING */
      {
        mrb_int len = irep->pool[pool_no].tt >> 2; /* unpack length */
        mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
        size += sizeof(uint16_t);
        size += (size_t)len+1;
      }
      break;
    }
    mrb_gc_arena_restore(mrb, ai);
  }

  return size;
}

static ptrdiff_t
write_pool_block(mrb_state *mrb, const mrb_irep *irep, uint8_t *buf)
{
  int pool_no;
  uint8_t *cur = buf;
  mrb_int len;
  const char *ptr;

  cur += uint16_to_bin(irep->plen, cur); /* number of pool */

  for (pool_no = 0; pool_no < irep->plen; pool_no++) {
    int ai = mrb_gc_arena_save(mrb);

    switch (irep->pool[pool_no].tt) {
#ifdef MRB_64BIT
    case IREP_TT_INT64:
      {
        int64_t i = irep->pool[pool_no].u.i64;
        if (i < INT32_MIN || INT32_MAX < i) {
          cur += uint8_to_bin(IREP_TT_INT64, cur); /* data type */
          cur += uint32_to_bin((uint32_t)((i>>32) & 0xffffffff), cur); /* i64 hi */
          cur += uint32_to_bin((uint32_t)((i    ) & 0xffffffff), cur); /* i64 lo */
        }
        else {
          cur += uint8_to_bin(IREP_TT_INT32, cur); /* data type */
          cur += uint32_to_bin(irep->pool[pool_no].u.i32, cur); /* i32 */
        }
      }
      break;
#endif
    case IREP_TT_INT32:
      cur += uint8_to_bin(IREP_TT_INT32, cur); /* data type */
      cur += uint32_to_bin(irep->pool[pool_no].u.i32, cur); /* i32 */
      break;

    case IREP_TT_FLOAT:
      cur += uint8_to_bin(IREP_TT_FLOAT, cur); /* data type */
#ifndef MRB_NO_FLOAT
      {
        dump_float(mrb, cur,irep->pool[pool_no].u.f);
        cur += sizeof(double);
      }
#else
      cur += uint16_to_bin(0, cur); /* zero length */
#endif
      break;

    default: /* string */
      cur += uint8_to_bin(IREP_TT_STR, cur); /* data type */
      ptr = irep->pool[pool_no].u.str;
      len = irep->pool[pool_no].tt>>2;
      mrb_assert_int_fit(mrb_int, len, uint16_t, UINT16_MAX);
      cur += uint16_to_bin((uint16_t)len, cur); /* data length */
      memcpy(cur, ptr, (size_t)len);
      cur += len;
      *cur++ = '\0';
      break;
    }
    mrb_gc_arena_restore(mrb, ai);
  }

  return cur - buf;
}


static size_t
get_syms_block_size(mrb_state *mrb, const mrb_irep *irep)
{
  size_t size = 0;
  int sym_no;
  mrb_int len;

  size += sizeof(uint16_t); /* slen */
  for (sym_no = 0; sym_no < irep->slen; sym_no++) {
    size += sizeof(uint16_t); /* snl(n) */
    if (irep->syms[sym_no] != 0) {
      mrb_sym_name_len(mrb, irep->syms[sym_no], &len);
      size += len + 1; /* sn(n) + null char */
    }
  }

  return size;
}

static ptrdiff_t
write_syms_block(mrb_state *mrb, const mrb_irep *irep, uint8_t *buf)
{
  int sym_no;
  uint8_t *cur = buf;
  const char *name;

  cur += uint16_to_bin(irep->slen, cur); /* number of symbol */

  for (sym_no = 0; sym_no < irep->slen; sym_no++) {
    if (irep->syms[sym_no] != 0) {
      mrb_int len;

      name = mrb_sym_name_len(mrb, irep->syms[sym_no], &len);

      mrb_assert_int_fit(mrb_int, len, uint16_t, UINT16_MAX);
      cur += uint16_to_bin((uint16_t)len, cur); /* length of symbol name */
      memcpy(cur, name, len); /* symbol name */
      cur += (uint16_t)len;
      *cur++ = '\0';
    }
    else {
      cur += uint16_to_bin(MRB_DUMP_NULL_SYM_LEN, cur); /* length of symbol name */
    }
  }

  return cur - buf;
}

static size_t
get_irep_record_size_1(mrb_state *mrb, const mrb_irep *irep)
{
  size_t size = 0;

  size += get_irep_header_size(mrb);
  size += get_iseq_block_size(mrb, irep);
  size += get_pool_block_size(mrb, irep);
  size += get_syms_block_size(mrb, irep);
  return size;
}

static size_t
get_irep_record_size(mrb_state *mrb, const mrb_irep *irep)
{
  size_t size = 0;
  int irep_no;

  size = get_irep_record_size_1(mrb, irep);
  for (irep_no = 0; irep_no < irep->rlen; irep_no++) {
    size += get_irep_record_size(mrb, irep->reps[irep_no]);
  }
  return size;
}

static int
write_irep_record(mrb_state *mrb, const mrb_irep *irep, uint8_t *bin, size_t *irep_record_size, uint8_t flags)
{
  int i;
  uint8_t *src = bin;

  if (irep == NULL) {
    return MRB_DUMP_INVALID_IREP;
  }

  bin += write_irep_header(mrb, irep, bin);
  bin += write_iseq_block(mrb, irep, bin, flags);
  bin += write_pool_block(mrb, irep, bin);
  bin += write_syms_block(mrb, irep, bin);

  for (i = 0; i < irep->rlen; i++) {
    int result;
    size_t rsize;

    result = write_irep_record(mrb, irep->reps[i], bin, &rsize, flags);
    if (result != MRB_DUMP_OK) {
      return result;
    }
    bin += rsize;
  }
  *irep_record_size = bin - src;
  return MRB_DUMP_OK;
}

static uint32_t
write_footer(mrb_state *mrb, uint8_t *bin)
{
  struct rite_binary_footer footer;

  memcpy(footer.section_ident, RITE_BINARY_EOF, sizeof(footer.section_ident));
  uint32_to_bin(sizeof(struct rite_binary_footer), footer.section_size);
  memcpy(bin, &footer, sizeof(struct rite_binary_footer));

  return sizeof(struct rite_binary_footer);
}


static int
write_section_irep_header(mrb_state *mrb, size_t section_size, uint8_t *bin)
{
  struct rite_section_irep_header *header = (struct rite_section_irep_header*)bin;

  memcpy(header->section_ident, RITE_SECTION_IREP_IDENT, sizeof(header->section_ident));

  mrb_assert_int_fit(size_t, section_size, uint32_t, UINT32_MAX);
  uint32_to_bin((uint32_t)section_size, header->section_size);
  memcpy(header->rite_version, RITE_VM_VER, sizeof(header->rite_version));

  return MRB_DUMP_OK;
}

static int
write_section_irep(mrb_state *mrb, const mrb_irep *irep, uint8_t *bin, size_t *len_p, uint8_t flags)
{
  int result;
  size_t rsize = 0;
  uint8_t *cur = bin;

  if (mrb == NULL || bin == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  cur += sizeof(struct rite_section_irep_header);

  result = write_irep_record(mrb, irep, cur, &rsize, flags);
  if (result != MRB_DUMP_OK) {
    return result;
  }
  mrb_assert(rsize == get_irep_record_size(mrb, irep));
  *len_p = cur - bin + rsize;
  write_section_irep_header(mrb, *len_p, bin);

  return MRB_DUMP_OK;
}

static size_t
get_debug_record_size(mrb_state *mrb, const mrb_irep *irep)
{
  size_t ret = 0;
  uint16_t f_idx;
  int i;

  ret += sizeof(uint32_t); /* record size */
  ret += sizeof(uint16_t); /* file count */

  for (f_idx = 0; f_idx < irep->debug_info->flen; ++f_idx) {
    mrb_irep_debug_info_file const* file = irep->debug_info->files[f_idx];

    ret += sizeof(uint32_t); /* position */
    ret += sizeof(uint16_t); /* filename index */

    /* lines */
    ret += sizeof(uint32_t); /* entry count */
    ret += sizeof(uint8_t); /* line type */
    switch (file->line_type) {
      case mrb_debug_line_ary:
        ret += sizeof(uint16_t) * (size_t)(file->line_entry_count);
        break;

      case mrb_debug_line_flat_map:
        ret += (sizeof(uint32_t) + sizeof(uint16_t)) * (size_t)(file->line_entry_count);
        break;

      default: mrb_assert(0); break;
    }
  }
  for (i=0; i<irep->rlen; i++) {
    ret += get_debug_record_size(mrb, irep->reps[i]);
  }

  return ret;
}

static int
find_filename_index(const mrb_sym *ary, int ary_len, mrb_sym s)
{
  int i;

  for (i = 0; i < ary_len; ++i) {
    if (ary[i] == s) { return i; }
  }
  return -1;
}

static size_t
get_filename_table_size(mrb_state *mrb, const mrb_irep *irep, mrb_sym **fp, uint16_t *lp)
{
  mrb_sym *filenames = *fp;
  size_t size = 0;
  const mrb_irep_debug_info *di = irep->debug_info;
  int i;

  mrb_assert(lp);
  for (i = 0; i < di->flen; ++i) {
    mrb_irep_debug_info_file *file;
    mrb_int filename_len;

    file = di->files[i];
    if (find_filename_index(filenames, *lp, file->filename_sym) == -1) {
      /* register filename */
      *lp += 1;
      *fp = filenames = (mrb_sym *)mrb_realloc(mrb, filenames, sizeof(mrb_sym) * (*lp));
      filenames[*lp - 1] = file->filename_sym;

      /* filename */
      mrb_sym_name_len(mrb, file->filename_sym, &filename_len);
      size += sizeof(uint16_t) + (size_t)filename_len;
    }
  }
  for (i=0; i<irep->rlen; i++) {
    size += get_filename_table_size(mrb, irep->reps[i], fp, lp);
  }
  return size;
}

static size_t
write_debug_record_1(mrb_state *mrb, const mrb_irep *irep, uint8_t *bin, mrb_sym const* filenames, uint16_t filenames_len)
{
  uint8_t *cur;
  uint16_t f_idx;
  ptrdiff_t ret;

  cur = bin + sizeof(uint32_t); /* skip record size */
  cur += uint16_to_bin(irep->debug_info->flen, cur); /* file count */

  for (f_idx = 0; f_idx < irep->debug_info->flen; ++f_idx) {
    int filename_idx;
    const mrb_irep_debug_info_file *file = irep->debug_info->files[f_idx];

    /* position */
    cur += uint32_to_bin(file->start_pos, cur);

    /* filename index */
    filename_idx = find_filename_index(filenames, filenames_len,
                                                  file->filename_sym);
    mrb_assert_int_fit(int, filename_idx, uint16_t, UINT16_MAX);
    cur += uint16_to_bin((uint16_t)filename_idx, cur);

    /* lines */
    cur += uint32_to_bin(file->line_entry_count, cur);
    cur += uint8_to_bin(file->line_type, cur);
    switch (file->line_type) {
      case mrb_debug_line_ary: {
        uint32_t l;
        for (l = 0; l < file->line_entry_count; ++l) {
          cur += uint16_to_bin(file->lines.ary[l], cur);
        }
      } break;

      case mrb_debug_line_flat_map: {
        uint32_t line;
        for (line = 0; line < file->line_entry_count; ++line) {
          cur += uint32_to_bin(file->lines.flat_map[line].start_pos, cur);
          cur += uint16_to_bin(file->lines.flat_map[line].line, cur);
        }
      } break;

      default: mrb_assert(0); break;
    }
  }

  ret = cur - bin;
  mrb_assert_int_fit(ptrdiff_t, ret, uint32_t, UINT32_MAX);
  uint32_to_bin((uint32_t)ret, bin);

  mrb_assert_int_fit(ptrdiff_t, ret, size_t, SIZE_MAX);
  return (size_t)ret;
}

static size_t
write_debug_record(mrb_state *mrb, const mrb_irep *irep, uint8_t *bin, mrb_sym const* filenames, uint16_t filenames_len)
{
  size_t size, len;
  int irep_no;

  size = len = write_debug_record_1(mrb, irep, bin, filenames, filenames_len);
  bin += len;
  for (irep_no = 0; irep_no < irep->rlen; irep_no++) {
    len = write_debug_record(mrb, irep->reps[irep_no], bin, filenames, filenames_len);
    bin += len;
    size += len;
  }

  mrb_assert(size == get_debug_record_size(mrb, irep));
  return size;
}

static int
write_section_debug(mrb_state *mrb, const mrb_irep *irep, uint8_t *cur, mrb_sym const *filenames, uint16_t filenames_len)
{
  size_t section_size = 0;
  const uint8_t *bin = cur;
  struct rite_section_debug_header *header;
  size_t dlen;
  uint16_t i;
  char const *sym; mrb_int sym_len;

  if (mrb == NULL || cur == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  header = (struct rite_section_debug_header *)bin;
  cur += sizeof(struct rite_section_debug_header);
  section_size += sizeof(struct rite_section_debug_header);

  /* filename table */
  cur += uint16_to_bin(filenames_len, cur);
  section_size += sizeof(uint16_t);
  for (i = 0; i < filenames_len; ++i) {
    sym = mrb_sym_name_len(mrb, filenames[i], &sym_len);
    mrb_assert(sym);
    cur += uint16_to_bin((uint16_t)sym_len, cur);
    memcpy(cur, sym, sym_len);
    cur += sym_len;
    section_size += sizeof(uint16_t) + sym_len;
  }

  /* debug records */
  dlen = write_debug_record(mrb, irep, cur, filenames, filenames_len);
  section_size += dlen;

  memcpy(header->section_ident, RITE_SECTION_DEBUG_IDENT, sizeof(header->section_ident));
  mrb_assert(section_size <= INT32_MAX);
  uint32_to_bin((uint32_t)section_size, header->section_size);

  return MRB_DUMP_OK;
}

static void
create_lv_sym_table(mrb_state *mrb, const mrb_irep *irep, mrb_sym **syms, uint32_t *syms_len)
{
  int i;

  if (*syms == NULL) {
    *syms = (mrb_sym*)mrb_malloc(mrb, sizeof(mrb_sym) * 1);
  }

  for (i = 0; i + 1 < irep->nlocals; ++i) {
    mrb_sym const name = irep->lv[i];
    if (name == 0) continue;
    if (find_filename_index(*syms, *syms_len, name) != -1) continue;

    ++(*syms_len);
    *syms = (mrb_sym*)mrb_realloc(mrb, *syms, sizeof(mrb_sym) * (*syms_len));
    (*syms)[*syms_len - 1] = name;
  }

  for (i = 0; i < irep->rlen; ++i) {
    create_lv_sym_table(mrb, irep->reps[i], syms, syms_len);
  }
}

static int
write_lv_sym_table(mrb_state *mrb, uint8_t **start, mrb_sym const *syms, uint32_t syms_len)
{
  uint8_t *cur = *start;
  uint32_t i;
  const char *str;
  mrb_int str_len;

  cur += uint32_to_bin(syms_len, cur);

  for (i = 0; i < syms_len; ++i) {
    str = mrb_sym_name_len(mrb, syms[i], &str_len);
    cur += uint16_to_bin((uint16_t)str_len, cur);
    memcpy(cur, str, str_len);
    cur += str_len;
  }

  *start = cur;

  return MRB_DUMP_OK;
}

static int
write_lv_record(mrb_state *mrb, const mrb_irep *irep, uint8_t **start, mrb_sym const *syms, uint32_t syms_len)
{
  uint8_t *cur = *start;
  int i;

  for (i = 0; i + 1 < irep->nlocals; ++i) {
    if (irep->lv[i] == 0) {
      cur += uint16_to_bin(RITE_LV_NULL_MARK, cur);
    }
    else {
      int const sym_idx = find_filename_index(syms, syms_len, irep->lv[i]);
      mrb_assert(sym_idx != -1); /* local variable name must be in syms */

      cur += uint16_to_bin(sym_idx, cur);
    }
  }

  for (i = 0; i < irep->rlen; ++i) {
    write_lv_record(mrb, irep->reps[i], &cur, syms, syms_len);
  }

  *start = cur;

  return MRB_DUMP_OK;
}

static size_t
get_lv_record_size(mrb_state *mrb, const mrb_irep *irep)
{
  size_t ret = 0;
  int i;

  ret += sizeof(uint16_t) * (irep->nlocals - 1);

  for (i = 0; i < irep->rlen; ++i) {
    ret += get_lv_record_size(mrb, irep->reps[i]);
  }

  return ret;
}

static size_t
get_lv_section_size(mrb_state *mrb, const mrb_irep *irep, mrb_sym const *syms, uint32_t syms_len)
{
  size_t ret = 0, i;

  ret += sizeof(uint32_t); /* syms_len */
  ret += sizeof(uint16_t) * syms_len; /* symbol name lengths */
  for (i = 0; i < syms_len; ++i) {
    mrb_int str_len;
    mrb_sym_name_len(mrb, syms[i], &str_len);
    ret += str_len;
  }

  ret += get_lv_record_size(mrb, irep);

  return ret;
}

static int
write_section_lv(mrb_state *mrb, const mrb_irep *irep, uint8_t *start, mrb_sym const *syms, uint32_t const syms_len)
{
  uint8_t *cur = start;
  struct rite_section_lv_header *header;
  ptrdiff_t diff;
  int result = MRB_DUMP_OK;

  if (mrb == NULL || cur == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  header = (struct rite_section_lv_header*)cur;
  cur += sizeof(struct rite_section_lv_header);

  result = write_lv_sym_table(mrb, &cur, syms, syms_len);
  if (result != MRB_DUMP_OK) {
    goto lv_section_exit;
  }

  result = write_lv_record(mrb, irep, &cur, syms, syms_len);
  if (result != MRB_DUMP_OK) {
    goto lv_section_exit;
  }

  memcpy(header->section_ident, RITE_SECTION_LV_IDENT, sizeof(header->section_ident));

  diff = cur - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  uint32_to_bin((uint32_t)diff, header->section_size);

lv_section_exit:
  return result;
}

static int
write_rite_binary_header(mrb_state *mrb, size_t binary_size, uint8_t *bin, uint8_t flags)
{
  struct rite_binary_header *header = (struct rite_binary_header *)bin;

  memcpy(header->binary_ident, RITE_BINARY_IDENT, sizeof(header->binary_ident));
  memcpy(header->major_version, RITE_BINARY_MAJOR_VER, sizeof(header->major_version));
  memcpy(header->minor_version, RITE_BINARY_MINOR_VER, sizeof(header->minor_version));
  memcpy(header->compiler_name, RITE_COMPILER_NAME, sizeof(header->compiler_name));
  memcpy(header->compiler_version, RITE_COMPILER_VERSION, sizeof(header->compiler_version));
  mrb_assert(binary_size <= UINT32_MAX);
  uint32_to_bin((uint32_t)binary_size, header->binary_size);

  return MRB_DUMP_OK;
}

static mrb_bool
debug_info_defined_p(const mrb_irep *irep)
{
  int i;

  if (!irep->debug_info) return FALSE;
  for (i=0; i<irep->rlen; i++) {
    if (!debug_info_defined_p(irep->reps[i])) return FALSE;
  }
  return TRUE;
}

static mrb_bool
lv_defined_p(const mrb_irep *irep)
{
  int i;

  if (irep->lv) { return TRUE; }

  for (i = 0; i < irep->rlen; ++i) {
    if (lv_defined_p(irep->reps[i])) { return TRUE; }
  }

  return FALSE;
}

static int
dump_irep(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, uint8_t **bin, size_t *bin_size)
{
  int result = MRB_DUMP_GENERAL_FAILURE;
  size_t malloc_size;
  size_t section_irep_size;
  size_t section_lineno_size = 0, section_lv_size = 0;
  uint8_t *cur = NULL;
  mrb_bool const debug_info_defined = debug_info_defined_p(irep), lv_defined = lv_defined_p(irep);
  mrb_sym *lv_syms = NULL; uint32_t lv_syms_len = 0;
  mrb_sym *filenames = NULL; uint16_t filenames_len = 0;

  if (mrb == NULL) {
    *bin = NULL;
    return MRB_DUMP_GENERAL_FAILURE;
  }

  section_irep_size = sizeof(struct rite_section_irep_header);
  section_irep_size += get_irep_record_size(mrb, irep);

  /* DEBUG section size */
  if (flags & DUMP_DEBUG_INFO) {
    if (debug_info_defined) {
      section_lineno_size += sizeof(struct rite_section_debug_header);
      /* filename table */
      filenames = (mrb_sym*)mrb_malloc(mrb, sizeof(mrb_sym) + 1);

      /* filename table size */
      section_lineno_size += sizeof(uint16_t);
      section_lineno_size += get_filename_table_size(mrb, irep, &filenames, &filenames_len);

      section_lineno_size += get_debug_record_size(mrb, irep);
    }
  }

  if (lv_defined) {
    section_lv_size += sizeof(struct rite_section_lv_header);
    create_lv_sym_table(mrb, irep, &lv_syms, &lv_syms_len);
    section_lv_size += get_lv_section_size(mrb, irep, lv_syms, lv_syms_len);
  }

  malloc_size = sizeof(struct rite_binary_header) +
                section_irep_size + section_lineno_size + section_lv_size +
                sizeof(struct rite_binary_footer);
  cur = *bin = (uint8_t*)mrb_malloc(mrb, malloc_size);
  cur += sizeof(struct rite_binary_header);

  result = write_section_irep(mrb, irep, cur, &section_irep_size, flags);
  if (result != MRB_DUMP_OK) {
    goto error_exit;
  }
  cur += section_irep_size;
  *bin_size = sizeof(struct rite_binary_header) +
              section_irep_size + section_lineno_size + section_lv_size +
              sizeof(struct rite_binary_footer);

  /* write DEBUG section */
  if (flags & DUMP_DEBUG_INFO) {
    if (debug_info_defined) {
      result = write_section_debug(mrb, irep, cur, filenames, filenames_len);
      if (result != MRB_DUMP_OK) {
        goto error_exit;
      }
    }
    cur += section_lineno_size;
  }

  if (lv_defined) {
    result = write_section_lv(mrb, irep, cur, lv_syms, lv_syms_len);
    if (result != MRB_DUMP_OK) {
      goto error_exit;
    }
    cur += section_lv_size;
  }

  write_footer(mrb, cur);
  write_rite_binary_header(mrb, *bin_size, *bin, flags);

error_exit:
  if (result != MRB_DUMP_OK) {
    mrb_free(mrb, *bin);
    *bin = NULL;
  }
  mrb_free(mrb, lv_syms);
  mrb_free(mrb, filenames);
  return result;
}

int
mrb_dump_irep(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, uint8_t **bin, size_t *bin_size)
{
  return dump_irep(mrb, irep, flags, bin, bin_size);
}

#ifndef MRB_NO_STDIO

int
mrb_dump_irep_binary(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, FILE* fp)
{
  uint8_t *bin = NULL;
  size_t bin_size = 0;
  int result;

  if (fp == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  result = dump_irep(mrb, irep, flags, &bin, &bin_size);
  if (result == MRB_DUMP_OK) {
    if (fwrite(bin, sizeof(bin[0]), bin_size, fp) != bin_size) {
      result = MRB_DUMP_WRITE_FAULT;
    }
  }

  mrb_free(mrb, bin);
  return result;
}

int
mrb_dump_irep_cfunc(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, FILE *fp, const char *initname)
{
  uint8_t *bin = NULL;
  size_t bin_size = 0, bin_idx = 0;
  int result;

  if (fp == NULL || initname == NULL || initname[0] == '\0') {
    return MRB_DUMP_INVALID_ARGUMENT;
  }
  result = dump_irep(mrb, irep, flags, &bin, &bin_size);
  if (result == MRB_DUMP_OK) {
    if (fprintf(fp, "#include <stdint.h>\n") < 0) { /* for uint8_t under at least Darwin */
      mrb_free(mrb, bin);
      return MRB_DUMP_WRITE_FAULT;
    }
    if (fprintf(fp,
          "#ifdef __cplusplus\n"
          "extern const uint8_t %s[];\n"
          "#endif\n"
          "const uint8_t %s[] = {",
          initname, initname) < 0) {
      mrb_free(mrb, bin);
      return MRB_DUMP_WRITE_FAULT;
    }
    while (bin_idx < bin_size) {
      if (bin_idx % 16 == 0) {
        if (fputs("\n", fp) == EOF) {
          mrb_free(mrb, bin);
          return MRB_DUMP_WRITE_FAULT;
        }
      }
      if (fprintf(fp, "0x%02x,", bin[bin_idx++]) < 0) {
        mrb_free(mrb, bin);
        return MRB_DUMP_WRITE_FAULT;
      }
    }
    if (fputs("\n};\n", fp) == EOF) {
      mrb_free(mrb, bin);
      return MRB_DUMP_WRITE_FAULT;
    }
  }

  mrb_free(mrb, bin);
  return result;
}

static int
dump_pool(mrb_state *mrb, const mrb_pool_value *p, FILE *fp)
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
dump_sym(mrb_state *mrb, mrb_sym sym, const char *var_name, int idx, mrb_value init_syms_code, FILE *fp)
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
dump_syms(mrb_state *mrb, const char *name, const char *key, int n, int syms_len, const mrb_sym *syms, mrb_value init_syms_code, FILE *fp)
{
  int ai = mrb_gc_arena_save(mrb);
  mrb_int code_len = RSTRING_LEN(init_syms_code);
  const char *var_name = sym_var_name(mrb, name, key, n);
  fprintf(fp, "mrb_DEFINE_SYMS_VAR(%s, %d, (", var_name, syms_len);
  for (int i=0; i<syms_len; i++) {
    dump_sym(mrb, syms[i], var_name, i, init_syms_code, fp);
  }
  fputs("), ", fp);
  if (code_len == RSTRING_LEN(init_syms_code)) fputs("const", fp);
  fputs(");\n", fp);
  mrb_gc_arena_restore(mrb, ai);
  return MRB_DUMP_OK;
}

static int
dump_irep_struct(mrb_state *mrb, const mrb_irep *irep, uint8_t flags, FILE *fp, const char *name, int n, mrb_value init_syms_code, int *mp)
{
  int i, len;
  int max = *mp;

  /* dump reps */
  if (irep->reps) {
    for (i=0,len=irep->rlen; i<len; i++) {
      *mp += len;
      if (dump_irep_struct(mrb, irep->reps[i], flags, fp, name, max+i, init_syms_code, mp) != MRB_DUMP_OK)
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
      if (dump_pool(mrb, &irep->pool[i], fp) != MRB_DUMP_OK)
        return MRB_DUMP_INVALID_ARGUMENT;
    }
    fputs("};\n", fp);
  }
  /* dump syms */
  if (irep->syms) {
    dump_syms(mrb, name, "syms", n, irep->slen, irep->syms, init_syms_code, fp);
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
    dump_syms(mrb, name, "lv", n, irep->nlocals-1, irep->lv, init_syms_code, fp);
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
  fputs(        "  NULL,\t\t\t\t\t/* debug_info */\n", fp);
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
  int n = dump_irep_struct(mrb, irep, flags, fp, initname, 0, init_syms_code, &max);
  if (n != MRB_DUMP_OK) return n;
  fprintf(fp, "#ifdef __cplusplus\nextern const struct RProc %s[];\n#endif\n", initname);
  fprintf(fp, "const struct RProc %s[] = {{\n", initname);
  fprintf(fp, "NULL,NULL,MRB_TT_PROC,7,0,{&%s_irep_0},NULL,{NULL},\n}};\n", initname);
  fputs("static void\n", fp);
  fprintf(fp, "%s_init_syms(mrb_state *mrb)\n", initname);
  fputs("{\n", fp);
  fputs(RSTRING_PTR(init_syms_code), fp);
  fputs("}\n", fp);
  return MRB_DUMP_OK;
}

#endif /* MRB_NO_STDIO */
