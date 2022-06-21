/*
** codegen.c - mruby code generator
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/proc.h>
#include <mruby/dump.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/debug.h>
#include <mruby/presym.h>
#include "node.h"
#include <mruby/opcode.h>
#include <mruby/re.h>
#include <mruby/throw.h>
#include <ctype.h>
#include <string.h>

#ifndef MRB_CODEGEN_LEVEL_MAX
#define MRB_CODEGEN_LEVEL_MAX 256
#endif

#define MAXARG_S (1<<16)

typedef mrb_ast_node node;
typedef struct mrb_parser_state parser_state;

enum looptype {
  LOOP_NORMAL,
  LOOP_BLOCK,
  LOOP_FOR,
  LOOP_BEGIN,
  LOOP_RESCUE,
};

struct loopinfo {
  enum looptype type;
  uint32_t pc0;                 /* `next` destination */
  uint32_t pc1;                 /* `redo` destination */
  uint32_t pc2;                 /* `break` destination */
  int reg;                      /* destination register */
  struct loopinfo *prev;
};

typedef struct scope {
  mrb_state *mrb;
  mrb_pool *mpool;

  struct scope *prev;

  node *lv;

  uint16_t sp;
  uint32_t pc;
  uint32_t lastpc;
  uint32_t lastlabel;
  size_t ainfo:15;
  mrb_bool mscope:1;

  struct loopinfo *loop;
  mrb_sym filename_sym;
  uint16_t lineno;

  mrb_code *iseq;
  uint16_t *lines;
  uint32_t icapa;

  mrb_irep *irep;
  mrb_pool_value *pool;
  mrb_sym *syms;
  mrb_irep **reps;
  struct mrb_irep_catch_handler *catch_table;
  uint32_t pcapa, scapa, rcapa;

  uint16_t nlocals;
  uint16_t nregs;
  int ai;

  int debug_start_pos;
  uint16_t filename_index;
  parser_state* parser;

  int rlev;                     /* recursion levels */
} codegen_scope;

static codegen_scope* scope_new(mrb_state *mrb, codegen_scope *prev, node *lv);
static void scope_finish(codegen_scope *s);
static struct loopinfo *loop_push(codegen_scope *s, enum looptype t);
static void loop_break(codegen_scope *s, node *tree);
static void loop_pop(codegen_scope *s, int val);

/*
 * The search for catch handlers starts at the end of the table in mrb_vm_run().
 * Therefore, the next handler to be added must meet one of the following conditions.
 * - Larger start position
 * - Same start position but smaller end position
 */
static int catch_handler_new(codegen_scope *s);
static void catch_handler_set(codegen_scope *s, int ent, enum mrb_catch_type type, uint32_t begin, uint32_t end, uint32_t target);

static void gen_assignment(codegen_scope *s, node *tree, int sp, int val);
static void gen_vmassignment(codegen_scope *s, node *tree, int rhs, int val);

static void codegen(codegen_scope *s, node *tree, int val);
static void raise_error(codegen_scope *s, const char *msg);

static void
codegen_error(codegen_scope *s, const char *message)
{
  if (!s) return;
#ifndef MRB_NO_STDIO
  if (s->filename_sym && s->lineno) {
    const char *filename = mrb_sym_name_len(s->mrb, s->filename_sym, NULL);
    fprintf(stderr, "%s:%d: %s\n", filename, s->lineno, message);
  }
  else {
    fprintf(stderr, "%s\n", message);
  }
#endif
  while (s->prev) {
    codegen_scope *tmp = s->prev;
    if (s->irep) {
      mrb_free(s->mrb, s->iseq);
      for (int i=0; i<s->irep->plen; i++) {
        mrb_pool_value *pv = &s->pool[i];
        if ((pv->tt & 0x3) == IREP_TT_STR || pv->tt == IREP_TT_BIGINT) {
          mrb_free(s->mrb, (void*)pv->u.str);
        }
      }
      mrb_free(s->mrb, s->pool);
      mrb_free(s->mrb, s->syms);
      mrb_free(s->mrb, s->catch_table);
      if (s->reps) {
        /* copied from mrb_irep_free() in state.c */
        for (int i=0; i<s->irep->rlen; i++) {
          if (s->reps[i])
            mrb_irep_decref(s->mrb, (mrb_irep*)s->reps[i]);
        }
        mrb_free(s->mrb, s->reps);
      }
      mrb_free(s->mrb, s->lines);
    }
    mrb_pool_close(s->mpool);
    s = tmp;
  }
  MRB_THROW(s->mrb->jmp);
}

static void*
codegen_palloc(codegen_scope *s, size_t len)
{
  void *p = mrb_pool_alloc(s->mpool, len);

  if (!p) codegen_error(s, "pool memory allocation");
  return p;
}

static void*
codegen_realloc(codegen_scope *s, void *p, size_t len)
{
  p = mrb_realloc_simple(s->mrb, p, len);

  if (!p && len > 0) codegen_error(s, "mrb_realloc");
  return p;
}

static void
check_no_ext_ops(codegen_scope *s, uint16_t a, uint16_t b)
{
  if (s->parser->no_ext_ops && (a | b) > 0xff) {
    codegen_error(s, "need OP_EXTs instruction (currently OP_EXTs are prohibited)");
  }
}

static int
new_label(codegen_scope *s)
{
  return s->lastlabel = s->pc;
}

static void
emit_B(codegen_scope *s, uint32_t pc, uint8_t i)
{
  if (pc >= s->icapa) {
    if (pc == UINT32_MAX) {
      codegen_error(s, "too big code block");
    }
    if (pc >= UINT32_MAX / 2) {
      pc = UINT32_MAX;
    }
    else {
      s->icapa *= 2;
    }
    s->iseq = (mrb_code *)codegen_realloc(s, s->iseq, sizeof(mrb_code)*s->icapa);
    if (s->lines) {
      s->lines = (uint16_t*)codegen_realloc(s, s->lines, sizeof(uint16_t)*s->icapa);
    }
  }
  if (s->lines) {
    if (s->lineno > 0 || pc == 0)
      s->lines[pc] = s->lineno;
    else
      s->lines[pc] = s->lines[pc-1];
  }
  s->iseq[pc] = i;
}

static void
emit_S(codegen_scope *s, int pc, uint16_t i)
{
  uint8_t hi = i>>8;
  uint8_t lo = i&0xff;

  emit_B(s, pc,   hi);
  emit_B(s, pc+1, lo);
}

static void
gen_B(codegen_scope *s, uint8_t i)
{
  emit_B(s, s->pc, i);
  s->pc++;
}

static void
gen_S(codegen_scope *s, uint16_t i)
{
  emit_S(s, s->pc, i);
  s->pc += 2;
}

static void
genop_0(codegen_scope *s, mrb_code i)
{
  s->lastpc = s->pc;
  gen_B(s, i);
}

static void
genop_1(codegen_scope *s, mrb_code i, uint16_t a)
{
  s->lastpc = s->pc;
  check_no_ext_ops(s, a, 0);
  if (a > 0xff) {
    gen_B(s, OP_EXT1);
    gen_B(s, i);
    gen_S(s, a);
  }
  else {
    gen_B(s, i);
    gen_B(s, (uint8_t)a);
  }
}

static void
genop_2(codegen_scope *s, mrb_code i, uint16_t a, uint16_t b)
{
  s->lastpc = s->pc;
  check_no_ext_ops(s, a, b);
  if (a > 0xff && b > 0xff) {
    gen_B(s, OP_EXT3);
    gen_B(s, i);
    gen_S(s, a);
    gen_S(s, b);
  }
  else if (b > 0xff) {
    gen_B(s, OP_EXT2);
    gen_B(s, i);
    gen_B(s, (uint8_t)a);
    gen_S(s, b);
  }
  else if (a > 0xff) {
    gen_B(s, OP_EXT1);
    gen_B(s, i);
    gen_S(s, a);
    gen_B(s, (uint8_t)b);
  }
  else {
    gen_B(s, i);
    gen_B(s, (uint8_t)a);
    gen_B(s, (uint8_t)b);
  }
}

static void
genop_3(codegen_scope *s, mrb_code i, uint16_t a, uint16_t b, uint8_t c)
{
  genop_2(s, i, a, b);
  gen_B(s, c);
}

static void
genop_2S(codegen_scope *s, mrb_code i, uint16_t a, uint16_t b)
{
  genop_1(s, i, a);
  gen_S(s, b);
}

static void
genop_2SS(codegen_scope *s, mrb_code i, uint16_t a, uint32_t b)
{
  genop_1(s, i, a);
  gen_S(s, b>>16);
  gen_S(s, b&0xffff);
}

static void
genop_W(codegen_scope *s, mrb_code i, uint32_t a)
{
  uint8_t a1 = (a>>16) & 0xff;
  uint8_t a2 = (a>>8) & 0xff;
  uint8_t a3 = a & 0xff;

  s->lastpc = s->pc;
  gen_B(s, i);
  gen_B(s, a1);
  gen_B(s, a2);
  gen_B(s, a3);
}

#define NOVAL  0
#define VAL    1

static mrb_bool
no_optimize(codegen_scope *s)
{
  if (s && s->parser && s->parser->no_optimize)
    return TRUE;
  return FALSE;
}

struct mrb_insn_data
mrb_decode_insn(const mrb_code *pc)
{
  struct mrb_insn_data data = { 0 };
  if (pc == 0) return data;
  data.addr = pc;
  mrb_code insn = READ_B();
  uint16_t a = 0;
  uint16_t b = 0;
  uint16_t c = 0;

  switch (insn) {
#define FETCH_Z() /* empty */
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x (); break;
#include "mruby/ops.h"
#undef OPCODE
  }
  switch (insn) {
  case OP_EXT1:
    insn = READ_B();
    switch (insn) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _1 (); break;
#include "mruby/ops.h"
#undef OPCODE
    }
    break;
  case OP_EXT2:
    insn = READ_B();
    switch (insn) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _2 (); break;
#include "mruby/ops.h"
#undef OPCODE
    }
    break;
  case OP_EXT3:
    insn = READ_B();
    switch (insn) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _3 (); break;
#include "mruby/ops.h"
#undef OPCODE
    }
    break;
  default:
    break;
  }
  data.insn = insn;
  data.a = a;
  data.b = b;
  data.c = c;
  return data;
}

#undef OPCODE
#define Z 1
#define S 3
#define W 4
#define OPCODE(_,x) x,
/* instruction sizes */
static uint8_t mrb_insn_size[] = {
#define B 2
#define BB 3
#define BBB 4
#define BS 4
#define BSS 6
#include "mruby/ops.h"
#undef B
#undef BB
#undef BBB
#undef BS
#undef BSS
};
/* EXT1 instruction sizes */
static uint8_t mrb_insn_size1[] = {
#define B 3
#define BB 4
#define BBB 5
#define BS 5
#define BSS 7
#include "mruby/ops.h"
#undef B
#undef BS
#undef BSS
};
/* EXT2 instruction sizes */
static uint8_t mrb_insn_size2[] = {
#define B 2
#define BS 4
#define BSS 6
#include "mruby/ops.h"
#undef B
#undef BB
#undef BBB
#undef BS
#undef BSS
};
/* EXT3 instruction sizes */
#define B 3
#define BB 5
#define BBB 6
#define BS 5
#define BSS 7
static uint8_t mrb_insn_size3[] = {
#include "mruby/ops.h"
};
#undef B
#undef BB
#undef BBB
#undef BS
#undef BSS
#undef OPCODE

static const mrb_code*
mrb_prev_pc(codegen_scope *s, const mrb_code *pc)
{
  const mrb_code *prev_pc = NULL;
  const mrb_code *i = s->iseq;

  while (i<pc) {
    uint8_t insn = i[0];
    prev_pc = i;
    switch (insn) {
    case OP_EXT1:
      i += mrb_insn_size1[i[1]] + 1;
      break;
    case OP_EXT2:
      i += mrb_insn_size2[i[1]] + 1;
      break;
    case OP_EXT3:
      i += mrb_insn_size3[i[1]] + 1;
      break;
    default:
      i += mrb_insn_size[insn];
      break;
    }
  }
  return prev_pc;
}

#define pc_addr(s) &((s)->iseq[(s)->pc])
#define addr_pc(s, addr) (uint32_t)((addr) - s->iseq)
#define rewind_pc(s) s->pc = s->lastpc

static struct mrb_insn_data
mrb_last_insn(codegen_scope *s)
{
  if (s->pc == 0) {
    struct mrb_insn_data data = { OP_NOP, 0 };
    return data;
  }
  return mrb_decode_insn(&s->iseq[s->lastpc]);
}

static mrb_bool
no_peephole(codegen_scope *s)
{
  return no_optimize(s) || s->lastlabel == s->pc || s->pc == 0 || s->pc == s->lastpc;
}

#define JMPLINK_START UINT32_MAX

static void
gen_jmpdst(codegen_scope *s, uint32_t pc)
{

  if (pc == JMPLINK_START) {
    pc = 0;
  }
  uint32_t pos2 = s->pc+2;
  int32_t off = pc - pos2;

  if (off > INT16_MAX || INT16_MIN > off) {
    codegen_error(s, "too big jump offset");
  }
  gen_S(s, (uint16_t)off);
}

static uint32_t
genjmp(codegen_scope *s, mrb_code i, uint32_t pc)
{
  uint32_t pos;

  genop_0(s, i);
  pos = s->pc;
  gen_jmpdst(s, pc);
  return pos;
}

#define genjmp_0(s,i) genjmp(s,i,JMPLINK_START)

static uint32_t
genjmp2(codegen_scope *s, mrb_code i, uint16_t a, uint32_t pc, int val)
{
  uint32_t pos;

  if (!no_peephole(s) && !val) {
    struct mrb_insn_data data = mrb_last_insn(s);

    switch (data.insn) {
    case OP_MOVE:
      if (data.a == a && data.a > s->nlocals) {
        rewind_pc(s);
        a = data.b;
      }
      break;
    case OP_LOADNIL:
    case OP_LOADF:
      if (data.a == a || data.a > s->nlocals) {
        s->pc = addr_pc(s, data.addr);
        if (i == OP_JMPNOT || (i == OP_JMPNIL && data.insn == OP_LOADNIL)) {
          return genjmp(s, OP_JMP, pc);
        }
        else {                  /* OP_JMPIF */
          return JMPLINK_START;
        }
      }
      break;
    case OP_LOADT: case OP_LOADI: case OP_LOADINEG: case OP_LOADI__1:
    case OP_LOADI_0: case OP_LOADI_1: case OP_LOADI_2: case OP_LOADI_3:
    case OP_LOADI_4: case OP_LOADI_5: case OP_LOADI_6: case OP_LOADI_7:
      if (data.a == a || data.a > s->nlocals) {
        s->pc = addr_pc(s, data.addr);
        if (i == OP_JMPIF) {
          return genjmp(s, OP_JMP, pc);
        }
        else {                  /* OP_JMPNOT and OP_JMPNIL */
          return JMPLINK_START;
        }
      }
      break;
    }
  }

  if (a > 0xff) {
    check_no_ext_ops(s, a, 0);
    gen_B(s, OP_EXT1);
    genop_0(s, i);
    gen_S(s, a);
  }
  else {
    genop_0(s, i);
    gen_B(s, (uint8_t)a);
  }
  pos = s->pc;
  gen_jmpdst(s, pc);
  return pos;
}

#define genjmp2_0(s,i,a,val) genjmp2(s,i,a,JMPLINK_START,val)

static mrb_bool get_int_operand(codegen_scope *s, struct mrb_insn_data *data, mrb_int *ns);
static void gen_int(codegen_scope *s, uint16_t dst, mrb_int i);

static void
gen_move(codegen_scope *s, uint16_t dst, uint16_t src, int nopeep)
{
  if (nopeep || no_peephole(s)) goto normal;
  else if (dst == src) return;
  else {
    struct mrb_insn_data data = mrb_last_insn(s);

    switch (data.insn) {
    case OP_MOVE:
      if (dst == src) return;             /* remove useless MOVE */
      if (data.b == dst && data.a == src) /* skip swapping MOVE */
        return;
      goto normal;
    case OP_LOADNIL: case OP_LOADSELF: case OP_LOADT: case OP_LOADF:
    case OP_LOADI__1:
    case OP_LOADI_0: case OP_LOADI_1: case OP_LOADI_2: case OP_LOADI_3:
    case OP_LOADI_4: case OP_LOADI_5: case OP_LOADI_6: case OP_LOADI_7:
      if (data.a != src || data.a < s->nlocals) goto normal;
      rewind_pc(s);
      genop_1(s, data.insn, dst);
      return;
    case OP_HASH: case OP_ARRAY:
      if (data.b != 0) goto normal;
      /* fall through */
    case OP_LOADI: case OP_LOADINEG:
    case OP_LOADL: case OP_LOADSYM:
    case OP_GETGV: case OP_GETSV: case OP_GETIV: case OP_GETCV:
    case OP_GETCONST: case OP_STRING:
    case OP_LAMBDA: case OP_BLOCK: case OP_METHOD: case OP_BLKPUSH:
      if (data.a != src || data.a < s->nlocals) goto normal;
      rewind_pc(s);
      genop_2(s, data.insn, dst, data.b);
      return;
    case OP_LOADI16:
      if (data.a != src || data.a < s->nlocals) goto normal;
      rewind_pc(s);
      genop_2S(s, data.insn, dst, data.b);
      return;
    case OP_LOADI32:
      if (data.a != src || data.a < s->nlocals) goto normal;
      else {
        uint32_t i = (uint32_t)data.b<<16|data.c;
        rewind_pc(s);
        genop_2SS(s, data.insn, dst, i);
      }
      return;
    case OP_AREF:
    case OP_GETUPVAR:
      if (data.a != src || data.a < s->nlocals) goto normal;
      rewind_pc(s);
      genop_3(s, data.insn, dst, data.b, data.c);
      return;
    case OP_ADDI: case OP_SUBI:
      if (addr_pc(s, data.addr) == s->lastlabel || data.a != src || data.a < s->nlocals) goto normal;
      else {
        struct mrb_insn_data data0 = mrb_decode_insn(mrb_prev_pc(s, data.addr));
        if (data0.insn != OP_MOVE || data0.a != data.a || data0.b != dst) goto normal;
        s->pc = addr_pc(s, data0.addr);
        if (addr_pc(s, data0.addr) != s->lastlabel) {
          /* constant folding */
          data0 = mrb_decode_insn(mrb_prev_pc(s, data0.addr));
          mrb_int n;
          if (data0.a == dst && get_int_operand(s, &data0, &n)) {
            if ((data.insn == OP_ADDI && !mrb_int_add_overflow(n, data.b, &n)) ||
                (data.insn == OP_SUBI && !mrb_int_sub_overflow(n, data.b, &n))) {
              s->pc = addr_pc(s, data0.addr);
              gen_int(s, dst, n);
              return;
            }
          }
        }
      }
      genop_2(s, data.insn, dst, data.b);
      return;
    default:
      break;
    }
  }
 normal:
  genop_2(s, OP_MOVE, dst, src);
  return;
}

static int search_upvar(codegen_scope *s, mrb_sym id, int *idx);

static void
gen_getupvar(codegen_scope *s, uint16_t dst, mrb_sym id)
{
  int idx;
  int lv = search_upvar(s, id, &idx);

  if (!no_peephole(s)) {
    struct mrb_insn_data data = mrb_last_insn(s);
    if (data.insn == OP_SETUPVAR && data.a == dst && data.b == idx && data.c == lv) {
      /* skip GETUPVAR right after SETUPVAR */
      return;
    }
  }
  genop_3(s, OP_GETUPVAR, dst, idx, lv);
}

static void
gen_setupvar(codegen_scope *s, uint16_t dst, mrb_sym id)
{
  int idx;
  int lv = search_upvar(s, id, &idx);

  if (!no_peephole(s)) {
    struct mrb_insn_data data = mrb_last_insn(s);
    if (data.insn == OP_MOVE && data.a == dst) {
      dst = data.b;
      rewind_pc(s);
    }
  }
  genop_3(s, OP_SETUPVAR, dst, idx, lv);
}

static void
gen_return(codegen_scope *s, uint8_t op, uint16_t src)
{
  if (no_peephole(s)) {
    genop_1(s, op, src);
  }
  else {
    struct mrb_insn_data data = mrb_last_insn(s);

    if (data.insn == OP_MOVE && src == data.a) {
      rewind_pc(s);
      genop_1(s, op, data.b);
    }
    else if (data.insn != OP_RETURN) {
      genop_1(s, op, src);
    }
  }
}

static mrb_bool
get_int_operand(codegen_scope *s, struct mrb_insn_data *data, mrb_int *n)
{
  switch (data->insn) {
  case OP_LOADI__1:
    *n = -1;
    return TRUE;

  case OP_LOADINEG:
    *n = -data->b;
    return TRUE;

  case OP_LOADI_0: case OP_LOADI_1: case OP_LOADI_2: case OP_LOADI_3:
  case OP_LOADI_4: case OP_LOADI_5: case OP_LOADI_6: case OP_LOADI_7:
    *n = data->insn - OP_LOADI_0;
    return TRUE;

  case OP_LOADI:
  case OP_LOADI16:
    *n = (int16_t)data->b;
    return TRUE;

  case OP_LOADI32:
    *n = (mrb_int)((uint32_t)data->b<<16)+data->c;
    return TRUE;

  case OP_LOADL:
    {
      mrb_pool_value *pv = &s->pool[data->b];

      if (pv->tt == IREP_TT_INT32) {
        *n = (mrb_int)pv->u.i32;
      }
#ifdef MRB_INT64
      else if (pv->tt == IREP_TT_INT64) {
        *n = (mrb_int)pv->u.i64;
      }
#endif
      else {
        return FALSE;
      }
    }
    return TRUE;

  default:
    return FALSE;
  }
}

static void
gen_addsub(codegen_scope *s, uint8_t op, uint16_t dst)
{
  if (no_peephole(s)) {
  normal:
    genop_1(s, op, dst);
    return;
  }
  else {
    struct mrb_insn_data data = mrb_last_insn(s);
    mrb_int n;

    if (!get_int_operand(s, &data, &n)) {
      /* not integer immediate */
      goto normal;
    }
    struct mrb_insn_data data0 = mrb_decode_insn(mrb_prev_pc(s, data.addr));
    mrb_int n0;
    if (addr_pc(s, data.addr) == s->lastlabel || !get_int_operand(s, &data0, &n0)) {
      /* OP_ADDI/OP_SUBI takes upto 8bits */
      if (n > INT8_MAX || n < INT8_MIN) goto normal;
      rewind_pc(s);
      if (n == 0) return;
      if (n > 0) {
        if (op == OP_ADD) genop_2(s, OP_ADDI, dst, (uint16_t)n);
        else genop_2(s, OP_SUBI, dst, (uint16_t)n);
      }
      else {                    /* n < 0 */
        n = -n;
        if (op == OP_ADD) genop_2(s, OP_SUBI, dst, (uint16_t)n);
        else genop_2(s, OP_ADDI, dst, (uint16_t)n);
      }
      return;
    }
    if (op == OP_ADD) {
      if (mrb_int_add_overflow(n0, n, &n)) goto normal;
    }
    else { /* OP_SUB */
      if (mrb_int_sub_overflow(n0, n, &n)) goto normal;
    }
    s->pc = addr_pc(s, data0.addr);
    gen_int(s, dst, n);
  }
}

static void
gen_muldiv(codegen_scope *s, uint8_t op, uint16_t dst)
{
  if (no_peephole(s)) {
  normal:
    genop_1(s, op, dst);
    return;
  }
  else {
    struct mrb_insn_data data = mrb_last_insn(s);
    mrb_int n, n0;
    if (addr_pc(s, data.addr) == s->lastlabel || !get_int_operand(s, &data, &n)) {
      /* not integer immediate */
      goto normal;
    }
    struct mrb_insn_data data0 = mrb_decode_insn(mrb_prev_pc(s, data.addr));
    if (!get_int_operand(s, &data0, &n0) || n == 0) {
      goto normal;
    }
    if (op == OP_MUL) {
      if (mrb_int_mul_overflow(n0, n, &n)) goto normal;
    }
    else { /* OP_DIV */
      if (n0 == MRB_INT_MIN && n == -1) goto normal;
      n = mrb_div_int(s->mrb, n0, n);
    }
    s->pc = addr_pc(s, data0.addr);
    gen_int(s, dst, n);
  }
}

mrb_bool mrb_num_shift(mrb_state *mrb, mrb_int val, mrb_int width, mrb_int *num);

static mrb_bool
gen_binop(codegen_scope *s, mrb_sym op, uint16_t dst)
{
  if (no_peephole(s)) return FALSE;
  else if (op == MRB_OPSYM_2(s->mrb, aref)) {
    genop_1(s, OP_GETIDX, dst);
    return TRUE;
  }
  else {
    struct mrb_insn_data data = mrb_last_insn(s);
    mrb_int n, n0;
    if (addr_pc(s, data.addr) == s->lastlabel || !get_int_operand(s, &data, &n)) {
      /* not integer immediate */
      return FALSE;
    }
    struct mrb_insn_data data0 = mrb_decode_insn(mrb_prev_pc(s, data.addr));
    if (!get_int_operand(s, &data0, &n0)) {
      return FALSE;
    }
    if (op == MRB_OPSYM_2(s->mrb, lshift)) {
      if (!mrb_num_shift(s->mrb, n0, n, &n)) return FALSE;
    }
    else if (op == MRB_OPSYM_2(s->mrb, rshift)) {
      if (n == MRB_INT_MIN) return FALSE;
      if (!mrb_num_shift(s->mrb, n0, -n, &n)) return FALSE;
    }
    else if (op == MRB_OPSYM_2(s->mrb, mod) && n != 0) {
      if (n0 == MRB_INT_MIN && n == -1) {
        n = 0;
      }
      else {
        mrb_int n1 = n0 % n;
        if ((n0 < 0) != (n < 0) && n1 != 0) {
          n1 += n;
        }
        n = n1;
      }
    }
    else if (op == MRB_OPSYM_2(s->mrb, and)) {
      n = n0 & n;
    }
    else if (op == MRB_OPSYM_2(s->mrb, or)) {
      n = n0 | n;
    }
    else if (op == MRB_OPSYM_2(s->mrb, xor)) {
      n = n0 ^ n;
    }
    else {
      return FALSE;
    }
    s->pc = addr_pc(s, data0.addr);
    gen_int(s, dst, n);
    return TRUE;
  }
}

static uint32_t
dispatch(codegen_scope *s, uint32_t pos0)
{
  int32_t pos1;
  int32_t offset;
  int16_t newpos;

  if (pos0 == JMPLINK_START) return 0;

  pos1 = pos0 + 2;
  offset = s->pc - pos1;
  if (offset > INT16_MAX) {
    codegen_error(s, "too big jmp offset");
  }
  s->lastlabel = s->pc;
  newpos = (int16_t)PEEK_S(s->iseq+pos0);
  emit_S(s, pos0, (uint16_t)offset);
  if (newpos == 0) return 0;
  return pos1+newpos;
}

static void
dispatch_linked(codegen_scope *s, uint32_t pos)
{
  if (pos==JMPLINK_START) return;
  for (;;) {
    pos = dispatch(s, pos);
    if (pos==0) break;
  }
}

#define nregs_update do {if (s->sp > s->nregs) s->nregs = s->sp;} while (0)
static void
push_n_(codegen_scope *s, int n)
{
  if (s->sp+n >= 0xffff) {
    codegen_error(s, "too complex expression");
  }
  s->sp+=n;
  nregs_update;
}

static void
pop_n_(codegen_scope *s, int n)
{
  if ((int)s->sp-n < 0) {
    codegen_error(s, "stack pointer underflow");
  }
  s->sp-=n;
}

#define push() push_n_(s,1)
#define push_n(n) push_n_(s,n)
#define pop() pop_n_(s,1)
#define pop_n(n) pop_n_(s,n)
#define cursp() (s->sp)

static int
new_litbn(codegen_scope *s, const char *p, int base, mrb_bool neg)
{
  int i;
  size_t plen;
  mrb_pool_value *pv;

  plen = strlen(p);
  if (plen > 255) {
    codegen_error(s, "integer too big");
  }
  for (i=0; i<s->irep->plen; i++) {
    size_t len;
    pv = &s->pool[i];
    if (pv->tt != IREP_TT_BIGINT) continue;
    len = pv->u.str[0];
    if (len == plen && pv->u.str[1] == base && memcmp(pv->u.str+2, p, len) == 0)
      return i;
  }

  if (s->irep->plen == s->pcapa) {
    s->pcapa *= 2;
    s->pool = (mrb_pool_value*)codegen_realloc(s, s->pool, sizeof(mrb_pool_value)*s->pcapa);
  }

  pv = &s->pool[s->irep->plen];
  i = s->irep->plen++;
  {
    char *buf;
    pv->tt = IREP_TT_BIGINT;
    buf = (char*)codegen_realloc(s, NULL, plen+3);
    buf[0] = (char)plen;
    buf[1] = base;
    if (neg) buf[1] = 0x80;
    memcpy(buf+2, p, plen);
    buf[plen+2] = '\0';
    pv->u.str = buf;
  }
  return i;
}

static int
new_lit(codegen_scope *s, mrb_value val)
{
  int i;
  mrb_pool_value *pv;

  switch (mrb_type(val)) {
  case MRB_TT_STRING:
    for (i=0; i<s->irep->plen; i++) {
      mrb_int len;
      pv = &s->pool[i];
      if (pv->tt & IREP_TT_NFLAG) continue;
      len = pv->tt>>2;
      if (RSTRING_LEN(val) != len) continue;
      if (memcmp(pv->u.str, RSTRING_PTR(val), len) == 0)
        return i;
    }
    break;
#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    for (i=0; i<s->irep->plen; i++) {
      mrb_float f1, f2;
      pv = &s->pool[i];
      if (pv->tt != IREP_TT_FLOAT) continue;
      pv = &s->pool[i];
      f1 = pv->u.f;
      f2 = mrb_float(val);
      if (f1 == f2 && !signbit(f1) == !signbit(f2)) return i;
    }
    break;
#endif
  case MRB_TT_INTEGER:
    for (i=0; i<s->irep->plen; i++) {
      mrb_int v = mrb_integer(val);
      pv = &s->pool[i];
      if (pv->tt == IREP_TT_INT32) {
        if (v == pv->u.i32) return i;
      }
#ifdef MRB_64BIT
      else if (pv->tt == IREP_TT_INT64) {
        if (v == pv->u.i64) return i;
      }
      continue;
#endif
    }
    break;
  default:
    /* should not happen */
    return 0;
  }

  if (s->irep->plen == s->pcapa) {
    s->pcapa *= 2;
    s->pool = (mrb_pool_value*)codegen_realloc(s, s->pool, sizeof(mrb_pool_value)*s->pcapa);
  }

  pv = &s->pool[s->irep->plen];
  i = s->irep->plen++;

  switch (mrb_type(val)) {
  case MRB_TT_STRING:
    if (RSTR_NOFREE_P(RSTRING(val))) {
      pv->tt = (uint32_t)(RSTRING_LEN(val)<<2) | IREP_TT_SSTR;
      pv->u.str = RSTRING_PTR(val);
    }
    else {
      char *p;
      mrb_int len = RSTRING_LEN(val);
      pv->tt = (uint32_t)(len<<2) | IREP_TT_STR;
      p = (char*)codegen_realloc(s, NULL, len+1);
      memcpy(p, RSTRING_PTR(val), len);
      p[len] = '\0';
      pv->u.str = p;
    }
    break;

#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    pv->tt = IREP_TT_FLOAT;
    pv->u.f = mrb_float(val);
    break;
#endif
  case MRB_TT_INTEGER:
#ifdef MRB_INT64
    pv->tt = IREP_TT_INT64;
    pv->u.i64 = mrb_integer(val);
#else
    pv->tt = IREP_TT_INT32;
    pv->u.i32 = mrb_integer(val);
#endif
    break;

  default:
    /* should not happen */
    break;
  }
  return i;
}

static int
new_sym(codegen_scope *s, mrb_sym sym)
{
  int i, len;

  mrb_assert(s->irep);

  len = s->irep->slen;
  for (i=0; i<len; i++) {
    if (s->syms[i] == sym) return i;
  }
  if (s->irep->slen >= s->scapa) {
    s->scapa *= 2;
    if (s->scapa > 0xffff) {
      codegen_error(s, "too many symbols");
    }
    s->syms = (mrb_sym*)codegen_realloc(s, s->syms, sizeof(mrb_sym)*s->scapa);
  }
  s->syms[s->irep->slen] = sym;
  return s->irep->slen++;
}

static void
gen_setxv(codegen_scope *s, uint8_t op, uint16_t dst, mrb_sym sym, int val)
{
  int idx = new_sym(s, sym);
  if (!val && !no_peephole(s)) {
    struct mrb_insn_data data = mrb_last_insn(s);
    if (data.insn == OP_MOVE && data.a == dst) {
      dst = data.b;
      rewind_pc(s);
    }
  }
  genop_2(s, op, dst, idx);
}

static void
gen_int(codegen_scope *s, uint16_t dst, mrb_int i)
{
  if (i < 0) {
    if (i == -1) genop_1(s, OP_LOADI__1, dst);
    else if (i >= -0xff) genop_2(s, OP_LOADINEG, dst, (uint16_t)-i);
    else if (i >= INT16_MIN) genop_2S(s, OP_LOADI16, dst, (uint16_t)i);
    else if (i >= INT32_MIN) genop_2SS(s, OP_LOADI32, dst, (uint32_t)i);
    else goto int_lit;
  }
  else if (i < 8) genop_1(s, OP_LOADI_0 + (uint8_t)i, dst);
  else if (i <= 0xff) genop_2(s, OP_LOADI, dst, (uint16_t)i);
  else if (i <= INT16_MAX) genop_2S(s, OP_LOADI16, dst, (uint16_t)i);
  else if (i <= INT32_MAX) genop_2SS(s, OP_LOADI32, dst, (uint32_t)i);
  else {
  int_lit:
    genop_2(s, OP_LOADL, dst, new_lit(s, mrb_int_value(s->mrb, i)));
  }
}

static mrb_bool
gen_uniop(codegen_scope *s, mrb_sym sym, uint16_t dst)
{
  if (no_peephole(s)) return FALSE;
  struct mrb_insn_data data = mrb_last_insn(s);
  mrb_int n;

  if (!get_int_operand(s, &data, &n)) return FALSE;
  if (sym == MRB_OPSYM_2(s->mrb, plus)) {
    /* unary plus does nothing */
  }
  else if (sym == MRB_OPSYM_2(s->mrb, minus)) {
    if (n == MRB_INT_MIN) return FALSE;
    n = -n;
  }
  else if (sym == MRB_OPSYM_2(s->mrb, neg)) {
    n = ~n;
  }
  else {
    return FALSE;
  }
  s->pc = addr_pc(s, data.addr);
  gen_int(s, dst, n);
  return TRUE;
}

static int
node_len(node *tree)
{
  int n = 0;

  while (tree) {
    n++;
    tree = tree->cdr;
  }
  return n;
}

#define nint(x) ((int)(intptr_t)(x))
#define nchar(x) ((char)(intptr_t)(x))
#define nsym(x) ((mrb_sym)(intptr_t)(x))

#define lv_name(lv) nsym((lv)->car)

static int
lv_idx(codegen_scope *s, mrb_sym id)
{
  node *lv = s->lv;
  int n = 1;

  while (lv) {
    if (lv_name(lv) == id) return n;
    n++;
    lv = lv->cdr;
  }
  return 0;
}

static int
search_upvar(codegen_scope *s, mrb_sym id, int *idx)
{
  const struct RProc *u;
  int lv = 0;
  codegen_scope *up = s->prev;

  while (up) {
    *idx = lv_idx(up, id);
    if (*idx > 0) {
      return lv;
    }
    lv ++;
    up = up->prev;
  }

  if (lv < 1) lv = 1;
  u = s->parser->upper;
  while (u && !MRB_PROC_CFUNC_P(u)) {
    const struct mrb_irep *ir = u->body.irep;
    uint_fast16_t n = ir->nlocals;
    int i;

    const mrb_sym *v = ir->lv;
    if (v) {
      for (i=1; n > 1; n--, v++, i++) {
        if (*v == id) {
          *idx = i;
          return lv - 1;
        }
      }
    }
    if (MRB_PROC_SCOPE_P(u)) break;
    u = u->upper;
    lv ++;
  }

  codegen_error(s, "Can't found local variables");
  return -1; /* not reached */
}

static void
for_body(codegen_scope *s, node *tree)
{
  codegen_scope *prev = s;
  int idx;
  struct loopinfo *lp;
  node *n2;

  /* generate receiver */
  codegen(s, tree->cdr->car, VAL);
  /* generate loop-block */
  s = scope_new(s->mrb, s, NULL);

  push();                       /* push for a block parameter */

  /* generate loop variable */
  n2 = tree->car;
  genop_W(s, OP_ENTER, 0x40000);
  if (n2->car && !n2->car->cdr && !n2->cdr) {
    gen_assignment(s, n2->car->car, 1, NOVAL);
  }
  else {
    gen_vmassignment(s, n2, 1, VAL);
  }
  /* construct loop */
  lp = loop_push(s, LOOP_FOR);
  lp->pc1 = new_label(s);

  /* loop body */
  codegen(s, tree->cdr->cdr->car, VAL);
  pop();
  gen_return(s, OP_RETURN, cursp());
  loop_pop(s, NOVAL);
  scope_finish(s);
  s = prev;
  genop_2(s, OP_BLOCK, cursp(), s->irep->rlen-1);
  push();pop(); /* space for a block */
  pop();
  idx = new_sym(s, MRB_SYM_2(s->mrb, each));
  genop_3(s, OP_SENDB, cursp(), idx, 0);
}

static int
lambda_body(codegen_scope *s, node *tree, int blk)
{
  codegen_scope *parent = s;
  s = scope_new(s->mrb, s, tree->car);

  s->mscope = !blk;

  if (blk) {
    struct loopinfo *lp = loop_push(s, LOOP_BLOCK);
    lp->pc0 = new_label(s);
  }
  tree = tree->cdr;
  if (tree->car == NULL) {
    genop_W(s, OP_ENTER, 0);
    s->ainfo = 0;
  }
  else {
    mrb_aspec a;
    int ma, oa, ra, pa, ka, kd, ba, i;
    uint32_t pos;
    node *opt;
    node *margs, *pargs;
    node *tail;

    /* mandatory arguments */
    ma = node_len(tree->car->car);
    margs = tree->car->car;
    tail = tree->car->cdr->cdr->cdr->cdr;

    /* optional arguments */
    oa = node_len(tree->car->cdr->car);
    /* rest argument? */
    ra = tree->car->cdr->cdr->car ? 1 : 0;
    /* mandatory arguments after rest argument */
    pa = node_len(tree->car->cdr->cdr->cdr->car);
    pargs = tree->car->cdr->cdr->cdr->car;
    /* keyword arguments */
    ka = tail? node_len(tail->cdr->car) : 0;
    /* keyword dictionary? */
    kd = tail && tail->cdr->cdr->car? 1 : 0;
    /* block argument? */
    ba = tail && tail->cdr->cdr->cdr->car ? 1 : 0;

    if (ma > 0x1f || oa > 0x1f || pa > 0x1f || ka > 0x1f) {
      codegen_error(s, "too many formal arguments");
    }
    /* (23bits = 5:5:1:5:5:1:1) */
    a = MRB_ARGS_REQ(ma)
      | MRB_ARGS_OPT(oa)
      | (ra? MRB_ARGS_REST() : 0)
      | MRB_ARGS_POST(pa)
      | MRB_ARGS_KEY(ka, kd)
      | (ba? MRB_ARGS_BLOCK() : 0);
    genop_W(s, OP_ENTER, a);
    /* (12bits = 5:1:5:1) */
    s->ainfo = (((ma+oa) & 0x3f) << 7)
      | ((ra & 0x1) << 6)
      | ((pa & 0x1f) << 1)
      | ((ka | kd) ? 1 : 0);
    /* generate jump table for optional arguments initializer */
    pos = new_label(s);
    for (i=0; i<oa; i++) {
      new_label(s);
      genjmp_0(s, OP_JMP);
    }
    if (oa > 0) {
      genjmp_0(s, OP_JMP);
    }
    opt = tree->car->cdr->car;
    i = 0;
    while (opt) {
      int idx;
      mrb_sym id = nsym(opt->car->car);

      dispatch(s, pos+i*3+1);
      codegen(s, opt->car->cdr, VAL);
      pop();
      idx = lv_idx(s, id);
      if (idx > 0) {
        gen_move(s, idx, cursp(), 0);
      }
      else {
        gen_getupvar(s, cursp(), id);
      }
      i++;
      opt = opt->cdr;
    }
    if (oa > 0) {
      dispatch(s, pos+i*3+1);
    }

    /* keyword arguments */
    if (tail) {
      node *kwds = tail->cdr->car;
      int kwrest = 0;

      if (tail->cdr->cdr->car) {
        kwrest = 1;
      }
      mrb_assert(nint(tail->car) == NODE_ARGS_TAIL);
      mrb_assert(node_len(tail) == 4);

      while (kwds) {
        int jmpif_key_p, jmp_def_set = -1;
        node *kwd = kwds->car, *def_arg = kwd->cdr->cdr->car;
        mrb_sym kwd_sym = nsym(kwd->cdr->car);

        mrb_assert(nint(kwd->car) == NODE_KW_ARG);

        if (def_arg) {
          int idx;
          genop_2(s, OP_KEY_P, lv_idx(s, kwd_sym), new_sym(s, kwd_sym));
          jmpif_key_p = genjmp2_0(s, OP_JMPIF, lv_idx(s, kwd_sym), NOVAL);
          codegen(s, def_arg, VAL);
          pop();
          idx = lv_idx(s, kwd_sym);
          if (idx > 0) {
            gen_move(s, idx, cursp(), 0);
          }
          else {
            gen_getupvar(s, cursp(), kwd_sym);
          }
          jmp_def_set = genjmp_0(s, OP_JMP);
          dispatch(s, jmpif_key_p);
        }
        genop_2(s, OP_KARG, lv_idx(s, kwd_sym), new_sym(s, kwd_sym));
        if (jmp_def_set != -1) {
          dispatch(s, jmp_def_set);
        }
        i++;

        kwds = kwds->cdr;
      }
      if (tail->cdr->car && !kwrest) {
        genop_0(s, OP_KEYEND);
      }
    }

    /* argument destructuring */
    if (margs) {
      node *n = margs;

      pos = 1;
      while (n) {
        if (nint(n->car->car) == NODE_MASGN) {
          gen_vmassignment(s, n->car->cdr->car, pos, NOVAL);
        }
        pos++;
        n = n->cdr;
      }
    }
    if (pargs) {
      node *n = pargs;

      pos = ma+oa+ra+1;
      while (n) {
        if (nint(n->car->car) == NODE_MASGN) {
          gen_vmassignment(s, n->car->cdr->car, pos, NOVAL);
        }
        pos++;
        n = n->cdr;
      }
    }
  }

  codegen(s, tree->cdr->car, VAL);
  pop();
  if (s->pc > 0) {
    gen_return(s, OP_RETURN, cursp());
  }
  if (blk) {
    loop_pop(s, NOVAL);
  }
  scope_finish(s);
  return parent->irep->rlen - 1;
}

static int
scope_body(codegen_scope *s, node *tree, int val)
{
  codegen_scope *scope = scope_new(s->mrb, s, tree->car);

  codegen(scope, tree->cdr, VAL);
  gen_return(scope, OP_RETURN, scope->sp-1);
  if (!s->iseq) {
    genop_0(scope, OP_STOP);
  }
  scope_finish(scope);
  if (!s->irep) {
    /* should not happen */
    return 0;
  }
  return s->irep->rlen - 1;
}

static mrb_bool
nosplat(node *t)
{
  while (t) {
    if (nint(t->car->car) == NODE_SPLAT) return FALSE;
    t = t->cdr;
  }
  return TRUE;
}

static mrb_sym
attrsym(codegen_scope *s, mrb_sym a)
{
  const char *name;
  mrb_int len;
  char *name2;

  name = mrb_sym_name_len(s->mrb, a, &len);
  name2 = (char *)codegen_palloc(s,
                                 (size_t)len
                                 + 1 /* '=' */
                                 + 1 /* '\0' */
                                 );
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  memcpy(name2, name, (size_t)len);
  name2[len] = '=';
  name2[len+1] = '\0';

  return mrb_intern(s->mrb, name2, len+1);
}

#define CALL_MAXARGS 15
#define GEN_LIT_ARY_MAX 64
#define GEN_VAL_STACK_MAX 99

static int
gen_values(codegen_scope *s, node *t, int val, int extra, int limit)
{
  int n = 0;
  int first = 1;
  int slimit = GEN_VAL_STACK_MAX;

  if (limit == 0) limit = GEN_LIT_ARY_MAX;
  if (cursp() >= slimit) slimit = INT16_MAX;

  if (!val) {
    while (t) {
      codegen(s, t->car, NOVAL);
      n++;
      t = t->cdr;
    }
    return n;
  }

  while (t) {
    int is_splat = nint(t->car->car) == NODE_SPLAT;

    if (is_splat || n+extra >= limit-1 || cursp() >= slimit) { /* flush stack */
      pop_n(n);
      if (first) {
        if (n == 0) {
          genop_1(s, OP_LOADNIL, cursp());
        }
        else {
          genop_2(s, OP_ARRAY, cursp(), n);
        }
        push();
        first = 0;
        limit = GEN_LIT_ARY_MAX;
      }
      else if (n > 0) {
        pop();
        genop_2(s, OP_ARYPUSH, cursp(), n);
        push();
      }
      n = 0;
    }
    codegen(s, t->car, val);
    if (is_splat) {
      pop(); pop();
      genop_1(s, OP_ARYCAT, cursp());
      push();
    }
    else {
      n++;
    }
    t = t->cdr;
  }
  if (!first) {
    pop();
    if (n > 0) {
      pop_n(n);
      genop_2(s, OP_ARYPUSH, cursp(), n);
    }
    return -1;                  /* variable length */
  }
  return n;
}

static int
gen_hash(codegen_scope *s, node *tree, int val, int limit)
{
  int slimit = GEN_VAL_STACK_MAX;
  if (cursp() >= GEN_LIT_ARY_MAX) slimit = INT16_MAX;
  int len = 0;
  mrb_bool update = FALSE;

  while (tree) {
    if (nint(tree->car->car->car) == NODE_KW_REST_ARGS) {
      if (val && len > 0) {
        pop_n(len*2);
        if (!update) {
          genop_2(s, OP_HASH, cursp(), len);
        }
        else {
          pop();
          genop_2(s, OP_HASHADD, cursp(), len);
        }
        push();
      }
      codegen(s, tree->car->cdr, val);
      if (val && (len > 0 || update)) {
        pop(); pop();
        genop_1(s, OP_HASHCAT, cursp());
        push();
      }
      update = TRUE;
      len = 0;
    }
    else {
      codegen(s, tree->car->car, val);
      codegen(s, tree->car->cdr, val);
      len++;
    }
    tree = tree->cdr;
    if (val && cursp() >= slimit) {
      pop_n(len*2);
      if (!update) {
        genop_2(s, OP_HASH, cursp(), len);
      }
      else {
        pop();
        genop_2(s, OP_HASHADD, cursp(), len);
      }
      push();
      update = TRUE;
      len = 0;
    }
  }
  if (update) {
    if (val && len > 0) {
      pop_n(len*2+1);
      genop_2(s, OP_HASHADD, cursp(), len);
      push();
    }
    return -1;                  /* variable length */
  }
  return len;
}

static void
gen_call(codegen_scope *s, node *tree, mrb_sym name, int sp, int val, int safe)
{
  mrb_sym sym = name ? name : nsym(tree->cdr->car);
  int skip = 0, n = 0, nk = 0, noop = 0, noself = 0, blk = 0, sp_save = cursp();

  if (!tree->car) {
    noself = noop = 1;
    push();
  }
  else {
    codegen(s, tree->car, VAL); /* receiver */
  }
  if (safe) {
    int recv = cursp()-1;
    gen_move(s, cursp(), recv, 1);
    skip = genjmp2_0(s, OP_JMPNIL, cursp(), val);
  }
  tree = tree->cdr->cdr->car;
  if (tree) {
    if (tree->car) {            /* positional arguments */
      n = gen_values(s, tree->car, VAL, sp?1:0, 14);
      if (n < 0) {              /* variable length */
        noop = 1;               /* not operator */
        n = 15;
        push();
      }
    }
    if (tree->cdr->car) {       /* keyword arguments */
      noop = 1;
      nk = gen_hash(s, tree->cdr->car->cdr, VAL, 14);
      if (nk < 0) nk = 15;
    }
  }
  if (sp) {                     /* last argument pushed (attr=, []=) */
    /* pack keyword arguments */
    if (nk > 0 && nk < 15) {
      pop_n(nk*2);
      genop_2(s, OP_HASH, cursp(), nk);
      push();
    }
    if (n == CALL_MAXARGS) {
      if (nk > 0) {
        pop(); pop();
        genop_2(s, OP_ARYPUSH, cursp(), 1);
        push();
      }
      gen_move(s, cursp(), sp, 0);
      pop();
      genop_2(s, OP_ARYPUSH, cursp(), 1);
      push();
    }
    else {
      gen_move(s, cursp(), sp, 0);
      push();
      if (nk > 0) n++;
      n++;
    }
    nk = 0;
  }
  if (tree && tree->cdr && tree->cdr->cdr) {
    codegen(s, tree->cdr->cdr, VAL);
    pop();
    noop = 1;
    blk = 1;
  }
  push();pop();
  s->sp = sp_save;
  if (!noop && sym == MRB_OPSYM_2(s->mrb, add) && n == 1)  {
    gen_addsub(s, OP_ADD, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, sub) && n == 1)  {
    gen_addsub(s, OP_SUB, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, mul) && n == 1)  {
    gen_muldiv(s, OP_MUL, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, div) && n == 1)  {
    gen_muldiv(s, OP_DIV, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, lt) && n == 1)  {
    genop_1(s, OP_LT, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, le) && n == 1)  {
    genop_1(s, OP_LE, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, gt) && n == 1)  {
    genop_1(s, OP_GT, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, ge) && n == 1)  {
    genop_1(s, OP_GE, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, eq) && n == 1)  {
    genop_1(s, OP_EQ, cursp());
  }
  else if (!noop && sym == MRB_OPSYM_2(s->mrb, aset) && n == 2)  {
    genop_1(s, OP_SETIDX, cursp());
  }
  else if (!noop && n == 0 && gen_uniop(s, sym, cursp())) {
    /* constant folding succeeded */
  }
  else if (!noop && n == 1 && gen_binop(s, sym, cursp())) {
    /* constant folding succeeded */
  }
  else if (noself){
    genop_3(s, blk ? OP_SSENDB : OP_SSEND, cursp(), new_sym(s, sym), n|(nk<<4));
  }
  else {
    genop_3(s, blk ? OP_SENDB : OP_SEND, cursp(), new_sym(s, sym), n|(nk<<4));
  }
  if (safe) {
    dispatch(s, skip);
  }
  if (val) {
    push();
  }
}

static void
gen_assignment(codegen_scope *s, node *tree, int sp, int val)
{
  int idx;
  int type = nint(tree->car);

  tree = tree->cdr;
  switch (type) {
  case NODE_GVAR:
    gen_setxv(s, OP_SETGV, sp, nsym(tree), val);
    break;
  case NODE_ARG:
  case NODE_LVAR:
    idx = lv_idx(s, nsym(tree));
    if (idx > 0) {
      if (idx != sp) {
        gen_move(s, idx, sp, val);
      }
      break;
    }
    else {                      /* upvar */
      gen_setupvar(s, sp, nsym(tree));
    }
    break;
  case NODE_NVAR:
    idx = nint(tree);
    codegen_error(s, "Can't assign to numbered parameter");
    break;
  case NODE_IVAR:
    gen_setxv(s, OP_SETIV, sp, nsym(tree), val);
    break;
  case NODE_CVAR:
    gen_setxv(s, OP_SETCV, sp, nsym(tree), val);
    break;
  case NODE_CONST:
    gen_setxv(s, OP_SETCONST, sp, nsym(tree), val);
    break;
  case NODE_COLON2:
    gen_move(s, cursp(), sp, 0);
    push();
    codegen(s, tree->car, VAL);
    pop_n(2);
    idx = new_sym(s, nsym(tree->cdr));
    genop_2(s, OP_SETMCNST, sp, idx);
    break;

  case NODE_CALL:
  case NODE_SCALL:
    push();
    gen_call(s, tree, attrsym(s, nsym(tree->cdr->car)), sp, NOVAL,
             type == NODE_SCALL);
    pop();
    if (val && cursp() != sp) {
      gen_move(s, cursp(), sp, 0);
    }
    break;

  case NODE_MASGN:
    gen_vmassignment(s, tree->car, sp, val);
    break;

  /* splat without assignment */
  case NODE_NIL:
    break;

  default:
    codegen_error(s, "unknown lhs");
    break;
  }
  if (val) push();
}

static void
gen_vmassignment(codegen_scope *s, node *tree, int rhs, int val)
{
  int n = 0, post = 0;
  node *t, *p;

  if (tree->car) {              /* pre */
    t = tree->car;
    n = 0;
    while (t) {
      int sp = cursp();

      genop_3(s, OP_AREF, sp, rhs, n);
      push();
      gen_assignment(s, t->car, sp, NOVAL);
      pop();
      n++;
      t = t->cdr;
    }
  }
  t = tree->cdr;
  if (t) {
    if (t->cdr) {               /* post count */
      p = t->cdr->car;
      while (p) {
        post++;
        p = p->cdr;
      }
    }
    gen_move(s, cursp(), rhs, val);
    push_n(post+1);
    pop_n(post+1);
    genop_3(s, OP_APOST, cursp(), n, post);
    n = 1;
    if (t->car && t->car != (node*)-1) { /* rest */
      gen_assignment(s, t->car, cursp(), NOVAL);
    }
    if (t->cdr && t->cdr->car) {
      t = t->cdr->car;
      while (t) {
        gen_assignment(s, t->car, cursp()+n, NOVAL);
        t = t->cdr;
        n++;
      }
    }
    if (val) {
      gen_move(s, cursp(), rhs, 0);
    }
  }
}

static void
gen_intern(codegen_scope *s)
{
  pop();
  if (!no_peephole(s)) {
    struct mrb_insn_data data = mrb_last_insn(s);

    if (data.insn == OP_STRING && data.a == cursp()) {
      rewind_pc(s);
      genop_2(s, OP_SYMBOL, data.a, data.b);
      push();
      return;
    }
  }
  genop_1(s, OP_INTERN, cursp());
  push();
}

static void
gen_literal_array(codegen_scope *s, node *tree, mrb_bool sym, int val)
{
  if (val) {
    int i = 0, j = 0, gen = 0;

    while (tree) {
      switch (nint(tree->car->car)) {
      case NODE_STR:
        if ((tree->cdr == NULL) && (nint(tree->car->cdr->cdr) == 0))
          break;
        /* fall through */
      case NODE_BEGIN:
        codegen(s, tree->car, VAL);
        ++j;
        break;

      case NODE_LITERAL_DELIM:
        if (j > 0) {
          j = 0;
          ++i;
          if (sym)
            gen_intern(s);
        }
        break;
      }
      while (j >= 2) {
        pop(); pop();
        genop_1(s, OP_STRCAT, cursp());
        push();
        j--;
      }
      if (i > GEN_LIT_ARY_MAX) {
        pop_n(i);
        if (gen) {
          pop();
          genop_2(s, OP_ARYPUSH, cursp(), i);
        }
        else {
          genop_2(s, OP_ARRAY, cursp(), i);
          gen = 1;
        }
        push();
        i = 0;
      }
      tree = tree->cdr;
    }
    if (j > 0) {
      ++i;
      if (sym)
        gen_intern(s);
    }
    pop_n(i);
    if (gen) {
      pop();
      genop_2(s, OP_ARYPUSH, cursp(), i);
    }
    else {
      genop_2(s, OP_ARRAY, cursp(), i);
    }
    push();
  }
  else {
    while (tree) {
      switch (nint(tree->car->car)) {
      case NODE_BEGIN: case NODE_BLOCK:
        codegen(s, tree->car, NOVAL);
      }
      tree = tree->cdr;
    }
  }
}

static void
raise_error(codegen_scope *s, const char *msg)
{
  int idx = new_lit(s, mrb_str_new_cstr(s->mrb, msg));

  genop_1(s, OP_ERR, idx);
}

static mrb_int
readint(codegen_scope *s, const char *p, int base, mrb_bool neg, mrb_bool *overflow)
{
  const char *e = p + strlen(p);
  mrb_int result = 0;

  mrb_assert(base >= 2 && base <= 16);
  if (*p == '+') p++;
  while (p < e) {
    int n;
    char c = *p;
    switch (c) {
    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
      n = c - '0'; break;
    case '8': case '9':
      n = c - '0'; break;
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      n = c - 'a' + 10; break;
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      n = c - 'A' + 10; break;
    default:
      codegen_error(s, "malformed readint input");
      *overflow = TRUE;
      /* not reached */
      return result;
    }
    if (mrb_int_mul_overflow(result, base, &result)) {
    overflow:
      *overflow = TRUE;
      return 0;
    }
    mrb_uint tmp = ((mrb_uint)result)+n;
    if (neg && tmp == (mrb_uint)MRB_INT_MAX+1) {
      *overflow = FALSE;
      return MRB_INT_MIN;
    }
    if (tmp > MRB_INT_MAX) goto overflow;
    result = (mrb_int)tmp;
    p++;
  }
  *overflow = FALSE;
  if (neg) return -result;
  return result;
}

static void
gen_retval(codegen_scope *s, node *tree)
{
  if (nint(tree->car) == NODE_SPLAT) {
    codegen(s, tree, VAL);
    pop();
    genop_1(s, OP_ARYDUP, cursp());
  }
  else {
    codegen(s, tree, VAL);
    pop();
  }
}

static mrb_bool
true_always(node *tree)
{
  switch (nint(tree->car)) {
  case NODE_TRUE:
  case NODE_INT:
  case NODE_STR:
  case NODE_SYM:
    return TRUE;
  default:
    return FALSE;
  }
}

static mrb_bool
false_always(node *tree)
{
  switch (nint(tree->car)) {
  case NODE_FALSE:
  case NODE_NIL:
    return TRUE;
  default:
    return FALSE;
  }
}

static void
gen_blkmove(codegen_scope *s, uint16_t ainfo, int lv)
{
  int m1 = (ainfo>>7)&0x3f;
  int r  = (ainfo>>6)&0x1;
  int m2 = (ainfo>>1)&0x1f;
  int kd = (ainfo)&0x1;
  int off = m1+r+m2+kd+1;
  if (lv == 0) {
    gen_move(s, cursp(), off, 0);
  }
  else {
    genop_3(s, OP_GETUPVAR, cursp(), off, lv);
  }
  push();
}

static void
codegen(codegen_scope *s, node *tree, int val)
{
  int nt;
  int rlev = s->rlev;

  if (!tree) {
    if (val) {
      genop_1(s, OP_LOADNIL, cursp());
      push();
    }
    return;
  }

  s->rlev++;
  if (s->rlev > MRB_CODEGEN_LEVEL_MAX) {
    codegen_error(s, "too complex expression");
  }
  if (s->irep && s->filename_index != tree->filename_index) {
    mrb_sym fname = mrb_parser_get_filename(s->parser, s->filename_index);
    const char *filename = mrb_sym_name_len(s->mrb, fname, NULL);

    mrb_debug_info_append_file(s->mrb, s->irep->debug_info,
                               filename, s->lines, s->debug_start_pos, s->pc);
    s->debug_start_pos = s->pc;
    s->filename_index = tree->filename_index;
    s->filename_sym = mrb_parser_get_filename(s->parser, tree->filename_index);
  }

  nt = nint(tree->car);
  s->lineno = tree->lineno;
  tree = tree->cdr;
  switch (nt) {
  case NODE_BEGIN:
    if (val && !tree) {
      genop_1(s, OP_LOADNIL, cursp());
      push();
    }
    while (tree) {
      codegen(s, tree->car, tree->cdr ? NOVAL : val);
      tree = tree->cdr;
    }
    break;

  case NODE_RESCUE:
    {
      int noexc;
      uint32_t exend, pos1, pos2, tmp;
      struct loopinfo *lp;
      int catch_entry, begin, end;

      if (tree->car == NULL) goto exit;
      lp = loop_push(s, LOOP_BEGIN);
      lp->pc0 = new_label(s);
      catch_entry = catch_handler_new(s);
      begin = s->pc;
      codegen(s, tree->car, VAL);
      pop();
      lp->type = LOOP_RESCUE;
      end = s->pc;
      noexc = genjmp_0(s, OP_JMP);
      catch_handler_set(s, catch_entry, MRB_CATCH_RESCUE, begin, end, s->pc);
      tree = tree->cdr;
      exend = JMPLINK_START;
      pos1 = JMPLINK_START;
      if (tree->car) {
        node *n2 = tree->car;
        int exc = cursp();

        genop_1(s, OP_EXCEPT, exc);
        push();
        while (n2) {
          node *n3 = n2->car;
          node *n4 = n3->car;

          dispatch(s, pos1);
          pos2 = JMPLINK_START;
          do {
            if (n4 && n4->car && nint(n4->car->car) == NODE_SPLAT) {
              codegen(s, n4->car, VAL);
              gen_move(s, cursp(), exc, 0);
              push_n(2); pop_n(2); /* space for one arg and a block */
              pop();
              genop_3(s, OP_SEND, cursp(), new_sym(s, MRB_SYM_2(s->mrb, __case_eqq)), 1);
            }
            else {
              if (n4) {
                codegen(s, n4->car, VAL);
              }
              else {
                genop_2(s, OP_GETCONST, cursp(), new_sym(s, MRB_SYM_2(s->mrb, StandardError)));
                push();
              }
              pop();
              genop_2(s, OP_RESCUE, exc, cursp());
            }
            tmp = genjmp2(s, OP_JMPIF, cursp(), pos2, val);
            pos2 = tmp;
            if (n4) {
              n4 = n4->cdr;
            }
          } while (n4);
          pos1 = genjmp_0(s, OP_JMP);
          dispatch_linked(s, pos2);

          pop();
          if (n3->cdr->car) {
            gen_assignment(s, n3->cdr->car, exc, NOVAL);
          }
          if (n3->cdr->cdr->car) {
            codegen(s, n3->cdr->cdr->car, val);
            if (val) pop();
          }
          tmp = genjmp(s, OP_JMP, exend);
          exend = tmp;
          n2 = n2->cdr;
          push();
        }
        if (pos1 != JMPLINK_START) {
          dispatch(s, pos1);
          genop_1(s, OP_RAISEIF, exc);
        }
      }
      pop();
      tree = tree->cdr;
      dispatch(s, noexc);
      if (tree->car) {
        codegen(s, tree->car, val);
      }
      else if (val) {
        push();
      }
      dispatch_linked(s, exend);
      loop_pop(s, NOVAL);
    }
    break;

  case NODE_ENSURE:
    if (!tree->cdr || !tree->cdr->cdr ||
        (nint(tree->cdr->cdr->car) == NODE_BEGIN &&
         tree->cdr->cdr->cdr)) {
      int catch_entry, begin, end, target;
      int idx;

      catch_entry = catch_handler_new(s);
      begin = s->pc;
      codegen(s, tree->car, val);
      end = target = s->pc;
      push();
      idx = cursp();
      genop_1(s, OP_EXCEPT, idx);
      push();
      codegen(s, tree->cdr->cdr, NOVAL);
      pop();
      genop_1(s, OP_RAISEIF, idx);
      pop();
      catch_handler_set(s, catch_entry, MRB_CATCH_ENSURE, begin, end, target);
    }
    else {                      /* empty ensure ignored */
      codegen(s, tree->car, val);
    }
    break;

  case NODE_LAMBDA:
    if (val) {
      int idx = lambda_body(s, tree, 1);

      genop_2(s, OP_LAMBDA, cursp(), idx);
      push();
    }
    break;

  case NODE_BLOCK:
    if (val) {
      int idx = lambda_body(s, tree, 1);

      genop_2(s, OP_BLOCK, cursp(), idx);
      push();
    }
    break;

  case NODE_IF:
    {
      uint32_t pos1, pos2;
      mrb_bool nil_p = FALSE;
      node *elsepart = tree->cdr->cdr->car;

      if (!tree->car) {
        codegen(s, elsepart, val);
        goto exit;
      }
      if (true_always(tree->car)) {
        codegen(s, tree->cdr->car, val);
        goto exit;
      }
      if (false_always(tree->car)) {
        codegen(s, elsepart, val);
        goto exit;
      }
      if (nint(tree->car->car) == NODE_CALL) {
        node *n = tree->car->cdr;
        mrb_sym mid = nsym(n->cdr->car);
        mrb_sym sym_nil_p = MRB_SYM_Q_2(s->mrb, nil);
        if (mid == sym_nil_p && n->cdr->cdr->car == NULL) {
          nil_p = TRUE;
          codegen(s, n->car, VAL);
        }
      }
      if (!nil_p) {
        codegen(s, tree->car, VAL);
      }
      pop();
      if (val || tree->cdr->car) {
        if (nil_p) {
          pos2 = genjmp2_0(s, OP_JMPNIL, cursp(), val);
          pos1 = genjmp_0(s, OP_JMP);
          dispatch(s, pos2);
        }
        else {
          pos1 = genjmp2_0(s, OP_JMPNOT, cursp(), val);
        }
        codegen(s, tree->cdr->car, val);
        if (val) pop();
        if (elsepart || val) {
          pos2 = genjmp_0(s, OP_JMP);
          dispatch(s, pos1);
          codegen(s, elsepart, val);
          dispatch(s, pos2);
        }
        else {
          dispatch(s, pos1);
        }
      }
      else {                    /* empty then-part */
        if (elsepart) {
          if (nil_p) {
            pos1 = genjmp2_0(s, OP_JMPNIL, cursp(), val);
          }
          else {
            pos1 = genjmp2_0(s, OP_JMPIF, cursp(), val);
          }
          codegen(s, elsepart, val);
          dispatch(s, pos1);
        }
        else if (val && !nil_p) {
          genop_1(s, OP_LOADNIL, cursp());
          push();
        }
      }
    }
    break;

  case NODE_AND:
    {
      uint32_t pos;

      if (true_always(tree->car)) {
        codegen(s, tree->cdr, val);
        goto exit;
      }
      if (false_always(tree->car)) {
        codegen(s, tree->car, val);
        goto exit;
      }
      codegen(s, tree->car, VAL);
      pop();
      pos = genjmp2_0(s, OP_JMPNOT, cursp(), val);
      codegen(s, tree->cdr, val);
      dispatch(s, pos);
    }
    break;

  case NODE_OR:
    {
      uint32_t pos;

      if (true_always(tree->car)) {
        codegen(s, tree->car, val);
        goto exit;
      }
      if (false_always(tree->car)) {
        codegen(s, tree->cdr, val);
        goto exit;
      }
      codegen(s, tree->car, VAL);
      pop();
      pos = genjmp2_0(s, OP_JMPIF, cursp(), val);
      codegen(s, tree->cdr, val);
      dispatch(s, pos);
    }
    break;

  case NODE_WHILE:
  case NODE_UNTIL:
    {
      if (true_always(tree->car)) {
        if (nt == NODE_UNTIL) {
          if (val) {
            genop_1(s, OP_LOADNIL, cursp());
            push();
          }
          goto exit;
        }
      }
      else if (false_always(tree->car)) {
        if (nt == NODE_WHILE) {
          if (val) {
            genop_1(s, OP_LOADNIL, cursp());
            push();
          }
          goto exit;
        }
      }

      uint32_t pos = JMPLINK_START;
      struct loopinfo *lp = loop_push(s, LOOP_NORMAL);

      if (!val) lp->reg = -1;
      lp->pc0 = new_label(s);
      codegen(s, tree->car, VAL);
      pop();
      if (nt == NODE_WHILE) {
        pos = genjmp2_0(s, OP_JMPNOT, cursp(), NOVAL);
      }
      else {
        pos = genjmp2_0(s, OP_JMPIF, cursp(), NOVAL);
      }
      lp->pc1 = new_label(s);
      codegen(s, tree->cdr, NOVAL);
      genjmp(s, OP_JMP, lp->pc0);
      dispatch(s, pos);
      loop_pop(s, val);
    }
    break;

  case NODE_FOR:
    for_body(s, tree);
    if (val) push();
    break;

  case NODE_CASE:
    {
      int head = 0;
      uint32_t pos1, pos2, pos3, tmp;
      node *n;

      pos3 = JMPLINK_START;
      if (tree->car) {
        head = cursp();
        codegen(s, tree->car, VAL);
      }
      tree = tree->cdr;
      while (tree) {
        n = tree->car->car;
        pos1 = pos2 = JMPLINK_START;
        while (n) {
          codegen(s, n->car, VAL);
          if (head) {
            gen_move(s, cursp(), head, 0);
            push(); push(); pop(); pop(); pop();
            if (nint(n->car->car) == NODE_SPLAT) {
              genop_3(s, OP_SEND, cursp(), new_sym(s, MRB_SYM_2(s->mrb, __case_eqq)), 1);
            }
            else {
              genop_3(s, OP_SEND, cursp(), new_sym(s, MRB_OPSYM_2(s->mrb, eqq)), 1);
            }
          }
          else {
            pop();
          }
          tmp = genjmp2(s, OP_JMPIF, cursp(), pos2, NOVAL);
          pos2 = tmp;
          n = n->cdr;
        }
        if (tree->car->car) {
          pos1 = genjmp_0(s, OP_JMP);
          dispatch_linked(s, pos2);
        }
        codegen(s, tree->car->cdr, val);
        if (val) pop();
        tmp = genjmp(s, OP_JMP, pos3);
        pos3 = tmp;
        dispatch(s, pos1);
        tree = tree->cdr;
      }
      if (val) {
        uint32_t pos = cursp();
        genop_1(s, OP_LOADNIL, cursp());
        if (pos3 != JMPLINK_START) dispatch_linked(s, pos3);
        if (head) pop();
        if (cursp() != pos) {
          gen_move(s, cursp(), pos, 0);
        }
        push();
      }
      else {
        if (pos3 != JMPLINK_START) {
          dispatch_linked(s, pos3);
        }
        if (head) {
          pop();
        }
      }
    }
    break;

  case NODE_SCOPE:
    scope_body(s, tree, NOVAL);
    break;

  case NODE_FCALL:
  case NODE_CALL:
    gen_call(s, tree, 0, 0, val, 0);
    break;
  case NODE_SCALL:
    gen_call(s, tree, 0, 0, val, 1);
    break;

  case NODE_DOT2:
    codegen(s, tree->car, val);
    codegen(s, tree->cdr, val);
    if (val) {
      pop(); pop();
      genop_1(s, OP_RANGE_INC, cursp());
      push();
    }
    break;

  case NODE_DOT3:
    codegen(s, tree->car, val);
    codegen(s, tree->cdr, val);
    if (val) {
      pop(); pop();
      genop_1(s, OP_RANGE_EXC, cursp());
      push();
    }
    break;

  case NODE_COLON2:
    {
      int sym = new_sym(s, nsym(tree->cdr));

      codegen(s, tree->car, VAL);
      pop();
      genop_2(s, OP_GETMCNST, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_COLON3:
    {
      int sym = new_sym(s, nsym(tree));

      genop_1(s, OP_OCLASS, cursp());
      genop_2(s, OP_GETMCNST, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_ARRAY:
    {
      int n;

      n = gen_values(s, tree, val, 0, 0);
      if (val) {
        if (n >= 0) {
          pop_n(n);
          genop_2(s, OP_ARRAY, cursp(), n);
        }
        push();
      }
    }
    break;

  case NODE_HASH:
  case NODE_KW_HASH:
    {
      int nk = gen_hash(s, tree, val, GEN_LIT_ARY_MAX);
      if (val && nk >= 0) {
        pop_n(nk*2);
        genop_2(s, OP_HASH, cursp(), nk);
        push();
      }
    }
    break;

  case NODE_SPLAT:
    codegen(s, tree, val);
    break;

  case NODE_ASGN:
    codegen(s, tree->cdr, VAL);
    pop();
    gen_assignment(s, tree->car, cursp(), val);
    break;

  case NODE_MASGN:
    {
      int len = 0, n = 0, post = 0;
      node *t = tree->cdr, *p;
      int rhs = cursp();

      if (nint(t->car) == NODE_ARRAY && t->cdr && nosplat(t->cdr)) {
        /* fixed rhs */
        t = t->cdr;
        while (t) {
          codegen(s, t->car, VAL);
          len++;
          t = t->cdr;
        }
        tree = tree->car;
        if (tree->car) {                /* pre */
          t = tree->car;
          n = 0;
          while (t) {
            if (n < len) {
              gen_assignment(s, t->car, rhs+n, NOVAL);
              n++;
            }
            else {
              genop_1(s, OP_LOADNIL, rhs+n);
              gen_assignment(s, t->car, rhs+n, NOVAL);
            }
            t = t->cdr;
          }
        }
        t = tree->cdr;
        if (t) {
          if (t->cdr) {         /* post count */
            p = t->cdr->car;
            while (p) {
              post++;
              p = p->cdr;
            }
          }
          if (t->car) {         /* rest (len - pre - post) */
            int rn;

            if (len < post + n) {
              rn = 0;
            }
            else {
              rn = len - post - n;
            }
            genop_3(s, OP_ARRAY2, cursp(), rhs+n, rn);
            gen_assignment(s, t->car, cursp(), NOVAL);
            n += rn;
          }
          if (t->cdr && t->cdr->car) {
            t = t->cdr->car;
            while (n<len) {
              gen_assignment(s, t->car, rhs+n, NOVAL);
              t = t->cdr;
              n++;
            }
          }
        }
        pop_n(len);
        if (val) {
          genop_2(s, OP_ARRAY, rhs, len);
          push();
        }
      }
      else {
        /* variable rhs */
        codegen(s, t, VAL);
        gen_vmassignment(s, tree->car, rhs, val);
        if (!val) {
          pop();
        }
      }
    }
    break;

  case NODE_OP_ASGN:
    {
      mrb_sym sym = nsym(tree->cdr->car);
      mrb_int len;
      const char *name = mrb_sym_name_len(s->mrb, sym, &len);
      int idx, callargs = -1, vsp = -1;

      if ((len == 2 && name[0] == '|' && name[1] == '|') &&
          (nint(tree->car->car) == NODE_CONST ||
           nint(tree->car->car) == NODE_CVAR)) {
        int catch_entry, begin, end;
        int noexc, exc;
        struct loopinfo *lp;

        lp = loop_push(s, LOOP_BEGIN);
        lp->pc0 = new_label(s);
        catch_entry = catch_handler_new(s);
        begin = s->pc;
        exc = cursp();
        codegen(s, tree->car, VAL);
        end = s->pc;
        noexc = genjmp_0(s, OP_JMP);
        lp->type = LOOP_RESCUE;
        catch_handler_set(s, catch_entry, MRB_CATCH_RESCUE, begin, end, s->pc);
        genop_1(s, OP_EXCEPT, exc);
        genop_1(s, OP_LOADF, exc);
        dispatch(s, noexc);
        loop_pop(s, NOVAL);
      }
      else if (nint(tree->car->car) == NODE_CALL) {
        node *n = tree->car->cdr;
        int base, i, nargs = 0;
        callargs = 0;

        if (val) {
          vsp = cursp();
          push();
        }
        codegen(s, n->car, VAL);   /* receiver */
        idx = new_sym(s, nsym(n->cdr->car));
        base = cursp()-1;
        if (n->cdr->cdr->car) {
          nargs = gen_values(s, n->cdr->cdr->car->car, VAL, 1, 14);
          if (nargs >= 0) {
            callargs = nargs;
          }
          else { /* varargs */
            push();
            nargs = 1;
            callargs = CALL_MAXARGS;
          }
        }
        /* copy receiver and arguments */
        gen_move(s, cursp(), base, 1);
        for (i=0; i<nargs; i++) {
          gen_move(s, cursp()+i+1, base+i+1, 1);
        }
        push_n(nargs+2);pop_n(nargs+2); /* space for receiver, arguments and a block */
        genop_3(s, OP_SEND, cursp(), idx, callargs);
        push();
      }
      else {
        codegen(s, tree->car, VAL);
      }
      if (len == 2 &&
          ((name[0] == '|' && name[1] == '|') ||
           (name[0] == '&' && name[1] == '&'))) {
        uint32_t pos;

        pop();
        if (val) {
          if (vsp >= 0) {
            gen_move(s, vsp, cursp(), 1);
          }
          pos = genjmp2_0(s, name[0]=='|'?OP_JMPIF:OP_JMPNOT, cursp(), val);
        }
        else {
          pos = genjmp2_0(s, name[0]=='|'?OP_JMPIF:OP_JMPNOT, cursp(), val);
        }
        codegen(s, tree->cdr->cdr->car, VAL);
        pop();
        if (val && vsp >= 0) {
          gen_move(s, vsp, cursp(), 1);
        }
        if (nint(tree->car->car) == NODE_CALL) {
          if (callargs == CALL_MAXARGS) {
            pop();
            genop_2(s, OP_ARYPUSH, cursp(), 1);
          }
          else {
            pop_n(callargs);
            callargs++;
          }
          pop();
          idx = new_sym(s, attrsym(s, nsym(tree->car->cdr->cdr->car)));
          genop_3(s, OP_SEND, cursp(), idx, callargs);
        }
        else {
          gen_assignment(s, tree->car, cursp(), val);
        }
        dispatch(s, pos);
        goto exit;
      }
      codegen(s, tree->cdr->cdr->car, VAL);
      push(); pop();
      pop(); pop();

      if (len == 1 && name[0] == '+')  {
        gen_addsub(s, OP_ADD, cursp());
      }
      else if (len == 1 && name[0] == '-')  {
        gen_addsub(s, OP_SUB, cursp());
      }
      else if (len == 1 && name[0] == '*')  {
        genop_1(s, OP_MUL, cursp());
      }
      else if (len == 1 && name[0] == '/')  {
        genop_1(s, OP_DIV, cursp());
      }
      else if (len == 1 && name[0] == '<')  {
        genop_1(s, OP_LT, cursp());
      }
      else if (len == 2 && name[0] == '<' && name[1] == '=')  {
        genop_1(s, OP_LE, cursp());
      }
      else if (len == 1 && name[0] == '>')  {
        genop_1(s, OP_GT, cursp());
      }
      else if (len == 2 && name[0] == '>' && name[1] == '=')  {
        genop_1(s, OP_GE, cursp());
      }
      else {
        idx = new_sym(s, sym);
        genop_3(s, OP_SEND, cursp(), idx, 1);
      }
      if (callargs < 0) {
        gen_assignment(s, tree->car, cursp(), val);
      }
      else {
        if (val && vsp >= 0) {
          gen_move(s, vsp, cursp(), 0);
        }
        if (callargs == CALL_MAXARGS) {
          pop();
          genop_2(s, OP_ARYPUSH, cursp(), 1);
        }
        else {
          pop_n(callargs);
          callargs++;
        }
        pop();
        idx = new_sym(s, attrsym(s,nsym(tree->car->cdr->cdr->car)));
        genop_3(s, OP_SEND, cursp(), idx, callargs);
      }
    }
    break;

  case NODE_SUPER:
    {
      codegen_scope *s2 = s;
      int lv = 0;
      int n = 0, nk = 0, st = 0;

      push();
      while (!s2->mscope) {
        lv++;
        s2 = s2->prev;
        if (!s2) break;
      }
      if (tree) {
        node *args = tree->car;
        if (args) {
          st = n = gen_values(s, args, VAL, 0, 14);
          if (n < 0) {
            st = 1; n = 15;
            push();
          }
        }
        /* keyword arguments */
        if (tree->cdr->car) {
          nk = gen_hash(s, tree->cdr->car->cdr, VAL, 14);
          if (nk < 0) {st++; nk = 15;}
          else st += nk*2;
          n |= nk<<4;
        }
        /* block arguments */
        if (tree->cdr->cdr) {
          codegen(s, tree->cdr->cdr, VAL);
        }
        else if (s2) gen_blkmove(s, s2->ainfo, lv);
        else {
          genop_1(s, OP_LOADNIL, cursp());
          push();
        }
      }
      else {
        if (s2) gen_blkmove(s, s2->ainfo, lv);
        else {
          genop_1(s, OP_LOADNIL, cursp());
          push();
        }
      }
      st++;
      pop_n(st+1);
      genop_2(s, OP_SUPER, cursp(), n);
      if (val) push();
    }
    break;

  case NODE_ZSUPER:
    {
      codegen_scope *s2 = s;
      int lv = 0;
      size_t ainfo = 0;
      int n = CALL_MAXARGS;
      int sp = cursp();

      push();        /* room for receiver */
      while (!s2->mscope) {
        lv++;
        s2 = s2->prev;
        if (!s2) break;
      }
      if (s2 && s2->ainfo > 0) {
        ainfo = s2->ainfo;
      }
      if (ainfo > 0) {
        genop_2S(s, OP_ARGARY, cursp(), (ainfo<<4)|(lv & 0xf));
        push(); push(); push();   /* ARGARY pushes 3 values at most */
        pop(); pop(); pop();
        /* keyword arguments */
        if (ainfo & 0x1) {
          n |= CALL_MAXARGS<<4;
          push();
        }
        /* block argument */
        if (tree && tree->cdr && tree->cdr->cdr) {
          push();
          codegen(s, tree->cdr->cdr, VAL);
        }
      }
      else {
        /* block argument */
        if (tree && tree->cdr && tree->cdr->cdr) {
          codegen(s, tree->cdr->cdr, VAL);
        }
        else {
          gen_blkmove(s, 0, lv);
        }
        n = 0;
      }
      s->sp = sp;
      genop_2(s, OP_SUPER, cursp(), n);
      if (val) push();
    }
    break;

  case NODE_RETURN:
    if (tree) {
      gen_retval(s, tree);
    }
    else {
      genop_1(s, OP_LOADNIL, cursp());
    }
    if (s->loop) {
      gen_return(s, OP_RETURN_BLK, cursp());
    }
    else {
      gen_return(s, OP_RETURN, cursp());
    }
    if (val) push();
    break;

  case NODE_YIELD:
    {
      codegen_scope *s2 = s;
      int lv = 0, ainfo = -1;
      int n = 0, sendv = 0;

      while (!s2->mscope) {
        lv++;
        s2 = s2->prev;
        if (!s2) break;
      }
      if (s2) {
        ainfo = (int)s2->ainfo;
      }
      if (ainfo < 0) codegen_error(s, "invalid yield (SyntaxError)");
      push();
      if (tree) {
        n = gen_values(s, tree, VAL, 0, 14);
        if (n < 0) {
          n = sendv = 1;
          push();
        }
      }
      push();pop(); /* space for a block */
      pop_n(n+1);
      genop_2S(s, OP_BLKPUSH, cursp(), (ainfo<<4)|(lv & 0xf));
      if (sendv) n = CALL_MAXARGS;
      genop_3(s, OP_SEND, cursp(), new_sym(s, MRB_SYM_2(s->mrb, call)), n);
      if (val) push();
    }
    break;

  case NODE_BREAK:
    loop_break(s, tree);
    if (val) push();
    break;

  case NODE_NEXT:
    if (!s->loop) {
      raise_error(s, "unexpected next");
    }
    else if (s->loop->type == LOOP_NORMAL) {
      codegen(s, tree, NOVAL);
      genjmp(s, OP_JMPUW, s->loop->pc0);
    }
    else {
      if (tree) {
        codegen(s, tree, VAL);
        pop();
      }
      else {
        genop_1(s, OP_LOADNIL, cursp());
      }
      gen_return(s, OP_RETURN, cursp());
    }
    if (val) push();
    break;

  case NODE_REDO:
    if (!s->loop || s->loop->type == LOOP_BEGIN || s->loop->type == LOOP_RESCUE) {
      raise_error(s, "unexpected redo");
    }
    else {
      genjmp(s, OP_JMPUW, s->loop->pc1);
    }
    if (val) push();
    break;

  case NODE_RETRY:
    {
      const char *msg = "unexpected retry";
      const struct loopinfo *lp = s->loop;

      while (lp && lp->type != LOOP_RESCUE) {
        lp = lp->prev;
      }
      if (!lp) {
        raise_error(s, msg);
      }
      else {
        genjmp(s, OP_JMPUW, lp->pc0);
      }
      if (val) push();
    }
    break;

  case NODE_LVAR:
    if (val) {
      int idx = lv_idx(s, nsym(tree));

      if (idx > 0) {
        gen_move(s, cursp(), idx, val);
      }
      else {
        gen_getupvar(s, cursp(), nsym(tree));
      }
      push();
    }
    break;

  case NODE_NVAR:
    if (val) {
      int idx = nint(tree);

      gen_move(s, cursp(), idx, val);

      push();
    }
    break;

  case NODE_GVAR:
    {
      int sym = new_sym(s, nsym(tree));

      genop_2(s, OP_GETGV, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_IVAR:
    {
      int sym = new_sym(s, nsym(tree));

      genop_2(s, OP_GETIV, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_CVAR:
    {
      int sym = new_sym(s, nsym(tree));

      genop_2(s, OP_GETCV, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_CONST:
    {
      int sym = new_sym(s, nsym(tree));

      genop_2(s, OP_GETCONST, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_BACK_REF:
    if (val) {
      char buf[] = {'$', nchar(tree)};
      int sym = new_sym(s, mrb_intern(s->mrb, buf, sizeof(buf)));

      genop_2(s, OP_GETGV, cursp(), sym);
      push();
    }
    break;

  case NODE_NTH_REF:
    if (val) {
      mrb_state *mrb = s->mrb;
      mrb_value str;
      int sym;

      str = mrb_format(mrb, "$%d", nint(tree));
      sym = new_sym(s, mrb_intern_str(mrb, str));
      genop_2(s, OP_GETGV, cursp(), sym);
      push();
    }
    break;

  case NODE_ARG:
    /* should not happen */
    break;

  case NODE_BLOCK_ARG:
    if (!tree) {
      int idx = lv_idx(s, MRB_OPSYM_2(s->mrb, and));

      if (idx == 0) {
        codegen_error(s, "no anonymous block argument");
      }
      gen_move(s, cursp(), idx, val);
      if (val) push();
    }
    else {
      codegen(s, tree, val);
    }
    break;

  case NODE_INT:
    if (val) {
      char *p = (char*)tree->car;
      int base = nint(tree->cdr->car);
      mrb_int i;
      mrb_bool overflow;

      i = readint(s, p, base, FALSE, &overflow);
      if (overflow) {
        int off = new_litbn(s, p, base, FALSE);
        genop_2(s, OP_LOADL, cursp(), off);
      }
      else {
        gen_int(s, cursp(), i);
      }
      push();
    }
    break;

#ifndef MRB_NO_FLOAT
  case NODE_FLOAT:
    if (val) {
      char *p = (char*)tree;
      mrb_float f = mrb_float_read(p, NULL);
      int off = new_lit(s, mrb_float_value(s->mrb, f));

      genop_2(s, OP_LOADL, cursp(), off);
      push();
    }
    break;
#endif

  case NODE_NEGATE:
    {
      nt = nint(tree->car);
      switch (nt) {
#ifndef MRB_NO_FLOAT
      case NODE_FLOAT:
        if (val) {
          char *p = (char*)tree->cdr;
          mrb_float f = mrb_float_read(p, NULL);
          int off = new_lit(s, mrb_float_value(s->mrb, -f));

          genop_2(s, OP_LOADL, cursp(), off);
          push();
        }
        break;
#endif

      case NODE_INT:
        if (val) {
          char *p = (char*)tree->cdr->car;
          int base = nint(tree->cdr->cdr->car);
          mrb_int i;
          mrb_bool overflow;

          i = readint(s, p, base, TRUE, &overflow);
          if (overflow) {
            int off = new_litbn(s, p, base, TRUE);
            genop_2(s, OP_LOADL, cursp(), off);
          }
          else {
            gen_int(s, cursp(), i);
          }
          push();
        }
        break;

      default:
        if (val) {
          codegen(s, tree, VAL);
          pop();
          push_n(2);pop_n(2); /* space for receiver&block */
          mrb_sym minus = MRB_OPSYM_2(s->mrb, minus);
          if (!gen_uniop(s, minus, cursp())) {
            genop_3(s, OP_SEND, cursp(), new_sym(s, minus), 0);
          }
          push();
        }
        else {
          codegen(s, tree, NOVAL);
        }
        break;
      }
    }
    break;

  case NODE_STR:
    if (val) {
      char *p = (char*)tree->car;
      size_t len = (intptr_t)tree->cdr;
      int ai = mrb_gc_arena_save(s->mrb);
      int off = new_lit(s, mrb_str_new(s->mrb, p, len));

      mrb_gc_arena_restore(s->mrb, ai);
      genop_2(s, OP_STRING, cursp(), off);
      push();
    }
    break;

  case NODE_HEREDOC:
    tree = ((struct mrb_parser_heredoc_info *)tree)->doc;
    /* fall through */
  case NODE_DSTR:
    if (val) {
      node *n = tree;

      if (!n) {
        genop_1(s, OP_LOADNIL, cursp());
        push();
        break;
      }
      codegen(s, n->car, VAL);
      n = n->cdr;
      while (n) {
        codegen(s, n->car, VAL);
        pop(); pop();
        genop_1(s, OP_STRCAT, cursp());
        push();
        n = n->cdr;
      }
    }
    else {
      node *n = tree;

      while (n) {
        if (nint(n->car->car) != NODE_STR) {
          codegen(s, n->car, NOVAL);
        }
        n = n->cdr;
      }
    }
    break;

  case NODE_WORDS:
    gen_literal_array(s, tree, FALSE, val);
    break;

  case NODE_SYMBOLS:
    gen_literal_array(s, tree, TRUE, val);
    break;

  case NODE_DXSTR:
    {
      node *n;
      int ai = mrb_gc_arena_save(s->mrb);
      int sym = new_sym(s, MRB_SYM_2(s->mrb, Kernel));

      genop_1(s, OP_LOADSELF, cursp());
      push();
      codegen(s, tree->car, VAL);
      n = tree->cdr;
      while (n) {
        if (nint(n->car->car) == NODE_XSTR) {
          n->car->car = (struct mrb_ast_node*)(intptr_t)NODE_STR;
          mrb_assert(!n->cdr); /* must be the end */
        }
        codegen(s, n->car, VAL);
        pop(); pop();
        genop_1(s, OP_STRCAT, cursp());
        push();
        n = n->cdr;
      }
      push();                   /* for block */
      pop_n(3);
      sym = new_sym(s, MRB_OPSYM_2(s->mrb, tick)); /* ` */
      genop_3(s, OP_SEND, cursp(), sym, 1);
      if (val) push();
      mrb_gc_arena_restore(s->mrb, ai);
    }
    break;

  case NODE_XSTR:
    {
      char *p = (char*)tree->car;
      size_t len = (intptr_t)tree->cdr;
      int ai = mrb_gc_arena_save(s->mrb);
      int off = new_lit(s, mrb_str_new(s->mrb, p, len));
      int sym;

      genop_1(s, OP_LOADSELF, cursp());
      push();
      genop_2(s, OP_STRING, cursp(), off);
      push(); push();
      pop_n(3);
      sym = new_sym(s, MRB_OPSYM_2(s->mrb, tick)); /* ` */
      genop_3(s, OP_SEND, cursp(), sym, 1);
      if (val) push();
      mrb_gc_arena_restore(s->mrb, ai);
    }
    break;

  case NODE_REGX:
    if (val) {
      char *p1 = (char*)tree->car;
      char *p2 = (char*)tree->cdr->car;
      char *p3 = (char*)tree->cdr->cdr;
      int ai = mrb_gc_arena_save(s->mrb);
      int sym = new_sym(s, mrb_intern_lit(s->mrb, REGEXP_CLASS));
      int off = new_lit(s, mrb_str_new_cstr(s->mrb, p1));
      int argc = 1;

      genop_1(s, OP_OCLASS, cursp());
      genop_2(s, OP_GETMCNST, cursp(), sym);
      push();
      genop_2(s, OP_STRING, cursp(), off);
      push();
      if (p2 || p3) {
        if (p2) { /* opt */
          off = new_lit(s, mrb_str_new_cstr(s->mrb, p2));
          genop_2(s, OP_STRING, cursp(), off);
        }
        else {
          genop_1(s, OP_LOADNIL, cursp());
        }
        push();
        argc++;
        if (p3) { /* enc */
          off = new_lit(s, mrb_str_new(s->mrb, p3, 1));
          genop_2(s, OP_STRING, cursp(), off);
          push();
          argc++;
        }
      }
      push(); /* space for a block */
      pop_n(argc+2);
      sym = new_sym(s, MRB_SYM_2(s->mrb, compile));
      genop_3(s, OP_SEND, cursp(), sym, argc);
      mrb_gc_arena_restore(s->mrb, ai);
      push();
    }
    break;

  case NODE_DREGX:
    if (val) {
      node *n = tree->car;
      int ai = mrb_gc_arena_save(s->mrb);
      int sym = new_sym(s, mrb_intern_lit(s->mrb, REGEXP_CLASS));
      int argc = 1;
      int off;
      char *p;

      genop_1(s, OP_OCLASS, cursp());
      genop_2(s, OP_GETMCNST, cursp(), sym);
      push();
      codegen(s, n->car, VAL);
      n = n->cdr;
      while (n) {
        codegen(s, n->car, VAL);
        pop(); pop();
        genop_1(s, OP_STRCAT, cursp());
        push();
        n = n->cdr;
      }
      n = tree->cdr->cdr;
      if (n->car) { /* tail */
        p = (char*)n->car;
        off = new_lit(s, mrb_str_new_cstr(s->mrb, p));
        codegen(s, tree->car, VAL);
        genop_2(s, OP_STRING, cursp(), off);
        pop();
        genop_1(s, OP_STRCAT, cursp());
        push();
      }
      if (n->cdr->car) { /* opt */
        char *p2 = (char*)n->cdr->car;
        off = new_lit(s, mrb_str_new_cstr(s->mrb, p2));
        genop_2(s, OP_STRING, cursp(), off);
        push();
        argc++;
      }
      if (n->cdr->cdr) { /* enc */
        char *p2 = (char*)n->cdr->cdr;
        off = new_lit(s, mrb_str_new_cstr(s->mrb, p2));
        genop_2(s, OP_STRING, cursp(), off);
        push();
        argc++;
      }
      push(); /* space for a block */
      pop_n(argc+2);
      sym = new_sym(s, MRB_SYM_2(s->mrb, compile));
      genop_3(s, OP_SEND, cursp(), sym, argc);
      mrb_gc_arena_restore(s->mrb, ai);
      push();
    }
    else {
      node *n = tree->car;

      while (n) {
        if (nint(n->car->car) != NODE_STR) {
          codegen(s, n->car, NOVAL);
        }
        n = n->cdr;
      }
    }
    break;

  case NODE_SYM:
    if (val) {
      int sym = new_sym(s, nsym(tree));

      genop_2(s, OP_LOADSYM, cursp(), sym);
      push();
    }
    break;

  case NODE_DSYM:
    codegen(s, tree, val);
    if (val) {
      gen_intern(s);
    }
    break;

  case NODE_SELF:
    if (val) {
      genop_1(s, OP_LOADSELF, cursp());
      push();
    }
    break;

  case NODE_NIL:
    if (val) {
      genop_1(s, OP_LOADNIL, cursp());
      push();
    }
    break;

  case NODE_TRUE:
    if (val) {
      genop_1(s, OP_LOADT, cursp());
      push();
    }
    break;

  case NODE_FALSE:
    if (val) {
      genop_1(s, OP_LOADF, cursp());
      push();
    }
    break;

  case NODE_ALIAS:
    {
      int a = new_sym(s, nsym(tree->car));
      int b = new_sym(s, nsym(tree->cdr));

      genop_2(s, OP_ALIAS, a, b);
      if (val) {
        genop_1(s, OP_LOADNIL, cursp());
        push();
      }
    }
   break;

  case NODE_UNDEF:
    {
      node *t = tree;

      while (t) {
        int symbol = new_sym(s, nsym(t->car));
        genop_1(s, OP_UNDEF, symbol);
        t = t->cdr;
      }
      if (val) {
        genop_1(s, OP_LOADNIL, cursp());
        push();
      }
    }
    break;

  case NODE_CLASS:
    {
      int idx;
      node *body;

      if (tree->car->car == (node*)0) {
        genop_1(s, OP_LOADNIL, cursp());
        push();
      }
      else if (tree->car->car == (node*)1) {
        genop_1(s, OP_OCLASS, cursp());
        push();
      }
      else {
        codegen(s, tree->car->car, VAL);
      }
      if (tree->cdr->car) {
        codegen(s, tree->cdr->car, VAL);
      }
      else {
        genop_1(s, OP_LOADNIL, cursp());
        push();
      }
      pop(); pop();
      idx = new_sym(s, nsym(tree->car->cdr));
      genop_2(s, OP_CLASS, cursp(), idx);
      body = tree->cdr->cdr->car;
      if (nint(body->cdr->car) == NODE_BEGIN && body->cdr->cdr == NULL) {
        genop_1(s, OP_LOADNIL, cursp());
      }
      else {
        idx = scope_body(s, body, val);
        genop_2(s, OP_EXEC, cursp(), idx);
      }
      if (val) {
        push();
      }
    }
    break;

  case NODE_MODULE:
    {
      int idx;

      if (tree->car->car == (node*)0) {
        genop_1(s, OP_LOADNIL, cursp());
        push();
      }
      else if (tree->car->car == (node*)1) {
        genop_1(s, OP_OCLASS, cursp());
        push();
      }
      else {
        codegen(s, tree->car->car, VAL);
      }
      pop();
      idx = new_sym(s, nsym(tree->car->cdr));
      genop_2(s, OP_MODULE, cursp(), idx);
      if (nint(tree->cdr->car->cdr->car) == NODE_BEGIN &&
          tree->cdr->car->cdr->cdr == NULL) {
        genop_1(s, OP_LOADNIL, cursp());
      }
      else {
        idx = scope_body(s, tree->cdr->car, val);
        genop_2(s, OP_EXEC, cursp(), idx);
      }
      if (val) {
        push();
      }
    }
    break;

  case NODE_SCLASS:
    {
      int idx;

      codegen(s, tree->car, VAL);
      pop();
      genop_1(s, OP_SCLASS, cursp());
      if (nint(tree->cdr->car->cdr->car) == NODE_BEGIN &&
          tree->cdr->car->cdr->cdr == NULL) {
        genop_1(s, OP_LOADNIL, cursp());
      }
      else {
        idx = scope_body(s, tree->cdr->car, val);
        genop_2(s, OP_EXEC, cursp(), idx);
      }
      if (val) {
        push();
      }
    }
    break;

  case NODE_DEF:
    {
      int sym = new_sym(s, nsym(tree->car));
      int idx = lambda_body(s, tree->cdr, 0);

      genop_1(s, OP_TCLASS, cursp());
      push();
      genop_2(s, OP_METHOD, cursp(), idx);
      push(); pop();
      pop();
      genop_2(s, OP_DEF, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_SDEF:
    {
      node *recv = tree->car;
      int sym = new_sym(s, nsym(tree->cdr->car));
      int idx = lambda_body(s, tree->cdr->cdr, 0);

      codegen(s, recv, VAL);
      pop();
      genop_1(s, OP_SCLASS, cursp());
      push();
      genop_2(s, OP_METHOD, cursp(), idx);
      pop();
      genop_2(s, OP_DEF, cursp(), sym);
      if (val) push();
    }
    break;

  case NODE_POSTEXE:
    codegen(s, tree, NOVAL);
    break;

  default:
    break;
  }
 exit:
  s->rlev = rlev;
}

static void
scope_add_irep(codegen_scope *s)
{
  mrb_irep *irep;
  codegen_scope *prev = s->prev;

  if (prev->irep == NULL) {
    irep = mrb_add_irep(s->mrb);
    prev->irep = s->irep = irep;
    return;
  }
  else {
    if (prev->irep->rlen == UINT16_MAX) {
      codegen_error(s, "too many nested blocks/methods");
    }
    s->irep = irep = mrb_add_irep(s->mrb);
    if (prev->irep->rlen == prev->rcapa) {
      prev->rcapa *= 2;
      prev->reps = (mrb_irep**)codegen_realloc(s, prev->reps, sizeof(mrb_irep*)*prev->rcapa);
    }
    prev->reps[prev->irep->rlen] = irep;
    prev->irep->rlen++;
  }
}

static codegen_scope*
scope_new(mrb_state *mrb, codegen_scope *prev, node *nlv)
{
  static const codegen_scope codegen_scope_zero = { 0 };
  mrb_pool *pool = mrb_pool_open(mrb);
  codegen_scope *s = (codegen_scope *)mrb_pool_alloc(pool, sizeof(codegen_scope));

  if (!s) {
    if (prev)
      codegen_error(prev, "unexpected scope");
    return NULL;
  }
  *s = codegen_scope_zero;
  s->mrb = mrb;
  s->mpool = pool;
  if (!prev) return s;
  s->prev = prev;
  s->ainfo = 0;
  s->mscope = 0;

  scope_add_irep(s);

  s->rcapa = 8;
  s->reps = (mrb_irep**)mrb_malloc(mrb, sizeof(mrb_irep*)*s->rcapa);

  s->icapa = 1024;
  s->iseq = (mrb_code*)mrb_malloc(mrb, sizeof(mrb_code)*s->icapa);

  s->pcapa = 32;
  s->pool = (mrb_pool_value*)mrb_malloc(mrb, sizeof(mrb_pool_value)*s->pcapa);

  s->scapa = 256;
  s->syms = (mrb_sym*)mrb_malloc(mrb, sizeof(mrb_sym)*s->scapa);

  s->lv = nlv;
  s->sp += node_len(nlv)+1;        /* add self */
  s->nlocals = s->sp;
  if (nlv) {
    mrb_sym *lv;
    node *n = nlv;
    size_t i = 0;

    s->irep->lv = lv = (mrb_sym*)mrb_malloc(mrb, sizeof(mrb_sym)*(s->nlocals-1));
    for (i=0, n=nlv; n; i++,n=n->cdr) {
      lv[i] = lv_name(n);
    }
    mrb_assert(i + 1 == s->nlocals);
  }
  s->ai = mrb_gc_arena_save(mrb);

  s->filename_sym = prev->filename_sym;
  if (s->filename_sym) {
    s->lines = (uint16_t*)mrb_malloc(mrb, sizeof(short)*s->icapa);
  }
  s->lineno = prev->lineno;

  /* debug setting */
  s->debug_start_pos = 0;
  if (s->filename_sym) {
    mrb_debug_info_alloc(mrb, s->irep);
  }
  else {
    s->irep->debug_info = NULL;
  }
  s->parser = prev->parser;
  s->filename_index = prev->filename_index;

  s->rlev = prev->rlev+1;

  return s;
}

static void
scope_finish(codegen_scope *s)
{
  mrb_state *mrb = s->mrb;
  mrb_irep *irep = s->irep;

  if (s->nlocals > 0xff) {
    codegen_error(s, "too many local variables");
  }
  irep->flags = 0;
  if (s->iseq) {
    size_t catchsize = sizeof(struct mrb_irep_catch_handler) * irep->clen;
    irep->iseq = (const mrb_code *)codegen_realloc(s, s->iseq, sizeof(mrb_code)*s->pc + catchsize);
    irep->ilen = s->pc;
    if (irep->clen > 0) {
      memcpy((void *)(irep->iseq + irep->ilen), s->catch_table, catchsize);
    }
  }
  else {
    irep->clen = 0;
  }
  mrb_free(s->mrb, s->catch_table);
  s->catch_table = NULL;
  irep->pool = (const mrb_pool_value*)codegen_realloc(s, s->pool, sizeof(mrb_pool_value)*irep->plen);
  irep->syms = (const mrb_sym*)codegen_realloc(s, s->syms, sizeof(mrb_sym)*irep->slen);
  irep->reps = (const mrb_irep**)codegen_realloc(s, s->reps, sizeof(mrb_irep*)*irep->rlen);
  if (s->filename_sym) {
    mrb_sym fname = mrb_parser_get_filename(s->parser, s->filename_index);
    const char *filename = mrb_sym_name_len(s->mrb, fname, NULL);

    mrb_debug_info_append_file(s->mrb, s->irep->debug_info,
                               filename, s->lines, s->debug_start_pos, s->pc);
  }
  mrb_free(s->mrb, s->lines);

  irep->nlocals = s->nlocals;
  irep->nregs = s->nregs;

  mrb_gc_arena_restore(mrb, s->ai);
  mrb_pool_close(s->mpool);
}

static struct loopinfo*
loop_push(codegen_scope *s, enum looptype t)
{
  struct loopinfo *p = (struct loopinfo *)codegen_palloc(s, sizeof(struct loopinfo));

  p->type = t;
  p->pc0 = p->pc1 = p->pc2 = JMPLINK_START;
  p->prev = s->loop;
  p->reg = cursp();
  s->loop = p;

  return p;
}

static void
loop_break(codegen_scope *s, node *tree)
{
  if (!s->loop) {
    codegen(s, tree, NOVAL);
    raise_error(s, "unexpected break");
  }
  else {
    struct loopinfo *loop;


    loop = s->loop;
    if (tree) {
      if (loop->reg < 0) {
        codegen(s, tree, NOVAL);
      }
      else {
        gen_retval(s, tree);
      }
    }
    while (loop) {
      if (loop->type == LOOP_BEGIN) {
        loop = loop->prev;
      }
      else if (loop->type == LOOP_RESCUE) {
        loop = loop->prev;
      }
      else{
        break;
      }
    }
    if (!loop) {
      raise_error(s, "unexpected break");
      return;
    }

    if (loop->type == LOOP_NORMAL) {
      int tmp;

      if (loop->reg >= 0) {
        if (tree) {
          gen_move(s, loop->reg, cursp(), 0);
        }
        else {
          genop_1(s, OP_LOADNIL, loop->reg);
        }
      }
      tmp = genjmp(s, OP_JMPUW, loop->pc2);
      loop->pc2 = tmp;
    }
    else {
      if (!tree) {
        genop_1(s, OP_LOADNIL, cursp());
      }
      gen_return(s, OP_BREAK, cursp());
    }
  }
}

static void
loop_pop(codegen_scope *s, int val)
{
  if (val) {
    genop_1(s, OP_LOADNIL, cursp());
  }
  dispatch_linked(s, s->loop->pc2);
  s->loop = s->loop->prev;
  if (val) push();
}

static int
catch_handler_new(codegen_scope *s)
{
  size_t newsize = sizeof(struct mrb_irep_catch_handler) * (s->irep->clen + 1);
  s->catch_table = (struct mrb_irep_catch_handler *)codegen_realloc(s, (void *)s->catch_table, newsize);
  return s->irep->clen ++;
}

static void
catch_handler_set(codegen_scope *s, int ent, enum mrb_catch_type type, uint32_t begin, uint32_t end, uint32_t target)
{
  struct mrb_irep_catch_handler *e;

  mrb_assert(ent >= 0 && ent < s->irep->clen);

  e = &s->catch_table[ent];
  uint8_to_bin(type, &e->type);
  mrb_irep_catch_handler_pack(begin, e->begin);
  mrb_irep_catch_handler_pack(end, e->end);
  mrb_irep_catch_handler_pack(target, e->target);
}

static struct RProc*
generate_code(mrb_state *mrb, parser_state *p, int val)
{
  codegen_scope *scope = scope_new(mrb, 0, 0);
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf jmpbuf;
  struct RProc *proc;

  mrb->jmp = &jmpbuf;

  scope->mrb = mrb;
  scope->parser = p;
  scope->filename_sym = p->filename_sym;
  scope->filename_index = p->current_filename_index;

  MRB_TRY(mrb->jmp) {
    /* prepare irep */
    codegen(scope, p->tree, val);
    proc = mrb_proc_new(mrb, scope->irep);
    mrb_irep_decref(mrb, scope->irep);
    mrb_pool_close(scope->mpool);
    proc->c = NULL;
    if (mrb->c->cibase && mrb->c->cibase->proc == proc->upper) {
      proc->upper = NULL;
    }
    mrb->jmp = prev_jmp;
    return proc;
  }
  MRB_CATCH(mrb->jmp) {
    mrb_irep_decref(mrb, scope->irep);
    mrb_pool_close(scope->mpool);
    mrb->jmp = prev_jmp;
    return NULL;
  }
  MRB_END_EXC(mrb->jmp);
}

MRB_API struct RProc*
mrb_generate_code(mrb_state *mrb, parser_state *p)
{
  return generate_code(mrb, p, VAL);
}

void
mrb_irep_remove_lv(mrb_state *mrb, mrb_irep *irep)
{
  int i;

  if (irep->flags & MRB_IREP_NO_FREE) return;
  if (irep->lv) {
    mrb_free(mrb, (void*)irep->lv);
    irep->lv = NULL;
  }
  if (!irep->reps) return;
  for (i = 0; i < irep->rlen; ++i) {
    mrb_irep_remove_lv(mrb, (mrb_irep*)irep->reps[i]);
  }
}
