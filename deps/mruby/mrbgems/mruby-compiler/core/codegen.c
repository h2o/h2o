/*
** codegen.c - mruby code generator
**
** See Copyright Notice in mruby.h
*/

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/proc.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/debug.h>
#include "node.h"
#include <mruby/opcode.h>
#include <mruby/re.h>
#include <mruby/throw.h>

#ifndef MRB_CODEGEN_LEVEL_MAX
#define MRB_CODEGEN_LEVEL_MAX 1024
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
  int pc0, pc1, pc2, pc3, acc;
  int ensure_level;
  struct loopinfo *prev;
};

typedef struct scope {
  mrb_state *mrb;
  mrb_pool *mpool;
  struct mrb_jmpbuf jmp;

  struct scope *prev;

  node *lv;

  uint16_t sp;
  uint16_t pc;
  uint16_t lastpc;
  uint16_t lastlabel;
  int ainfo:15;
  mrb_bool mscope:1;

  struct loopinfo *loop;
  int ensure_level;
  mrb_sym filename_sym;
  uint16_t lineno;

  mrb_code *iseq;
  uint16_t *lines;
  uint32_t icapa;

  mrb_irep *irep;
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

static void gen_assignment(codegen_scope *s, node *tree, int sp, int val);
static void gen_vmassignment(codegen_scope *s, node *tree, int rhs, int val);

static void codegen(codegen_scope *s, node *tree, int val);
static void raise_error(codegen_scope *s, const char *msg);

static void
codegen_error(codegen_scope *s, const char *message)
{
  if (!s) return;
  while (s->prev) {
    codegen_scope *tmp = s->prev;
    mrb_free(s->mrb, s->iseq);
    mrb_free(s->mrb, s->lines);
    mrb_pool_close(s->mpool);
    s = tmp;
  }
#ifndef MRB_DISABLE_STDIO
  if (s->filename_sym && s->lineno) {
    const char *filename = mrb_sym_name_len(s->mrb, s->filename_sym, NULL);
    fprintf(stderr, "codegen error:%s:%d: %s\n", filename, s->lineno, message);
  }
  else {
    fprintf(stderr, "codegen error: %s\n", message);
  }
#endif
  MRB_THROW(&s->jmp);
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

static int
new_label(codegen_scope *s)
{
  return s->lastlabel = s->pc;
}

static void
emit_B(codegen_scope *s, uint32_t pc, uint8_t i)
{
  if (pc >= MAXARG_S || s->icapa >= MAXARG_S) {
    codegen_error(s, "too big code block");
  }
  if (pc >= s->icapa) {
    s->icapa *= 2;
    if (s->icapa > MAXARG_S) {
      s->icapa = MAXARG_S;
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
  mrb_code insn = READ_B();
  uint16_t a = 0;
  uint16_t b = 0;
  uint8_t  c = 0;

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

static struct mrb_insn_data
mrb_last_insn(codegen_scope *s)
{
  if (s->pc == s->lastpc) {
    struct mrb_insn_data data;

    data.insn = OP_NOP;
    return data;
  }
  return mrb_decode_insn(&s->iseq[s->lastpc]);
}

static mrb_bool
no_peephole(codegen_scope *s)
{
  return no_optimize(s) || s->lastlabel == s->pc || s->pc == 0 || s->pc == s->lastpc;
}

static uint16_t
genjmp(codegen_scope *s, mrb_code i, uint16_t pc)
{
  uint16_t pos;

  s->lastpc = s->pc;
  gen_B(s, i);
  pos = s->pc;
  gen_S(s, pc);
  return pos;
}

static uint16_t
genjmp2(codegen_scope *s, mrb_code i, uint16_t a, int pc, int val)
{
  uint16_t pos;

  if (!no_peephole(s) && !val) {
    struct mrb_insn_data data = mrb_last_insn(s);

    if (data.insn == OP_MOVE && data.a == a) {
      s->pc = s->lastpc;
      a = data.b;
    }
  }

  s->lastpc = s->pc;
  if (a > 0xff) {
    gen_B(s, OP_EXT1);
    gen_B(s, i);
    gen_S(s, a);
    pos = s->pc;
    gen_S(s, pc);
  }
  else {
    gen_B(s, i);
    gen_B(s, (uint8_t)a);
    pos = s->pc;
    gen_S(s, pc);
  }
  return pos;
}

static void
gen_move(codegen_scope *s, uint16_t dst, uint16_t src, int nopeep)
{
  if (no_peephole(s)) {
  normal:
    genop_2(s, OP_MOVE, dst, src);
    return;
  }
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
      if (nopeep || data.a != src || data.a < s->nlocals) goto normal;
      s->pc = s->lastpc;
      genop_1(s, data.insn, dst);
      break;
    case OP_LOADI: case OP_LOADINEG: case OP_LOADL: case OP_LOADSYM:
    case OP_GETGV: case OP_GETSV: case OP_GETIV: case OP_GETCV:
    case OP_GETCONST: case OP_STRING:
    case OP_LAMBDA: case OP_BLOCK: case OP_METHOD: case OP_BLKPUSH:
      if (nopeep || data.a != src || data.a < s->nlocals) goto normal;
      s->pc = s->lastpc;
      genop_2(s, data.insn, dst, data.b);
      break;
    default:
      goto normal;
    }
  }
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
      s->pc = s->lastpc;
      genop_1(s, op, data.b);
    }
    else if (data.insn != OP_RETURN) {
      genop_1(s, op, src);
    }
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

    switch (data.insn) {
    case OP_LOADI__1:
      if (op == OP_ADD) op = OP_SUB;
      else op = OP_ADD;
      data.b = 1;
      goto replace;
    case OP_LOADI_0: case OP_LOADI_1: case OP_LOADI_2: case OP_LOADI_3:
    case OP_LOADI_4: case OP_LOADI_5: case OP_LOADI_6: case OP_LOADI_7:
      data.b = data.insn - OP_LOADI_0;
      /* fall through */
    case OP_LOADI:
    replace:
      if (data.b >= 128) goto normal;
      s->pc = s->lastpc;
      if (op == OP_ADD) {
        genop_2(s, OP_ADDI, dst, (uint8_t)data.b);
      }
      else {
        genop_2(s, OP_SUBI, dst, (uint8_t)data.b);
      }
      break;
    default:
      goto normal;
    }
  }
}

static int
dispatch(codegen_scope *s, uint16_t pos0)
{
  uint16_t newpos;

  s->lastlabel = s->pc;
  newpos = PEEK_S(s->iseq+pos0);
  emit_S(s, pos0, s->pc);
  return newpos;
}

static void
dispatch_linked(codegen_scope *s, uint16_t pos)
{
  if (pos==0) return;
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

static inline int
new_lit(codegen_scope *s, mrb_value val)
{
  int i;
  mrb_value *pv;

  switch (mrb_type(val)) {
  case MRB_TT_STRING:
    for (i=0; i<s->irep->plen; i++) {
      mrb_int len;
      pv = &s->irep->pool[i];

      if (!mrb_string_p(*pv)) continue;
      if ((len = RSTRING_LEN(*pv)) != RSTRING_LEN(val)) continue;
      if (memcmp(RSTRING_PTR(*pv), RSTRING_PTR(val), len) == 0)
        return i;
    }
    break;
#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
    for (i=0; i<s->irep->plen; i++) {
      mrb_float f1, f2;
      pv = &s->irep->pool[i];
      if (!mrb_float_p(*pv)) continue;
      f1 = mrb_float(*pv);
      f2 = mrb_float(val);
      if (f1 == f2 && !signbit(f1) == !signbit(f2)) return i;
    }
    break;
#endif
  case MRB_TT_FIXNUM:
    for (i=0; i<s->irep->plen; i++) {
      pv = &s->irep->pool[i];
      if (!mrb_fixnum_p(*pv)) continue;
      if (mrb_fixnum(*pv) == mrb_fixnum(val)) return i;
    }
    break;
  default:
    /* should not happen */
    return 0;
  }

  if (s->irep->plen == s->pcapa) {
    s->pcapa *= 2;
    s->irep->pool = (mrb_value *)codegen_realloc(s, s->irep->pool, sizeof(mrb_value)*s->pcapa);
  }

  pv = &s->irep->pool[s->irep->plen];
  i = s->irep->plen++;

  switch (mrb_type(val)) {
  case MRB_TT_STRING:
    *pv = mrb_str_pool(s->mrb, RSTRING_PTR(val), RSTRING_LEN(val), RSTR_NOFREE_P(RSTRING(val)));
    break;

#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
#ifdef MRB_WORD_BOXING
    *pv = mrb_float_pool(s->mrb, mrb_float(val));
    break;
#endif
#endif
  case MRB_TT_FIXNUM:
    *pv = val;
    break;

  default:
    /* should not happen */
    break;
  }
  return i;
}

/* maximum symbol numbers */
#define MAXSYMLEN 0x10000

static int
new_sym(codegen_scope *s, mrb_sym sym)
{
  int i, len;

  mrb_assert(s->irep);

  len = s->irep->slen;
  for (i=0; i<len; i++) {
    if (s->irep->syms[i] == sym) return i;
  }
  if (s->irep->slen >= s->scapa) {
    s->scapa *= 2;
    s->irep->syms = (mrb_sym*)codegen_realloc(s, s->irep->syms, sizeof(mrb_sym)*s->scapa);
  }
  s->irep->syms[s->irep->slen] = sym;
  return s->irep->slen++;
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
  struct RProc *u;
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
    struct mrb_irep *ir = u->body.irep;
    uint_fast16_t n = ir->nlocals;
    const struct mrb_locals *v = ir->lv;
    for (; n > 1; n --, v ++) {
      if (v->name == id) {
        *idx = v->r;
        return lv - 1;
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
  lp->pc2 = new_label(s);

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
  idx = new_sym(s, mrb_intern_lit(s->mrb, "each"));
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
  }
  else {
    mrb_aspec a;
    int ma, oa, ra, pa, ka, kd, ba;
    int pos, i;
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
    /* mandatory arugments after rest argument */
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
    a = MRB_ARGS_REQ(ma)
      | MRB_ARGS_OPT(oa)
      | (ra? MRB_ARGS_REST() : 0)
      | MRB_ARGS_POST(pa)
      | MRB_ARGS_KEY(ka, kd)
      | (ba? MRB_ARGS_BLOCK() : 0);
    s->ainfo = (((ma+oa) & 0x3f) << 7) /* (12bits = 5:1:5:1) */
      | ((ra & 0x1) << 6)
      | ((pa & 0x1f) << 1)
      | ((ka | kd) != 0 ? 0x01 : 0x00);
    genop_W(s, OP_ENTER, a);
    /* generate jump table for optional arguments initializer */
    pos = new_label(s);
    for (i=0; i<oa; i++) {
      new_label(s);
      genjmp(s, OP_JMP, 0);
    }
    if (oa > 0) {
      genjmp(s, OP_JMP, 0);
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
        int lv = search_upvar(s, id, &idx);
        genop_3(s, OP_GETUPVAR, cursp(), idx, lv);
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
          jmpif_key_p = genjmp2(s, OP_JMPIF, lv_idx(s, kwd_sym), 0, 0);
          codegen(s, def_arg, VAL);
          pop();
          idx = lv_idx(s, kwd_sym);
          if (idx > 0) {
            gen_move(s, idx, cursp(), 0);
          }
          else {
            int lv = search_upvar(s, kwd_sym, &idx);
            genop_3(s, OP_GETUPVAR, cursp(), idx, lv);
          }
          jmp_def_set = genjmp(s, OP_JMP, 0);
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
      node *n = margs;

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

#define CALL_MAXARGS 127

static int
gen_values(codegen_scope *s, node *t, int val, int extra)
{
  int n = 0;
  int is_splat;

  while (t) {
    is_splat = nint(t->car->car) == NODE_SPLAT; /* splat mode */
    if (
      n+extra >= CALL_MAXARGS - 1 /* need to subtract one because vm.c expects an array if n == CALL_MAXARGS */
      || is_splat) {
      if (val) {
        if (is_splat && n == 0 && nint(t->car->cdr->car) == NODE_ARRAY) {
          codegen(s, t->car->cdr, VAL);
          pop();
        }
        else {
          pop_n(n);
          if (n == 0 && is_splat) {
            genop_1(s, OP_LOADNIL, cursp());
          }
          else {
            genop_2(s, OP_ARRAY, cursp(), n);
          }
          push();
          codegen(s, t->car, VAL);
          pop(); pop();
          if (is_splat) {
            genop_1(s, OP_ARYCAT, cursp());
          }
          else {
            genop_1(s, OP_ARYPUSH, cursp());
          }
        }
        t = t->cdr;
        while (t) {
          push();
          codegen(s, t->car, VAL);
          pop(); pop();
          if (nint(t->car->car) == NODE_SPLAT) {
            genop_1(s, OP_ARYCAT, cursp());
          }
          else {
            genop_1(s, OP_ARYPUSH, cursp());
          }
          t = t->cdr;
        }
      }
      else {
        while (t) {
          codegen(s, t->car, NOVAL);
          t = t->cdr;
        }
      }
      return -1;
    }
    /* normal (no splat) mode */
    codegen(s, t->car, val);
    n++;
    t = t->cdr;
  }
  return n;
}

static void
gen_call(codegen_scope *s, node *tree, mrb_sym name, int sp, int val, int safe)
{
  mrb_sym sym = name ? name : nsym(tree->cdr->car);
  int skip = 0;
  int n = 0, noop = 0, sendv = 0, blk = 0;

  codegen(s, tree->car, VAL); /* receiver */
  if (safe) {
    int recv = cursp()-1;
    gen_move(s, cursp(), recv, 1);
    skip = genjmp2(s, OP_JMPNIL, cursp(), 0, val);
  }
  tree = tree->cdr->cdr->car;
  if (tree) {
    n = gen_values(s, tree->car, VAL, sp?1:0);
    if (n < 0) {
      n = noop = sendv = 1;
      push();
    }
  }
  if (sp) {                     /* last argument pushed (attr=) */
    if (sendv) {
      gen_move(s, cursp(), sp, 0);
      pop();
      genop_1(s, OP_ARYPUSH, cursp());
      push();
    }
    else {
      gen_move(s, cursp(), sp, 0);
      push();
      n++;
    }
  }
  if (tree && tree->cdr) {
    noop = 1;
    codegen(s, tree->cdr, VAL);
    pop();
    blk = 1;
  }
  push();pop();
  pop_n(n+1);
  {
    mrb_int symlen;
    const char *symname = mrb_sym_name_len(s->mrb, sym, &symlen);

    if (!noop && symlen == 1 && symname[0] == '+' && n == 1)  {
      gen_addsub(s, OP_ADD, cursp());
    }
    else if (!noop && symlen == 1 && symname[0] == '-' && n == 1)  {
      gen_addsub(s, OP_SUB, cursp());
    }
    else if (!noop && symlen == 1 && symname[0] == '*' && n == 1)  {
      genop_1(s, OP_MUL, cursp());
    }
    else if (!noop && symlen == 1 && symname[0] == '/' && n == 1)  {
      genop_1(s, OP_DIV, cursp());
    }
    else if (!noop && symlen == 1 && symname[0] == '<' && n == 1)  {
      genop_1(s, OP_LT, cursp());
    }
    else if (!noop && symlen == 2 && symname[0] == '<' && symname[1] == '=' && n == 1)  {
      genop_1(s, OP_LE, cursp());
    }
    else if (!noop && symlen == 1 && symname[0] == '>' && n == 1)  {
      genop_1(s, OP_GT, cursp());
    }
    else if (!noop && symlen == 2 && symname[0] == '>' && symname[1] == '=' && n == 1)  {
      genop_1(s, OP_GE, cursp());
    }
    else if (!noop && symlen == 2 && symname[0] == '=' && symname[1] == '=' && n == 1)  {
      genop_1(s, OP_EQ, cursp());
    }
    else {
      int idx = new_sym(s, sym);

      if (sendv) {
        genop_2(s, blk ? OP_SENDVB : OP_SENDV, cursp(), idx);
      }
      else {
        genop_3(s, blk ? OP_SENDB : OP_SEND, cursp(), idx, n);
      }
    }
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
    idx = new_sym(s, nsym(tree));
    genop_2(s, OP_SETGV, sp, idx);
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
      int lv = search_upvar(s, nsym(tree), &idx);
      genop_3(s, OP_SETUPVAR, sp, idx, lv);
    }
    break;
  case NODE_NVAR:
    idx = nint(tree);
    codegen_error(s, "Can't assign to numbered parameter");
    break;
  case NODE_IVAR:
    idx = new_sym(s, nsym(tree));
    genop_2(s, OP_SETIV, sp, idx);
    break;
  case NODE_CVAR:
    idx = new_sym(s, nsym(tree));
    genop_2(s, OP_SETCV, sp, idx);
    break;
  case NODE_CONST:
    idx = new_sym(s, nsym(tree));
    genop_2(s, OP_SETCONST, sp, idx);
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
    if (val) {
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
#ifndef MRB_DISABLE_STDIO
    fprintf(stderr, "unknown lhs %d\n", type);
#endif
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
  genop_1(s, OP_INTERN, cursp());
  push();
}

static void
gen_literal_array(codegen_scope *s, node *tree, mrb_bool sym, int val)
{
  if (val) {
    int i = 0, j = 0;

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
      tree = tree->cdr;
    }
    if (j > 0) {
      ++i;
      if (sym)
        gen_intern(s);
    }
    pop_n(i);
    genop_2(s, OP_ARRAY, cursp(), i);
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

#ifndef MRB_WITHOUT_FLOAT
static double
readint_float(codegen_scope *s, const char *p, int base)
{
  const char *e = p + strlen(p);
  double f = 0;
  int n;

  if (*p == '+') p++;
  while (p < e) {
    char c = *p;
    c = tolower((unsigned char)c);
    for (n=0; n<base; n++) {
      if (mrb_digitmap[n] == c) {
        f *= base;
        f += n;
        break;
      }
    }
    if (n == base) {
      codegen_error(s, "malformed readint input");
    }
    p++;
  }
  return f;
}
#endif

static mrb_int
readint_mrb_int(codegen_scope *s, const char *p, int base, mrb_bool neg, mrb_bool *overflow)
{
  const char *e = p + strlen(p);
  mrb_int result = 0;
  int n;

  mrb_assert(base >= 2 && base <= 36);
  if (*p == '+') p++;
  while (p < e) {
    char c = *p;
    c = tolower((unsigned char)c);
    for (n=0; n<base; n++) {
      if (mrb_digitmap[n] == c) {
        break;
      }
    }
    if (n == base) {
      codegen_error(s, "malformed readint input");
    }

    if (neg) {
      if ((MRB_INT_MIN + n)/base > result) {
        *overflow = TRUE;
        return 0;
      }
      result *= base;
      result -= n;
    }
    else {
      if ((MRB_INT_MAX - n)/base < result) {
        *overflow = TRUE;
        return 0;
      }
      result *= base;
      result += n;
    }
    p++;
  }
  *overflow = FALSE;
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
      int noexc, exend, pos1, pos2, tmp;
      struct loopinfo *lp;

      if (tree->car == NULL) goto exit;
      lp = loop_push(s, LOOP_BEGIN);
      lp->pc0 = new_label(s);
      lp->pc1 = genjmp(s, OP_ONERR, 0);
      codegen(s, tree->car, VAL);
      pop();
      lp->type = LOOP_RESCUE;
      noexc = genjmp(s, OP_JMP, 0);
      dispatch(s, lp->pc1);
      tree = tree->cdr;
      exend = 0;
      pos1 = 0;
      if (tree->car) {
        node *n2 = tree->car;
        int exc = cursp();

        genop_1(s, OP_EXCEPT, exc);
        push();
        while (n2) {
          node *n3 = n2->car;
          node *n4 = n3->car;

          if (pos1) dispatch(s, pos1);
          pos2 = 0;
          do {
            if (n4 && n4->car && nint(n4->car->car) == NODE_SPLAT) {
              codegen(s, n4->car, VAL);
              gen_move(s, cursp(), exc, 0);
              push_n(2); pop_n(2); /* space for one arg and a block */
              pop();
              genop_3(s, OP_SEND, cursp(), new_sym(s, mrb_intern_lit(s->mrb, "__case_eqq")), 1);
            }
            else {
              if (n4) {
                codegen(s, n4->car, VAL);
              }
              else {
                genop_2(s, OP_GETCONST, cursp(), new_sym(s, mrb_intern_lit(s->mrb, "StandardError")));
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
          pos1 = genjmp(s, OP_JMP, 0);
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
        if (pos1) {
          dispatch(s, pos1);
          genop_1(s, OP_RAISE, exc);
        }
      }
      pop();
      tree = tree->cdr;
      dispatch(s, noexc);
      genop_1(s, OP_POPERR, 1);
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
      int idx;

      s->ensure_level++;
      idx = scope_body(s, tree->cdr, NOVAL);
      genop_1(s, OP_EPUSH, idx);
      codegen(s, tree->car, val);
      s->ensure_level--;
      genop_1(s, OP_EPOP, 1);
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
      int pos1, pos2, nil_p = FALSE;
      node *elsepart = tree->cdr->cdr->car;

      if (!tree->car) {
        codegen(s, elsepart, val);
        goto exit;
      }
      switch (nint(tree->car->car)) {
      case NODE_TRUE:
      case NODE_INT:
      case NODE_STR:
        codegen(s, tree->cdr->car, val);
        goto exit;
      case NODE_FALSE:
      case NODE_NIL:
        codegen(s, elsepart, val);
        goto exit;
      case NODE_CALL:
        {
          node *n = tree->car->cdr;
          mrb_sym mid = nsym(n->cdr->car);
          mrb_sym mnil = mrb_intern_lit(s->mrb, "nil?");
          if (mid == mnil && n->cdr->cdr->car == NULL) {
            nil_p = TRUE;
            codegen(s, n->car, VAL);
          }
        }
        break;
      }
      if (!nil_p) {
        codegen(s, tree->car, VAL);
      }
      pop();
      if (val || tree->cdr->car) {
        if (nil_p) {
          pos2 = genjmp2(s, OP_JMPNIL, cursp(), 0, val);
          pos1 = genjmp(s, OP_JMP, 0);
          dispatch(s, pos2);
        }
        else {
          pos1 = genjmp2(s, OP_JMPNOT, cursp(), 0, val);
        }
        codegen(s, tree->cdr->car, val);
        if (val) pop();
        if (elsepart || val) {
          pos2 = genjmp(s, OP_JMP, 0);
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
            pos1 = genjmp2(s, OP_JMPNIL, cursp(), 0, val);
          }
          else {
            pos1 = genjmp2(s, OP_JMPIF, cursp(), 0, val);
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
      int pos;

      codegen(s, tree->car, VAL);
      pop();
      pos = genjmp2(s, OP_JMPNOT, cursp(), 0, val);
      codegen(s, tree->cdr, val);
      dispatch(s, pos);
    }
    break;

  case NODE_OR:
    {
      int pos;

      codegen(s, tree->car, VAL);
      pop();
      pos = genjmp2(s, OP_JMPIF, cursp(), 0, val);
      codegen(s, tree->cdr, val);
      dispatch(s, pos);
    }
    break;

  case NODE_WHILE:
    {
      struct loopinfo *lp = loop_push(s, LOOP_NORMAL);

      lp->pc0 = new_label(s);
      lp->pc1 = genjmp(s, OP_JMP, 0);
      lp->pc2 = new_label(s);
      codegen(s, tree->cdr, NOVAL);
      dispatch(s, lp->pc1);
      codegen(s, tree->car, VAL);
      pop();
      genjmp2(s, OP_JMPIF, cursp(), lp->pc2, NOVAL);

      loop_pop(s, val);
    }
    break;

  case NODE_UNTIL:
    {
      struct loopinfo *lp = loop_push(s, LOOP_NORMAL);

      lp->pc0 = new_label(s);
      lp->pc1 = genjmp(s, OP_JMP, 0);
      lp->pc2 = new_label(s);
      codegen(s, tree->cdr, NOVAL);
      dispatch(s, lp->pc1);
      codegen(s, tree->car, VAL);
      pop();
      genjmp2(s, OP_JMPNOT, cursp(), lp->pc2, NOVAL);

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
      int pos1, pos2, pos3, tmp;
      node *n;

      pos3 = 0;
      if (tree->car) {
        head = cursp();
        codegen(s, tree->car, VAL);
      }
      tree = tree->cdr;
      while (tree) {
        n = tree->car->car;
        pos1 = pos2 = 0;
        while (n) {
          codegen(s, n->car, VAL);
          if (head) {
            gen_move(s, cursp(), head, 0);
            push(); push(); pop(); pop(); pop();
            if (nint(n->car->car) == NODE_SPLAT) {
              genop_3(s, OP_SEND, cursp(), new_sym(s, mrb_intern_lit(s->mrb, "__case_eqq")), 1);
            }
            else {
              genop_3(s, OP_SEND, cursp(), new_sym(s, mrb_intern_lit(s->mrb, "===")), 1);
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
          pos1 = genjmp(s, OP_JMP, 0);
          dispatch_linked(s, pos2);
        }
        codegen(s, tree->car->cdr, val);
        if (val) pop();
        tmp = genjmp(s, OP_JMP, pos3);
        pos3 = tmp;
        if (pos1) dispatch(s, pos1);
        tree = tree->cdr;
      }
      if (val) {
        int pos = cursp();
        genop_1(s, OP_LOADNIL, cursp());
        if (pos3) dispatch_linked(s, pos3);
        if (head) pop();
        if (cursp() != pos) {
          gen_move(s, cursp(), pos, 0);
        }
        push();
      }
      else {
        if (pos3) {
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

      n = gen_values(s, tree, val, 0);
      if (n >= 0) {
        if (val) {
          pop_n(n);
          genop_2(s, OP_ARRAY, cursp(), n);
          push();
        }
      }
      else if (val) {
        push();
      }
    }
    break;

  case NODE_HASH:
  case NODE_KW_HASH:
    {
      int len = 0;
      mrb_bool update = FALSE;

      while (tree) {
        if (nint(tree->car->car->car) == NODE_KW_REST_ARGS) {
          if (len > 0) {
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
          codegen(s, tree->car->cdr, VAL);
          if (len > 0 || update) {
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
        if (val && cursp() > 127) {
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
      if (val) {
        pop_n(len*2);
        if (!update) {
          genop_2(s, OP_HASH, cursp(), len);
        }
        else {
          pop();
          if (len > 0) {
            genop_2(s, OP_HASHADD, cursp(), len);
          }
        }
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
        int onerr, noexc, exc;
        struct loopinfo *lp;

        onerr = genjmp(s, OP_ONERR, 0);
        lp = loop_push(s, LOOP_BEGIN);
        lp->pc1 = onerr;
        exc = cursp();
        codegen(s, tree->car, VAL);
        lp->type = LOOP_RESCUE;
        genop_1(s, OP_POPERR, 1);
        noexc = genjmp(s, OP_JMP, 0);
        dispatch(s, onerr);
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
          nargs = gen_values(s, n->cdr->cdr->car->car, VAL, 1);
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
        int pos;

        pop();
        if (val) {
          if (vsp >= 0) {
            gen_move(s, vsp, cursp(), 1);
          }
          pos = genjmp2(s, name[0]=='|'?OP_JMPIF:OP_JMPNOT, cursp(), 0, val);
        }
        else {
          pos = genjmp2(s, name[0]=='|'?OP_JMPIF:OP_JMPNOT, cursp(), 0, val);
        }
        codegen(s, tree->cdr->cdr->car, VAL);
        pop();
        if (val && vsp >= 0) {
          gen_move(s, vsp, cursp(), 1);
        }
        if (nint(tree->car->car) == NODE_CALL) {
          if (callargs == CALL_MAXARGS) {
            pop();
            genop_1(s, OP_ARYPUSH, cursp());
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
          genop_1(s, OP_ARYPUSH, cursp());
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
      int n = 0, noop = 0, sendv = 0;

      push();        /* room for receiver */
      while (!s2->mscope) {
        lv++;
        s2 = s2->prev;
        if (!s2) break;
      }
      genop_2S(s, OP_ARGARY, cursp(), (lv & 0xf));
      push(); push();         /* ARGARY pushes two values */
      pop(); pop();
      if (tree) {
        node *args = tree->car;
        if (args) {
          n = gen_values(s, args, VAL, 0);
          if (n < 0) {
            n = noop = sendv = 1;
            push();
          }
        }
      }
      if (tree && tree->cdr) {
        codegen(s, tree->cdr, VAL);
        pop();
      }
      else {
        genop_1(s, OP_LOADNIL, cursp());
        push(); pop();
      }
      pop_n(n+1);
      if (sendv) n = CALL_MAXARGS;
      genop_2(s, OP_SUPER, cursp(), n);
      if (val) push();
    }
    break;

  case NODE_ZSUPER:
    {
      codegen_scope *s2 = s;
      int lv = 0, ainfo = 0;

      push();        /* room for receiver */
      while (!s2->mscope) {
        lv++;
        s2 = s2->prev;
        if (!s2) break;
      }
      if (s2) ainfo = s2->ainfo;
      genop_2S(s, OP_ARGARY, cursp(), (ainfo<<4)|(lv & 0xf));
      push(); push(); pop();    /* ARGARY pushes two values */
      if (tree && tree->cdr) {
        codegen(s, tree->cdr, VAL);
        pop();
      }
      pop(); pop();
      genop_2(s, OP_SUPER, cursp(), CALL_MAXARGS);
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
      int lv = 0, ainfo = 0;
      int n = 0, sendv = 0;

      while (!s2->mscope) {
        lv++;
        s2 = s2->prev;
        if (!s2) break;
      }
      if (s2) ainfo = s2->ainfo;
      push();
      if (tree) {
        n = gen_values(s, tree, VAL, 0);
        if (n < 0) {
          n = sendv = 1;
          push();
        }
      }
      push();pop(); /* space for a block */
      pop_n(n+1);
      genop_2S(s, OP_BLKPUSH, cursp(), (ainfo<<4)|(lv & 0xf));
      if (sendv) n = CALL_MAXARGS;
      genop_3(s, OP_SEND, cursp(), new_sym(s, mrb_intern_lit(s->mrb, "call")), n);
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
      if (s->ensure_level > s->loop->ensure_level) {
        genop_1(s, OP_EPOP, s->ensure_level - s->loop->ensure_level);
      }
      codegen(s, tree, NOVAL);
      genjmp(s, OP_JMP, s->loop->pc0);
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
      if (s->ensure_level > s->loop->ensure_level) {
        genop_1(s, OP_EPOP, s->ensure_level - s->loop->ensure_level);
      }
      genjmp(s, OP_JMP, s->loop->pc2);
    }
    if (val) push();
    break;

  case NODE_RETRY:
    {
      const char *msg = "unexpected retry";

      if (!s->loop) {
        raise_error(s, msg);
      }
      else {
        struct loopinfo *lp = s->loop;
        int n = 0;

        while (lp && lp->type != LOOP_RESCUE) {
          if (lp->type == LOOP_BEGIN) {
            n++;
          }
          lp = lp->prev;
        }
        if (!lp) {
          raise_error(s, msg);
        }
        else {
          if (n > 0) {
            genop_1(s, OP_POPERR, n);
          }
          if (s->ensure_level > lp->ensure_level) {
            genop_1(s, OP_EPOP, s->ensure_level - lp->ensure_level);
          }
          genjmp(s, OP_JMP, lp->pc0);
        }
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
        int lv = search_upvar(s, nsym(tree), &idx);
        genop_3(s, OP_GETUPVAR, cursp(), idx, lv);
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
    codegen(s, tree, val);
    break;

  case NODE_INT:
    if (val) {
      char *p = (char*)tree->car;
      int base = nint(tree->cdr->car);
      mrb_int i;
      mrb_bool overflow;

      i = readint_mrb_int(s, p, base, FALSE, &overflow);
#ifndef MRB_WITHOUT_FLOAT
      if (overflow) {
        double f = readint_float(s, p, base);
        int off = new_lit(s, mrb_float_value(s->mrb, f));

        genop_2(s, OP_LOADL, cursp(), off);
      }
      else
#endif
      {
        if (i < 0) {
          if (i == -1) genop_1(s, OP_LOADI__1, cursp());
          else if (i >= -0xff) genop_2(s, OP_LOADINEG, cursp(), (uint16_t)-i); 
          else if (i >= -0x8000) genop_2S(s, OP_LOADI16, cursp(), (uint16_t)i);
          else goto lit_int;
        }
        else if (i < 8) genop_1(s, OP_LOADI_0 + (uint8_t)i, cursp());
        else if (i <= 0xff) genop_2(s, OP_LOADI, cursp(), (uint16_t)i);
        else if (i <= 0x7fff) genop_2S(s, OP_LOADI16, cursp(), (uint16_t)i);
        else {
          int off;

        lit_int:
          off = new_lit(s, mrb_fixnum_value(i));
          genop_2(s, OP_LOADL, cursp(), off);
        }
      }
      push();
    }
    break;

#ifndef MRB_WITHOUT_FLOAT
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
#ifndef MRB_WITHOUT_FLOAT
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

          i = readint_mrb_int(s, p, base, TRUE, &overflow);
#ifndef MRB_WITHOUT_FLOAT
          if (overflow) {
            double f = readint_float(s, p, base);
            int off = new_lit(s, mrb_float_value(s->mrb, -f));

            genop_2(s, OP_LOADL, cursp(), off);
          }
          else {
#endif
            if (i == -1) genop_1(s, OP_LOADI__1, cursp());
            else if (i >= -0xff) {
              genop_2(s, OP_LOADINEG, cursp(), (uint16_t)-i);
            }
            else if (i >= -0x8000) {
              genop_2S(s, OP_LOADI16, cursp(), (uint16_t)i);
            }
            else {
              int off = new_lit(s, mrb_fixnum_value(i));
              genop_2(s, OP_LOADL, cursp(), off);
            }
#ifndef MRB_WITHOUT_FLOAT
          }
#endif
          push();
        }
        break;

      default:
        if (val) {
          int sym = new_sym(s, mrb_intern_lit(s->mrb, "-@"));
          codegen(s, tree, VAL);
          pop();
          genop_3(s, OP_SEND, cursp(), sym, 0);
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
      int sym = new_sym(s, mrb_intern_lit(s->mrb, "Kernel"));

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
      sym = new_sym(s, mrb_intern_lit(s->mrb, "`"));
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
      sym = new_sym(s, mrb_intern_lit(s->mrb, "`"));
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
      sym = new_sym(s, mrb_intern_lit(s->mrb, "compile"));
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
      sym = new_sym(s, mrb_intern_lit(s->mrb, "compile"));
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
      if (val) {
        genop_2(s, OP_LOADSYM, cursp(), sym);
        push();
      }
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
      if (val) {
        genop_2(s, OP_LOADSYM, cursp(), sym);
        push();
      }
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
scope_add_irep(codegen_scope *s, mrb_irep *irep)
{
  if (s->irep == NULL) {
    s->irep = irep;
    return;
  }
  if (s->irep->rlen == s->rcapa) {
    s->rcapa *= 2;
    s->irep->reps = (mrb_irep**)codegen_realloc(s, s->irep->reps, sizeof(mrb_irep*)*s->rcapa);
  }
  s->irep->reps[s->irep->rlen] = irep;
  s->irep->rlen++;
}

static codegen_scope*
scope_new(mrb_state *mrb, codegen_scope *prev, node *lv)
{
  static const codegen_scope codegen_scope_zero = { 0 };
  mrb_pool *pool = mrb_pool_open(mrb);
  codegen_scope *p = (codegen_scope *)mrb_pool_alloc(pool, sizeof(codegen_scope));

  if (!p) {
    if (prev)
      codegen_error(prev, "unexpected scope");
    return NULL;
  }
  *p = codegen_scope_zero;
  p->mrb = mrb;
  p->mpool = pool;
  if (!prev) return p;
  p->prev = prev;
  p->ainfo = -1;
  p->mscope = 0;

  p->irep = mrb_add_irep(mrb);
  scope_add_irep(prev, p->irep);

  p->rcapa = 8;
  p->irep->reps = (mrb_irep**)mrb_malloc(mrb, sizeof(mrb_irep*)*p->rcapa);

  p->icapa = 1024;
  p->iseq = (mrb_code*)mrb_malloc(mrb, sizeof(mrb_code)*p->icapa);
  p->irep->iseq = NULL;

  p->pcapa = 32;
  p->irep->pool = (mrb_value*)mrb_malloc(mrb, sizeof(mrb_value)*p->pcapa);
  p->irep->plen = 0;

  p->scapa = 256;
  p->irep->syms = (mrb_sym*)mrb_malloc(mrb, sizeof(mrb_sym)*p->scapa);
  p->irep->slen = 0;

  p->lv = lv;
  p->sp += node_len(lv)+1;        /* add self */
  p->nlocals = p->sp;
  if (lv) {
    node *n = lv;
    size_t i = 0;

    p->irep->lv = (struct mrb_locals*)mrb_malloc(mrb, sizeof(struct mrb_locals) * (p->nlocals - 1));
    for (i=0, n=lv; n; i++,n=n->cdr) {
      p->irep->lv[i].name = lv_name(n);
      if (lv_name(n)) {
        p->irep->lv[i].r = lv_idx(p, lv_name(n));
      }
      else {
        p->irep->lv[i].r = 0;
      }
    }
    mrb_assert(i + 1 == p->nlocals);
  }
  p->ai = mrb_gc_arena_save(mrb);

  p->filename_sym = prev->filename_sym;
  if (p->filename_sym) {
    p->lines = (uint16_t*)mrb_malloc(mrb, sizeof(short)*p->icapa);
  }
  p->lineno = prev->lineno;

  /* debug setting */
  p->debug_start_pos = 0;
  if (p->filename_sym) {
    mrb_debug_info_alloc(mrb, p->irep);
  }
  else {
    p->irep->debug_info = NULL;
  }
  p->parser = prev->parser;
  p->filename_index = prev->filename_index;

  p->rlev = prev->rlev+1;

  return p;
}

static void
scope_finish(codegen_scope *s)
{
  mrb_state *mrb = s->mrb;
  mrb_irep *irep = s->irep;

  if (s->nlocals >= 0x3ff) {
    codegen_error(s, "too many local variables");
  }
  irep->flags = 0;
  if (s->iseq) {
    irep->iseq = (mrb_code *)codegen_realloc(s, s->iseq, sizeof(mrb_code)*s->pc);
    irep->ilen = s->pc;
  }
  irep->pool = (mrb_value*)codegen_realloc(s, irep->pool, sizeof(mrb_value)*irep->plen);
  irep->syms = (mrb_sym*)codegen_realloc(s, irep->syms, sizeof(mrb_sym)*irep->slen);
  irep->reps = (mrb_irep**)codegen_realloc(s, irep->reps, sizeof(mrb_irep*)*irep->rlen);
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
  p->pc0 = p->pc1 = p->pc2 = p->pc3 = 0;
  p->prev = s->loop;
  p->ensure_level = s->ensure_level;
  p->acc = cursp();
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
    int n = 0;

    if (tree) {
      gen_retval(s, tree);
    }

    loop = s->loop;
    while (loop) {
      if (loop->type == LOOP_BEGIN) {
        n++;
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
    if (n > 0) {
      genop_1(s, OP_POPERR, n);
    }

    if (loop->type == LOOP_NORMAL) {
      int tmp;

      if (s->ensure_level > s->loop->ensure_level) {
        genop_1(s, OP_EPOP, s->ensure_level - s->loop->ensure_level);
      }
      if (tree) {
        gen_move(s, loop->acc, cursp(), 0);
      }
      tmp = genjmp(s, OP_JMP, loop->pc3);
      loop->pc3 = tmp;
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
  dispatch_linked(s, s->loop->pc3);
  s->loop = s->loop->prev;
  if (val) push();
}

static struct RProc*
generate_code(mrb_state *mrb, parser_state *p, int val)
{
  codegen_scope *scope = scope_new(mrb, 0, 0);
  struct RProc *proc;
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;

  scope->mrb = mrb;
  scope->parser = p;
  scope->filename_sym = p->filename_sym;
  scope->filename_index = p->current_filename_index;

  MRB_TRY(&scope->jmp) {
    mrb->jmp = &scope->jmp;
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
  MRB_CATCH(&scope->jmp) {
    mrb_irep_decref(mrb, scope->irep);
    mrb_pool_close(scope->mpool);
    mrb->jmp = prev_jmp;
    return NULL;
  }
  MRB_END_EXC(&scope->jmp);
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

  if (irep->lv) {
    mrb_free(mrb, irep->lv);
    irep->lv = NULL;
  }

  for (i = 0; i < irep->rlen; ++i) {
    mrb_irep_remove_lv(mrb, irep->reps[i]);
  }
}

#undef OPCODE
#define Z 1
#define S 3
#define W 4
/* instruction sizes */
uint8_t mrb_insn_size[] = {
#define B 2
#define BB 3
#define BBB 4
#define BS 4
#define SB 4
#define OPCODE(_,x) x,
#include "mruby/ops.h"
#undef OPCODE
#undef B
#undef BB
#undef BS
#undef SB
#undef BBB
};
/* EXT1 instruction sizes */
uint8_t mrb_insn_size1[] = {
#define B 3
#define BB 4
#define BBB 5
#define BS 5
#define SB 5
#define OPCODE(_,x) x,
#include "mruby/ops.h"
#undef OPCODE
#undef B
};
/* EXT2 instruction sizes */
uint8_t mrb_insn_size2[] = {
#define B 2
#define OPCODE(_,x) x,
#include "mruby/ops.h"
#undef OPCODE
#undef BB
#undef BBB
#undef BS
#undef SB
};
/* EXT3 instruction sizes */
#define BB 5
#define BBB 6
#define BS 4
#define SB 5
uint8_t mrb_insn_size3[] = {
#define OPCODE(_,x) x,
#include "mruby/ops.h"
};
