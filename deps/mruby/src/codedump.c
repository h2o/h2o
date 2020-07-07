#include <mruby.h>
#include <mruby/irep.h>
#include <mruby/debug.h>
#include <mruby/opcode.h>
#include <mruby/string.h>
#include <mruby/proc.h>

#ifndef MRB_DISABLE_STDIO
static void
print_r(mrb_state *mrb, mrb_irep *irep, size_t n)
{
  size_t i;

  if (n == 0) return;

  for (i=0; i+1<irep->nlocals; i++) {
    if (irep->lv[i].r == n) {
      mrb_sym sym = irep->lv[i].name;
      printf(" R%d:%s", (int)n, mrb_sym_dump(mrb, sym));
      break;
    }
  }
}

static void
print_lv_a(mrb_state *mrb, mrb_irep *irep, uint16_t a)
{
  if (!irep->lv || a >= irep->nlocals || a == 0) {
    printf("\n");
    return;
  }
  printf("\t;");
  print_r(mrb, irep, a);
  printf("\n");
}

static void
print_lv_ab(mrb_state *mrb, mrb_irep *irep, uint16_t a, uint16_t b)
{
  if (!irep->lv || (a >= irep->nlocals && b >= irep->nlocals) || a+b == 0) {
    printf("\n");
    return;
  }
  printf("\t;");
  if (a > 0) print_r(mrb, irep, a);
  if (b > 0) print_r(mrb, irep, b);
  printf("\n");
}

static void
print_header(mrb_state *mrb, mrb_irep *irep, ptrdiff_t i)
{
  int32_t line;

  line = mrb_debug_get_line(mrb, irep, i);
  if (line < 0) {
    printf("      ");
  }
  else {
    printf("%5d ", line);
  }

  printf("%03d ", (int)i);
}

#define CASE(insn,ops) case insn: FETCH_ ## ops (); L_ ## insn

static void
codedump(mrb_state *mrb, mrb_irep *irep)
{
  int ai;
  const mrb_code *pc, *pcend;
  mrb_code ins;
  const char *file = NULL, *next_file;

  if (!irep) return;
  printf("irep %p nregs=%d nlocals=%d pools=%d syms=%d reps=%d iseq=%d\n", (void*)irep,
         irep->nregs, irep->nlocals, (int)irep->plen, (int)irep->slen, (int)irep->rlen, (int)irep->ilen);

  if (irep->lv) {
    int i;

    printf("local variable names:\n");
    for (i = 1; i < irep->nlocals; ++i) {
      char const *s = mrb_sym_dump(mrb, irep->lv[i - 1].name);
      int n = irep->lv[i - 1].r ? irep->lv[i - 1].r : i;
      printf("  R%d:%s\n", n, s ? s : "");
    }
  }

  pc = irep->iseq;
  pcend = pc + irep->ilen;
  while (pc < pcend) {
    ptrdiff_t i;
    uint32_t a;
    uint16_t b;
    uint8_t c;

    ai = mrb_gc_arena_save(mrb);

    i = pc - irep->iseq;
    next_file = mrb_debug_get_filename(mrb, irep, i);
    if (next_file && file != next_file) {
      printf("file: %s\n", next_file);
      file = next_file;
    }
    print_header(mrb, irep, i);
    ins = READ_B();
    switch (ins) {
    CASE(OP_NOP, Z):
      printf("OP_NOP\n");
      break;
    CASE(OP_MOVE, BB):
      printf("OP_MOVE\tR%d\tR%d\t", a, b);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_LOADL, BB):
      {
        mrb_value v = irep->pool[b];
        mrb_value s = mrb_inspect(mrb, v);
        printf("OP_LOADL\tR%d\tL(%d)\t; %s", a, b, RSTRING_PTR(s));
      }
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI, BB):
      printf("OP_LOADI\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADINEG, BB):
      printf("OP_LOADI\tR%d\t-%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI16, BS):
      printf("OP_LOADI16\tR%d\t%d\t", a, (int)(int16_t)b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI__1, B):
      printf("OP_LOADI__1\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI_0, B): goto L_LOADI;
    CASE(OP_LOADI_1, B): goto L_LOADI;
    CASE(OP_LOADI_2, B): goto L_LOADI;
    CASE(OP_LOADI_3, B): goto L_LOADI;
    CASE(OP_LOADI_4, B): goto L_LOADI;
    CASE(OP_LOADI_5, B): goto L_LOADI;
    CASE(OP_LOADI_6, B): goto L_LOADI;
    CASE(OP_LOADI_7, B):
    L_LOADI:
      printf("OP_LOADI_%d\tR%d\t\t", ins-(int)OP_LOADI_0, a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADSYM, BB):
      printf("OP_LOADSYM\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADNIL, B):
      printf("OP_LOADNIL\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADSELF, B):
      printf("OP_LOADSELF\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADT, B):
      printf("OP_LOADT\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADF, B):
      printf("OP_LOADF\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETGV, BB):
      printf("OP_GETGV\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETGV, BB):
      printf("OP_SETGV\t:%s\tR%d", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETSV, BB):
      printf("OP_GETSV\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETSV, BB):
      printf("OP_SETSV\t:%s\tR%d", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETCONST, BB):
      printf("OP_GETCONST\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETCONST, BB):
      printf("OP_SETCONST\t:%s\tR%d", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETMCNST, BB):
      printf("OP_GETMCNST\tR%d\tR%d::%s", a, a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETMCNST, BB):
      printf("OP_SETMCNST\tR%d::%s\tR%d", a+1, mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETIV, BB):
      printf("OP_GETIV\tR%d\t%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETIV, BB):
      printf("OP_SETIV\t%s\tR%d", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETUPVAR, BBB):
      printf("OP_GETUPVAR\tR%d\t%d\t%d", a, b, c);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETUPVAR, BBB):
      printf("OP_SETUPVAR\tR%d\t%d\t%d", a, b, c);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETCV, BB):
      printf("OP_GETCV\tR%d\t%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETCV, BB):
      printf("OP_SETCV\t%s\tR%d", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_JMP, S):
      printf("OP_JMP\t\t%03d\n", a);
      break;
    CASE(OP_JMPIF, BS):
      printf("OP_JMPIF\tR%d\t%03d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_JMPNOT, BS):
      printf("OP_JMPNOT\tR%d\t%03d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_JMPNIL, BS):
      printf("OP_JMPNIL\tR%d\t%03d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SENDV, BB):
      printf("OP_SENDV\tR%d\t:%s\n", a, mrb_sym_dump(mrb, irep->syms[b]));
      break;
    CASE(OP_SENDVB, BB):
      printf("OP_SENDVB\tR%d\t:%s\n", a, mrb_sym_dump(mrb, irep->syms[b]));
      break;
    CASE(OP_SEND, BBB):
      printf("OP_SEND\tR%d\t:%s\t%d\n", a, mrb_sym_dump(mrb, irep->syms[b]), c);
      break;
    CASE(OP_SENDB, BBB):
      printf("OP_SENDB\tR%d\t:%s\t%d\n", a, mrb_sym_dump(mrb, irep->syms[b]), c);
      break;
    CASE(OP_CALL, Z):
      printf("OP_CALL\n");
      break;
    CASE(OP_SUPER, BB):
      printf("OP_SUPER\tR%d\t%d\n", a, b);
      break;
    CASE(OP_ARGARY, BS):
      printf("OP_ARGARY\tR%d\t%d:%d:%d:%d (%d)", a,
             (b>>11)&0x3f,
             (b>>10)&0x1,
             (b>>5)&0x1f,
             (b>>4)&0x1,
             (b>>0)&0xf);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ENTER, W):
      printf("OP_ENTER\t%d:%d:%d:%d:%d:%d:%d\n",
             MRB_ASPEC_REQ(a),
             MRB_ASPEC_OPT(a),
             MRB_ASPEC_REST(a),
             MRB_ASPEC_POST(a),
             MRB_ASPEC_KEY(a),
             MRB_ASPEC_KDICT(a),
             MRB_ASPEC_BLOCK(a));
      break;
    CASE(OP_KEY_P, BB):
      printf("OP_KEY_P\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_KEYEND, Z):
      printf("OP_KEYEND\n");
      break;
    CASE(OP_KARG, BB):
      printf("OP_KARG\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_RETURN, B):
      printf("OP_RETURN\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_RETURN_BLK, B):
      printf("OP_RETURN_BLK\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_BREAK, B):
      printf("OP_BREAK\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_BLKPUSH, BS):
      printf("OP_BLKPUSH\tR%d\t%d:%d:%d:%d (%d)", a,
             (b>>11)&0x3f,
             (b>>10)&0x1,
             (b>>5)&0x1f,
             (b>>4)&0x1,
             (b>>0)&0xf);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LAMBDA, BB):
      printf("OP_LAMBDA\tR%d\tI(%d:%p)\n", a, b, irep->reps[b]);
      break;
    CASE(OP_BLOCK, BB):
      printf("OP_BLOCK\tR%d\tI(%d:%p)\n", a, b, irep->reps[b]);
      break;
    CASE(OP_METHOD, BB):
      printf("OP_METHOD\tR%d\tI(%d:%p)\n", a, b, irep->reps[b]);
      break;
    CASE(OP_RANGE_INC, B):
      printf("OP_RANGE_INC\tR%d\n", a);
      break;
    CASE(OP_RANGE_EXC, B):
      printf("OP_RANGE_EXC\tR%d\n", a);
      break;
    CASE(OP_DEF, BB):
      printf("OP_DEF\tR%d\t:%s\n", a, mrb_sym_dump(mrb, irep->syms[b]));
      break;
    CASE(OP_UNDEF, B):
      printf("OP_UNDEF\t:%s\n", mrb_sym_dump(mrb, irep->syms[a]));
      break;
    CASE(OP_ALIAS, BB):
      printf("OP_ALIAS\t:%s\t%s\n", mrb_sym_dump(mrb, irep->syms[a]), mrb_sym_dump(mrb, irep->syms[b]));
      break;
    CASE(OP_ADD, B):
      printf("OP_ADD\tR%d\t\n", a);
      break;
    CASE(OP_ADDI, BB):
      printf("OP_ADDI\tR%d\t%d\n", a, b);
      break;
    CASE(OP_SUB, B):
      printf("OP_SUB\tR%d\t\n", a);
      break;
    CASE(OP_SUBI, BB):
      printf("OP_SUBI\tR%d\t%d\n", a, b);
      break;
    CASE(OP_MUL, B):
      printf("OP_MUL\tR%d\t\n", a);
      break;
    CASE(OP_DIV, B):
      printf("OP_DIV\tR%d\t\n", a);
      break;
    CASE(OP_LT, B):
      printf("OP_LT\t\tR%d\t\n", a);
      break;
    CASE(OP_LE, B):
      printf("OP_LE\t\tR%d\t\n", a);
      break;
    CASE(OP_GT, B):
      printf("OP_GT\t\tR%d\t\n", a);
      break;
    CASE(OP_GE, B):
      printf("OP_GE\t\tR%d\t\n", a);
      break;
    CASE(OP_EQ, B):
      printf("OP_EQ\t\tR%d\t\n", a);
      break;
    CASE(OP_ARRAY, BB):
      printf("OP_ARRAY\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ARRAY2, BBB):
      printf("OP_ARRAY\tR%d\tR%d\t%d\t", a, b, c);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_ARYCAT, B):
      printf("OP_ARYCAT\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ARYPUSH, B):
      printf("OP_ARYPUSH\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ARYDUP, B):
      printf("OP_ARYDUP\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_AREF, BBB):
      printf("OP_AREF\tR%d\tR%d\t%d", a, b, c);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_ASET, BBB):
      printf("OP_ASET\tR%d\tR%d\t%d", a, b, c);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_APOST, BBB):
      printf("OP_APOST\tR%d\t%d\t%d", a, b, c);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_INTERN, B):
      printf("OP_INTERN\tR%d", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_STRING, BB):
      {
        mrb_value v = irep->pool[b];
        mrb_value s = mrb_str_dump(mrb, mrb_str_new(mrb, RSTRING_PTR(v), RSTRING_LEN(v)));
        printf("OP_STRING\tR%d\tL(%d)\t; %s", a, b, RSTRING_PTR(s));
      }
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_STRCAT, B):
      printf("OP_STRCAT\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_HASH, BB):
      printf("OP_HASH\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_HASHADD, BB):
      printf("OP_HASHADD\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_HASHCAT, B):
      printf("OP_HASHCAT\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;

    CASE(OP_OCLASS, B):
      printf("OP_OCLASS\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_CLASS, BB):
      printf("OP_CLASS\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_MODULE, BB):
      printf("OP_MODULE\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_EXEC, BB):
      printf("OP_EXEC\tR%d\tI(%d:%p)", a, b, irep->reps[b]);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SCLASS, B):
      printf("OP_SCLASS\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_TCLASS, B):
      printf("OP_TCLASS\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ERR, B):
      {
        mrb_value v = irep->pool[a];
        mrb_value s = mrb_str_dump(mrb, mrb_str_new(mrb, RSTRING_PTR(v), RSTRING_LEN(v)));
        printf("OP_ERR\t%s\n", RSTRING_PTR(s));
      }
      break;
    CASE(OP_EPUSH, B):
      printf("OP_EPUSH\t\t:I(%d:%p)\n", a, irep->reps[a]);
      break;
    CASE(OP_ONERR, S):
      printf("OP_ONERR\t%03d\n", a);
      break;
    CASE(OP_EXCEPT, B):
      printf("OP_EXCEPT\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_RESCUE, BB):
      printf("OP_RESCUE\tR%d\tR%d", a, b);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_RAISE, B):
      printf("OP_RAISE\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_POPERR, B):
      printf("OP_POPERR\t%d\t\t\n", a);
      break;
    CASE(OP_EPOP, B):
      printf("OP_EPOP\t%d\n", a);
      break;

    CASE(OP_DEBUG, BBB):
      printf("OP_DEBUG\t%d\t%d\t%d\n", a, b, c);
      break;

    CASE(OP_STOP, Z):
      printf("OP_STOP\n");
      break;

    CASE(OP_EXT1, Z):
      ins = READ_B();
      printf("OP_EXT1\n");
      print_header(mrb, irep, pc-irep->iseq-2);
      switch (ins) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _1 (); goto L_OP_ ## i;
#include "mruby/ops.h"
#undef OPCODE
      }
      break;
    CASE(OP_EXT2, Z):
      ins = READ_B();
      printf("OP_EXT2\n");
      print_header(mrb, irep, pc-irep->iseq-2);
      switch (ins) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _2 (); goto L_OP_ ## i;
#include "mruby/ops.h"
#undef OPCODE
      }
      break;
    CASE(OP_EXT3, Z):
      ins = READ_B();
      printf("OP_EXT3\n");
      print_header(mrb, irep, pc-irep->iseq-2);
      switch (ins) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _3 (); goto L_OP_ ## i;
#include "mruby/ops.h"
#undef OPCODE
      }
      break;

    default:
      printf("OP_unknown (0x%x)\n", ins);
      break;
    }
    mrb_gc_arena_restore(mrb, ai);
  }
  printf("\n");
}

static void
codedump_recur(mrb_state *mrb, mrb_irep *irep)
{
  int i;

  codedump(mrb, irep);
  for (i=0; i<irep->rlen; i++) {
    codedump_recur(mrb, irep->reps[i]);
  }
}
#endif

void
mrb_codedump_all(mrb_state *mrb, struct RProc *proc)
{
#ifndef MRB_DISABLE_STDIO
  codedump_recur(mrb, proc->body.irep);
#endif
}
