#include <mruby.h>
#include <mruby/irep.h>
#include <mruby/debug.h>
#include <mruby/opcode.h>
#include <mruby/string.h>
#include <mruby/proc.h>
#include <mruby/dump.h>

#ifndef MRB_NO_STDIO
static void
print_r(mrb_state *mrb, const mrb_irep *irep, size_t n)
{
  if (n == 0) return;
  if (n >= irep->nlocals) return;
  if (!irep->lv[n-1]) return;
  printf(" R%d:%s", (int)n, mrb_sym_dump(mrb, irep->lv[n-1]));
}

static void
print_lv_a(mrb_state *mrb, const mrb_irep *irep, uint16_t a)
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
print_lv_ab(mrb_state *mrb, const mrb_irep *irep, uint16_t a, uint16_t b)
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
print_header(mrb_state *mrb, const mrb_irep *irep, uint32_t i)
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

static void
print_args(uint8_t i)
{
  uint8_t n = i&0xf;
  uint8_t nk = (i>>4)&0xf;

  if (n == 15) {
    printf("n=*");
  }
  else {
    printf("n=%d", n);
  }
  if (nk > 0) {
    printf("|");
    if (nk == 15) {
      printf("nk=*");
    }
    else {
      printf("nk=%d", nk);
    }
  }
  printf(" (0x%02x)\n", i);
}

#define CASE(insn,ops) case insn: FETCH_ ## ops (); L_ ## insn

static void
codedump(mrb_state *mrb, const mrb_irep *irep)
{
  int ai;
  const mrb_code *pc, *pcend;
  mrb_code ins;
  const char *file = NULL, *next_file;

  if (!irep) return;
  printf("irep %p nregs=%d nlocals=%d pools=%d syms=%d reps=%d ilen=%d\n", (void*)irep,
         irep->nregs, irep->nlocals, (int)irep->plen, (int)irep->slen, (int)irep->rlen, (int)irep->ilen);

  if (irep->lv) {
    int i;

    printf("local variable names:\n");
    for (i = 1; i < irep->nlocals; ++i) {
      char const *s = mrb_sym_dump(mrb, irep->lv[i - 1]);
      printf("  R%d:%s\n", i, s ? s : "");
    }
  }

  if (irep->clen > 0) {
    int i = irep->clen;
    const struct mrb_irep_catch_handler *e = mrb_irep_catch_handler_table(irep);

    for (; i > 0; i --, e ++) {
      uint32_t begin = mrb_irep_catch_handler_unpack(e->begin);
      uint32_t end = mrb_irep_catch_handler_unpack(e->end);
      uint32_t target = mrb_irep_catch_handler_unpack(e->target);
      char buf[20];
      const char *type;

      switch (e->type) {
        case MRB_CATCH_RESCUE:
          type = "rescue";
          break;
        case MRB_CATCH_ENSURE:
          type = "ensure";
          break;
        default:
          buf[0] = '\0';
          snprintf(buf, sizeof(buf), "0x%02x <unknown>", (int)e->type);
          type = buf;
          break;
      }
      printf("catch type: %-8s begin: %04" PRIu32 " end: %04" PRIu32 " target: %04" PRIu32 "\n", type, begin, end, target);
    }
  }

  pc = irep->iseq;
  pcend = pc + irep->ilen;
  while (pc < pcend) {
    ptrdiff_t i;
    uint32_t a;
    uint16_t b;
    uint16_t c;

    ai = mrb_gc_arena_save(mrb);

    i = pc - irep->iseq;
    next_file = mrb_debug_get_filename(mrb, irep, (uint32_t)i);
    if (next_file && file != next_file) {
      printf("file: %s\n", next_file);
      file = next_file;
    }
    print_header(mrb, irep, (uint32_t)i);
    ins = READ_B();
    switch (ins) {
    CASE(OP_NOP, Z):
      printf("NOP\n");
      break;
    CASE(OP_MOVE, BB):
      printf("MOVE\t\tR%d\tR%d\t", a, b);
      print_lv_ab(mrb, irep, a, b);
      break;

    CASE(OP_LOADL, BB):
      switch (irep->pool[b].tt) {
#ifndef MRB_NO_FLOAT
      case IREP_TT_FLOAT:
        printf("LOADL\t\tR%d\tL(%d)\t; %f", a, b, (double)irep->pool[b].u.f);
        break;
#endif
      case IREP_TT_INT32:
        printf("LOADL\t\tR%d\tL(%d)\t; %" PRId32, a, b, irep->pool[b].u.i32);
        break;
#ifdef MRB_64BIT
      case IREP_TT_INT64:
        printf("LOADL\t\tR%d\tL(%d)\t; %" PRId64, a, b, irep->pool[b].u.i64);
        break;
#endif
      default:
        printf("LOADL\t\tR%d\tL(%d)\t", a, b);
        break;
      }
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI, BB):
      printf("LOADI\t\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADINEG, BB):
      printf("LOADI\tR%d\t-%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI16, BS):
      printf("LOADI16\tR%d\t%d\t", a, (int)(int16_t)b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI32, BSS):
      printf("LOADI32\tR%d\t%d\t", a, (int32_t)(((uint32_t)b<<16)+c));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADI__1, B):
      printf("LOADI__1\tR%d\t\t", a);
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
      printf("LOADI_%d\tR%d\t\t", ins-(int)OP_LOADI_0, a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADSYM, BB):
      printf("LOADSYM\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADNIL, B):
      printf("LOADNIL\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADSELF, B):
      printf("LOADSELF\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADT, B):
      printf("LOADT\t\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LOADF, B):
      printf("LOADF\t\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETGV, BB):
      printf("GETGV\t\tR%d\t%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETGV, BB):
      printf("SETGV\t\t%s\tR%d\t", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETSV, BB):
      printf("GETSV\t\tR%d\t%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETSV, BB):
      printf("SETSV\t\t%s\tR%d\t", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETCONST, BB):
      printf("GETCONST\tR%d\t%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETCONST, BB):
      printf("SETCONST\t%s\tR%d\t", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETMCNST, BB):
      printf("GETMCNST\tR%d\tR%d::%s\t", a, a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETMCNST, BB):
      printf("SETMCNST\tR%d::%s\tR%d\t", a+1, mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETIV, BB):
      printf("GETIV\t\tR%d\t%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETIV, BB):
      printf("SETIV\t\t%s\tR%d\t", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETUPVAR, BBB):
      printf("GETUPVAR\tR%d\t%d\t%d\t", a, b, c);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETUPVAR, BBB):
      printf("SETUPVAR\tR%d\t%d\t%d\t", a, b, c);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETCV, BB):
      printf("GETCV\t\tR%d\t%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SETCV, BB):
      printf("SETCV\t\t%s\tR%d\t", mrb_sym_dump(mrb, irep->syms[b]), a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_GETIDX, B):
      printf("GETIDX\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_SETIDX, B):
      printf("SETIDX\tR%d\tR%d\tR%d\n", a, a+1, a+2);
      break;
    CASE(OP_JMP, S):
      i = pc - irep->iseq;
      printf("JMP\t\t%03d\n", (int)i+(int16_t)a);
      break;
    CASE(OP_JMPUW, S):
      i = pc - irep->iseq;
      printf("JMPUW\t\t%03d\n", (int)i+(int16_t)a);
      break;
    CASE(OP_JMPIF, BS):
      i = pc - irep->iseq;
      printf("JMPIF\t\tR%d\t%03d\t", a, (int)i+(int16_t)b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_JMPNOT, BS):
      i = pc - irep->iseq;
      printf("JMPNOT\tR%d\t%03d\t", a, (int)i+(int16_t)b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_JMPNIL, BS):
      i = pc - irep->iseq;
      printf("JMPNIL\tR%d\t%03d\t", a, (int)i+(int16_t)b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SSEND, BBB):
      printf("SSEND\t\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_args(c);
      break;
    CASE(OP_SSENDB, BBB):
      printf("SSENDB\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_args(c);
      break;
    CASE(OP_SEND, BBB):
      printf("SEND\t\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_args(c);
      break;
    CASE(OP_SENDB, BBB):
      printf("SENDB\t\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_args(c);
      break;
    CASE(OP_CALL, Z):
      printf("CALL\n");
      break;
    CASE(OP_SUPER, BB):
      printf("SUPER\t\tR%d\t", a);
      print_args(b);
      break;
    CASE(OP_ARGARY, BS):
      printf("ARGARY\tR%d\t%d:%d:%d:%d (%d)\t", a,
             (b>>11)&0x3f,
             (b>>10)&0x1,
             (b>>5)&0x1f,
             (b>>4)&0x1,
             (b>>0)&0xf);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ENTER, W):
      printf("ENTER\t\t%d:%d:%d:%d:%d:%d:%d (0x%x)\n",
             MRB_ASPEC_REQ(a),
             MRB_ASPEC_OPT(a),
             MRB_ASPEC_REST(a),
             MRB_ASPEC_POST(a),
             MRB_ASPEC_KEY(a),
             MRB_ASPEC_KDICT(a),
             MRB_ASPEC_BLOCK(a), a);
      break;
    CASE(OP_KEY_P, BB):
      printf("KEY_P\t\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_KEYEND, Z):
      printf("KEYEND\n");
      break;
    CASE(OP_KARG, BB):
      printf("KARG\t\tR%d\t:%s\t", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_RETURN, B):
      printf("RETURN\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_RETURN_BLK, B):
      printf("RETURN_BLK\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_BREAK, B):
      printf("BREAK\t\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_BLKPUSH, BS):
      printf("BLKPUSH\tR%d\t%d:%d:%d:%d (%d)\t", a,
             (b>>11)&0x3f,
             (b>>10)&0x1,
             (b>>5)&0x1f,
             (b>>4)&0x1,
             (b>>0)&0xf);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_LAMBDA, BB):
      printf("LAMBDA\tR%d\tI(%d:%p)\n", a, b, (void*)irep->reps[b]);
      break;
    CASE(OP_BLOCK, BB):
      printf("BLOCK\t\tR%d\tI(%d:%p)\n", a, b, (void*)irep->reps[b]);
      break;
    CASE(OP_METHOD, BB):
      printf("METHOD\tR%d\tI(%d:%p)\n", a, b, (void*)irep->reps[b]);
      break;
    CASE(OP_RANGE_INC, B):
      printf("RANGE_INC\tR%d\n", a);
      break;
    CASE(OP_RANGE_EXC, B):
      printf("RANGE_EXC\tR%d\n", a);
      break;
    CASE(OP_DEF, BB):
      printf("DEF\t\tR%d\t:%s\n", a, mrb_sym_dump(mrb, irep->syms[b]));
      break;
    CASE(OP_UNDEF, B):
      printf("UNDEF\t\t:%s\n", mrb_sym_dump(mrb, irep->syms[a]));
      break;
    CASE(OP_ALIAS, BB):
      printf("ALIAS\t\t:%s\t%s\n", mrb_sym_dump(mrb, irep->syms[a]), mrb_sym_dump(mrb, irep->syms[b]));
      break;
    CASE(OP_ADD, B):
      printf("ADD\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_ADDI, BB):
      printf("ADDI\t\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SUB, B):
      printf("SUB\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_SUBI, BB):
      printf("SUBI\t\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_MUL, B):
      printf("MUL\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_DIV, B):
      printf("DIV\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_LT, B):
      printf("LT\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_LE, B):
      printf("LE\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_GT, B):
      printf("GT\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_GE, B):
      printf("GE\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_EQ, B):
      printf("EQ\t\tR%d\tR%d\n", a, a+1);
      break;
    CASE(OP_ARRAY, BB):
      printf("ARRAY\t\tR%d\tR%d\t%d", a, a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ARRAY2, BBB):
      printf("ARRAY\t\tR%d\tR%d\t%d", a, b, c);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_ARYCAT, B):
      printf("ARYCAT\tR%d\tR%d\t", a, a+1);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ARYPUSH, BB):
      printf("ARYPUSH\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ARYDUP, B):
      printf("ARYDUP\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_AREF, BBB):
      printf("AREF\t\tR%d\tR%d\t%d", a, b, c);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_ASET, BBB):
      printf("ASET\t\tR%d\tR%d\t%d", a, b, c);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_APOST, BBB):
      printf("APOST\t\tR%d\t%d\t%d", a, b, c);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_INTERN, B):
      printf("INTERN\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SYMBOL, BB):
      mrb_assert((irep->pool[b].tt&IREP_TT_NFLAG)==0);
      printf("SYMBOL\tR%d\tL(%d)\t; %s", a, b, irep->pool[b].u.str);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_STRING, BB):
      mrb_assert((irep->pool[b].tt&IREP_TT_NFLAG)==0);
      if ((irep->pool[b].tt & IREP_TT_NFLAG) == 0) {
        printf("STRING\tR%d\tL(%d)\t; %s", a, b, irep->pool[b].u.str);
      }
      else {
        printf("STRING\tR%d\tL(%d)\t", a, b);
      }
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_STRCAT, B):
      printf("STRCAT\tR%d\tR%d", a, a+1);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_HASH, BB):
      printf("HASH\t\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_HASHADD, BB):
      printf("HASHADD\tR%d\t%d\t", a, b);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_HASHCAT, B):
      printf("HASHCAT\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;

    CASE(OP_OCLASS, B):
      printf("OCLASS\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_CLASS, BB):
      printf("CLASS\t\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_MODULE, BB):
      printf("MODULE\tR%d\t:%s", a, mrb_sym_dump(mrb, irep->syms[b]));
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_EXEC, BB):
      printf("EXEC\t\tR%d\tI(%d:%p)", a, b, (void*)irep->reps[b]);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_SCLASS, B):
      printf("SCLASS\t\tR%d\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_TCLASS, B):
      printf("TCLASS\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_ERR, B):
      if ((irep->pool[a].tt & IREP_TT_NFLAG) == 0) {
        printf("ERR\t\t%s\n", irep->pool[a].u.str);
      }
      else {
        printf("ERR\tL(%d)\n", a);
      }
      break;
    CASE(OP_EXCEPT, B):
      printf("EXCEPT\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;
    CASE(OP_RESCUE, BB):
      printf("RESCUE\tR%d\tR%d", a, b);
      print_lv_ab(mrb, irep, a, b);
      break;
    CASE(OP_RAISEIF, B):
      printf("RAISEIF\tR%d\t\t", a);
      print_lv_a(mrb, irep, a);
      break;

    CASE(OP_DEBUG, BBB):
      printf("DEBUG\t\t%d\t%d\t%d\n", a, b, c);
      break;

    CASE(OP_STOP, Z):
      printf("STOP\n");
      break;

    CASE(OP_EXT1, Z):
      printf("EXT1\n");
      print_header(mrb, irep, pc-irep->iseq);
      ins = READ_B();
      switch (ins) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _1 (); goto L_OP_ ## i;
#include "mruby/ops.h"
#undef OPCODE
      }
      break;
    CASE(OP_EXT2, Z):
      printf("EXT2\n");
      print_header(mrb, irep, pc-irep->iseq);
      ins = READ_B();
      switch (ins) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _2 (); goto L_OP_ ## i;
#include "mruby/ops.h"
#undef OPCODE
      }
      break;
    CASE(OP_EXT3, Z):
      printf("EXT3\n");
      print_header(mrb, irep, pc-irep->iseq);
      ins = READ_B();
      switch (ins) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _3 (); goto L_OP_ ## i;
#include "mruby/ops.h"
#undef OPCODE
      }
      break;

    default:
      printf("unknown_op (0x%x)\n", ins);
      break;
    }
    mrb_gc_arena_restore(mrb, ai);
  }
  printf("\n");
}

static void
codedump_recur(mrb_state *mrb, const mrb_irep *irep)
{
  int i;

  codedump(mrb, irep);
  if (irep->reps) {
    for (i=0; i<irep->rlen; i++) {
      codedump_recur(mrb, irep->reps[i]);
    }
  }
}
#endif

void
mrb_codedump_all(mrb_state *mrb, struct RProc *proc)
{
#ifndef MRB_NO_STDIO
  codedump_recur(mrb, proc->body.irep);
#endif
}
