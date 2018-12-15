#include <mruby.h>
#include <mruby/irep.h>
#include <mruby/debug.h>
#include <mruby/opcode.h>
#include <mruby/string.h>
#include <mruby/proc.h>

#ifndef MRB_DISABLE_STDIO
static int
print_r(mrb_state *mrb, mrb_irep *irep, size_t n, int pre)
{
  size_t i;

  if (n == 0) return 0;

  for (i=0; i+1<irep->nlocals; i++) {
    if (irep->lv[i].r == n) {
      mrb_sym sym = irep->lv[i].name;
      if (pre) printf(" ");
      printf("R%d:%s", (int)n, mrb_sym2name(mrb, sym));
      return 1;
    }
  }
  return 0;
}

#define RA  1
#define RB  2
#define RAB 3

static void
print_lv(mrb_state *mrb, mrb_irep *irep, mrb_code c, int r)
{
  int pre = 0;

  if (!irep->lv
      || ((!(r & RA) || GETARG_A(c) >= irep->nlocals)
       && (!(r & RB) || GETARG_B(c) >= irep->nlocals))) {
    printf("\n");
    return;
  }
  printf("\t; ");
  if (r & RA) {
    pre = print_r(mrb, irep, GETARG_A(c), 0);
  }
  if (r & RB) {
    print_r(mrb, irep, GETARG_B(c), pre);
  }
  printf("\n");
}
#endif

static void
codedump(mrb_state *mrb, mrb_irep *irep)
{
#ifndef MRB_DISABLE_STDIO
  int i;
  int ai;
  mrb_code c;
  const char *file = NULL, *next_file;
  int32_t line;

  if (!irep) return;
  printf("irep %p nregs=%d nlocals=%d pools=%d syms=%d reps=%d\n", (void*)irep,
         irep->nregs, irep->nlocals, (int)irep->plen, (int)irep->slen, (int)irep->rlen);

  for (i = 0; i < (int)irep->ilen; i++) {
    ai = mrb_gc_arena_save(mrb);

    next_file = mrb_debug_get_filename(irep, i);
    if (next_file && file != next_file) {
      printf("file: %s\n", next_file);
      file = next_file;
    }
    line = mrb_debug_get_line(irep, i);
    if (line < 0) {
      printf("      ");
    }
    else {
      printf("%5d ", line);
    }

    printf("%03d ", i);
    c = irep->iseq[i];
    switch (GET_OPCODE(c)) {
    case OP_NOP:
      printf("OP_NOP\n");
      break;
    case OP_MOVE:
      printf("OP_MOVE\tR%d\tR%d\t", GETARG_A(c), GETARG_B(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_LOADL:
      {
        mrb_value v = irep->pool[GETARG_Bx(c)];
        mrb_value s = mrb_inspect(mrb, v);
        printf("OP_LOADL\tR%d\tL(%d)\t; %s", GETARG_A(c), GETARG_Bx(c), RSTRING_PTR(s));
      }
      print_lv(mrb, irep, c, RA);
      break;
    case OP_LOADI:
      printf("OP_LOADI\tR%d\t%d\t", GETARG_A(c), GETARG_sBx(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_LOADSYM:
      printf("OP_LOADSYM\tR%d\t:%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_LOADNIL:
      printf("OP_LOADNIL\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_LOADSELF:
      printf("OP_LOADSELF\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_LOADT:
      printf("OP_LOADT\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_LOADF:
      printf("OP_LOADF\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_GETGLOBAL:
      printf("OP_GETGLOBAL\tR%d\t:%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_SETGLOBAL:
      printf("OP_SETGLOBAL\t:%s\tR%d\t",
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]),
             GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_GETCONST:
      printf("OP_GETCONST\tR%d\t:%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_SETCONST:
      printf("OP_SETCONST\t:%s\tR%d\t",
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]),
             GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_GETMCNST:
      printf("OP_GETMCNST\tR%d\tR%d::%s", GETARG_A(c), GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_SETMCNST:
      printf("OP_SETMCNST\tR%d::%s\tR%d", GETARG_A(c)+1,
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]),
             GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_GETIV:
      printf("OP_GETIV\tR%d\t%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_SETIV:
      printf("OP_SETIV\t%s\tR%d",
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]),
             GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_GETUPVAR:
      printf("OP_GETUPVAR\tR%d\t%d\t%d",
             GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_SETUPVAR:
      printf("OP_SETUPVAR\tR%d\t%d\t%d",
             GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_GETCV:
      printf("OP_GETCV\tR%d\t%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_SETCV:
      printf("OP_SETCV\t%s\tR%d",
             mrb_sym2name(mrb, irep->syms[GETARG_Bx(c)]),
             GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_JMP:
      printf("OP_JMP\t%03d (%d)\n", i+GETARG_sBx(c), GETARG_sBx(c));
      break;
    case OP_JMPIF:
      printf("OP_JMPIF\tR%d\t%03d (%d)\n", GETARG_A(c), i+GETARG_sBx(c), GETARG_sBx(c));
      break;
    case OP_JMPNOT:
      printf("OP_JMPNOT\tR%d\t%03d (%d)\n", GETARG_A(c), i+GETARG_sBx(c), GETARG_sBx(c));
      break;
    case OP_SEND:
      printf("OP_SEND\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_SENDB:
      printf("OP_SENDB\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_CALL:
      printf("OP_CALL\tR%d\n", GETARG_A(c));
      break;
    case OP_TAILCALL:
      printf("OP_TAILCALL\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_SUPER:
      printf("OP_SUPER\tR%d\t%d\n", GETARG_A(c),
             GETARG_C(c));
      break;
    case OP_ARGARY:
      printf("OP_ARGARY\tR%d\t%d:%d:%d:%d", GETARG_A(c),
             (GETARG_Bx(c)>>10)&0x3f,
             (GETARG_Bx(c)>>9)&0x1,
             (GETARG_Bx(c)>>4)&0x1f,
             (GETARG_Bx(c)>>0)&0xf);
      print_lv(mrb, irep, c, RA);
      break;

    case OP_ENTER:
      printf("OP_ENTER\t%d:%d:%d:%d:%d:%d:%d\n",
             (GETARG_Ax(c)>>18)&0x1f,
             (GETARG_Ax(c)>>13)&0x1f,
             (GETARG_Ax(c)>>12)&0x1,
             (GETARG_Ax(c)>>7)&0x1f,
             (GETARG_Ax(c)>>2)&0x1f,
             (GETARG_Ax(c)>>1)&0x1,
             GETARG_Ax(c) & 0x1);
      break;
    case OP_RETURN:
      printf("OP_RETURN\tR%d", GETARG_A(c));
      switch (GETARG_B(c)) {
      case OP_R_NORMAL:
        printf("\tnormal\t"); break;
      case OP_R_RETURN:
        printf("\treturn\t"); break;
      case OP_R_BREAK:
        printf("\tbreak\t"); break;
      default:
        printf("\tbroken\t"); break;
      }
      print_lv(mrb, irep, c, RA);
      break;
    case OP_BLKPUSH:
      printf("OP_BLKPUSH\tR%d\t%d:%d:%d:%d", GETARG_A(c),
             (GETARG_Bx(c)>>10)&0x3f,
             (GETARG_Bx(c)>>9)&0x1,
             (GETARG_Bx(c)>>4)&0x1f,
             (GETARG_Bx(c)>>0)&0xf);
      print_lv(mrb, irep, c, RA);
      break;

    case OP_LAMBDA:
      printf("OP_LAMBDA\tR%d\tI(%+d)\t", GETARG_A(c), GETARG_b(c)+1);
      switch (GETARG_c(c)) {
      case OP_L_METHOD:
        printf("method"); break;
      case OP_L_BLOCK:
        printf("block"); break;
      case OP_L_LAMBDA:
        printf("lambda"); break;
      }
      print_lv(mrb, irep, c, RA);
      break;
    case OP_RANGE:
      printf("OP_RANGE\tR%d\tR%d\t%d", GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_METHOD:
      printf("OP_METHOD\tR%d\t:%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]));
      print_lv(mrb, irep, c, RA);
      break;

    case OP_ADD:
      printf("OP_ADD\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_ADDI:
      printf("OP_ADDI\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_SUB:
      printf("OP_SUB\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_SUBI:
      printf("OP_SUBI\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_MUL:
      printf("OP_MUL\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_DIV:
      printf("OP_DIV\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_LT:
      printf("OP_LT\t\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_LE:
      printf("OP_LE\t\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_GT:
      printf("OP_GT\t\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_GE:
      printf("OP_GE\t\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;
    case OP_EQ:
      printf("OP_EQ\t\tR%d\t:%s\t%d\n", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]),
             GETARG_C(c));
      break;

    case OP_STOP:
      printf("OP_STOP\n");
      break;

    case OP_ARRAY:
      printf("OP_ARRAY\tR%d\tR%d\t%d", GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_ARYCAT:
      printf("OP_ARYCAT\tR%d\tR%d\t", GETARG_A(c), GETARG_B(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_ARYPUSH:
      printf("OP_ARYPUSH\tR%d\tR%d\t", GETARG_A(c), GETARG_B(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_AREF:
      printf("OP_AREF\tR%d\tR%d\t%d", GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_APOST:
      printf("OP_APOST\tR%d\t%d\t%d", GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_STRING:
      {
        mrb_value v = irep->pool[GETARG_Bx(c)];
        mrb_value s = mrb_str_dump(mrb, mrb_str_new(mrb, RSTRING_PTR(v), RSTRING_LEN(v)));
        printf("OP_STRING\tR%d\tL(%d)\t; %s", GETARG_A(c), GETARG_Bx(c), RSTRING_PTR(s));
      }
      print_lv(mrb, irep, c, RA);
      break;
    case OP_STRCAT:
      printf("OP_STRCAT\tR%d\tR%d\t", GETARG_A(c), GETARG_B(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_HASH:
      printf("OP_HASH\tR%d\tR%d\t%d", GETARG_A(c), GETARG_B(c), GETARG_C(c));
      print_lv(mrb, irep, c, RAB);
      break;

    case OP_OCLASS:
      printf("OP_OCLASS\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_CLASS:
      printf("OP_CLASS\tR%d\t:%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_MODULE:
      printf("OP_MODULE\tR%d\t:%s", GETARG_A(c),
             mrb_sym2name(mrb, irep->syms[GETARG_B(c)]));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_EXEC:
      printf("OP_EXEC\tR%d\tI(%+d)", GETARG_A(c), GETARG_Bx(c)+1);
      print_lv(mrb, irep, c, RA);
      break;
    case OP_SCLASS:
      printf("OP_SCLASS\tR%d\tR%d\t", GETARG_A(c), GETARG_B(c));
      print_lv(mrb, irep, c, RAB);
      break;
    case OP_TCLASS:
      printf("OP_TCLASS\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_ERR:
      {
        mrb_value v = irep->pool[GETARG_Bx(c)];
        mrb_value s = mrb_str_dump(mrb, mrb_str_new(mrb, RSTRING_PTR(v), RSTRING_LEN(v)));
        printf("OP_ERR\t%s\n", RSTRING_PTR(s));
      }
      break;
    case OP_EPUSH:
      printf("OP_EPUSH\t:I(%+d)\n", GETARG_Bx(c)+1);
      break;
    case OP_ONERR:
      printf("OP_ONERR\t%03d\n", i+GETARG_sBx(c));
      break;
    case OP_RESCUE:
      {
        int a = GETARG_A(c);
        int b = GETARG_B(c);
        int cnt = GETARG_C(c);

        if (b == 0) {
          printf("OP_RESCUE\tR%d\t\t%s", a, cnt ? "cont" : "");
          print_lv(mrb, irep, c, RA);
          break;
        }
        else {
          printf("OP_RESCUE\tR%d\tR%d\t%s", a, b, cnt ? "cont" : "");
          print_lv(mrb, irep, c, RAB);
          break;
        }
      }
      break;
    case OP_RAISE:
      printf("OP_RAISE\tR%d\t\t", GETARG_A(c));
      print_lv(mrb, irep, c, RA);
      break;
    case OP_POPERR:
      printf("OP_POPERR\t%d\t\t\n", GETARG_A(c));
      break;
    case OP_EPOP:
      printf("OP_EPOP\t%d\n", GETARG_A(c));
      break;

    default:
      printf("OP_unknown %d\t%d\t%d\t%d\n", GET_OPCODE(c),
             GETARG_A(c), GETARG_B(c), GETARG_C(c));
      break;
    }
    mrb_gc_arena_restore(mrb, ai);
  }
  printf("\n");
#endif
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

void
mrb_codedump_all(mrb_state *mrb, struct RProc *proc)
{
  codedump_recur(mrb, proc->body.irep);
}
