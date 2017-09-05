/*
** mrdb.c - mruby debugger
**
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <mruby.h>
#include <mruby/dump.h>
#include <mruby/debug.h>
#include <mruby/class.h>
#include <mruby/opcode.h>
#include <mruby/variable.h>

#include "mrdb.h"
#include "apibreak.h"
#include "apilist.h"

void mrdb_state_free(mrb_state *);

static mrb_debug_context *_debug_context = NULL;
static mrdb_state *_mrdb_state = NULL;

struct _args {
  FILE *rfp;
  char* fname;
  char* srcpath;
  int argc;
  char** argv;
  mrb_bool mrbfile : 1;
};

typedef struct debug_command {
  const char *cmd1;
  const char *cmd2;
  uint8_t len1;
  uint8_t len2;
  uint8_t div;
  debug_command_id id;
  debug_command_func func;
} debug_command;

static const debug_command debug_command_list[] = {
  {"break",     NULL,           1, 0, 0, DBGCMD_BREAK,          dbgcmd_break},           /* b[reak] */
  {"continue",  NULL,           1, 0, 0, DBGCMD_CONTINUE,       dbgcmd_continue},        /* c[ontinue] */
  {"delete",    NULL,           1, 0, 1, DBGCMD_DELETE,         dbgcmd_delete},          /* d[elete] */
  {"disable",   NULL,           3, 0, 1, DBGCMD_DISABLE,        dbgcmd_disable},         /* dis[able] */
  {"enable",    NULL,           2, 0, 1, DBGCMD_ENABLE,         dbgcmd_enable},          /* en[able] */
  {"eval",      NULL,           2, 0, 0, DBGCMD_EVAL,           dbgcmd_eval},            /* ev[al] */
  {"help",      NULL,           1, 0, 1, DBGCMD_HELP,           dbgcmd_help},            /* h[elp] */
  {"info",      "breakpoints",  1, 1, 1, DBGCMD_INFO_BREAK,     dbgcmd_info_break},      /* i[nfo] b[reakpoints] */
  {"list",      NULL,           1, 0, 1, DBGCMD_LIST,           dbgcmd_list},            /* l[ist] */
  {"print",     NULL,           1, 0, 0, DBGCMD_PRINT,          dbgcmd_print},           /* p[rint] */
  {"quit",      NULL,           1, 0, 0, DBGCMD_QUIT,           dbgcmd_quit},            /* q[uit] */
  {"run",       NULL,           1, 0, 0, DBGCMD_RUN,            dbgcmd_run},             /* r[un] */
  {"step",      NULL,           1, 0, 1, DBGCMD_STEP,           dbgcmd_step},            /* s[tep] */
  {"next",      NULL,           1, 0, 1, DBGCMD_NEXT,           dbgcmd_next},            /* n[ext] */
  {NULL}
};


static void
usage(const char *name)
{
  static const char *const usage_msg[] = {
  "switches:",
  "-b           load and execute RiteBinary (mrb) file",
  "-d           specify source directory",
  "--version    print the version",
  "--copyright  print the copyright",
  NULL
  };
  const char *const *p = usage_msg;

  printf("Usage: %s [switches] programfile\n", name);
  while (*p) {
    printf("  %s\n", *p++);
  }
}

static int
parse_args(mrb_state *mrb, int argc, char **argv, struct _args *args)
{
  char **origargv = argv;
  static const struct _args args_zero = { 0 };

  *args = args_zero;

  for (argc--,argv++; argc > 0; argc--,argv++) {
    char *item;
    if (argv[0][0] != '-') break;

    item = argv[0] + 1;
    switch (*item++) {
    case 'b':
      args->mrbfile = TRUE;
      break;
    case 'd':
      if (item[0]) {
        goto append_srcpath;
      }
      else if (argc > 1) {
        argc--; argv++;
        item = argv[0];
append_srcpath:
        if (!args->srcpath) {
          size_t buflen;
          char *buf;

          buflen = strlen(item) + 1;
          buf = (char *)mrb_malloc(mrb, buflen);
          memcpy(buf, item, buflen);
          args->srcpath = buf;
        }
        else {
          size_t srcpathlen;
          size_t itemlen;

          srcpathlen = strlen(args->srcpath);
          itemlen = strlen(item);
          args->srcpath =
            (char *)mrb_realloc(mrb, args->srcpath, srcpathlen + itemlen + 2);
          args->srcpath[srcpathlen] = '\n';
          memcpy(args->srcpath + srcpathlen + 1, item, itemlen + 1);
        }
      }
      else {
        printf("%s: No path specified for -d\n", *origargv);
        return EXIT_SUCCESS;
      }
      break;
    case '-':
      if (strcmp((*argv) + 2, "version") == 0) {
        mrb_show_version(mrb);
        exit(EXIT_SUCCESS);
      }
      else if (strcmp((*argv) + 2, "copyright") == 0) {
        mrb_show_copyright(mrb);
        exit(EXIT_SUCCESS);
      }
    default:
      return EXIT_FAILURE;
    }
  }

  if (args->rfp == NULL) {
    if (*argv == NULL) {
      printf("%s: Program file not specified.\n", *origargv);
      return EXIT_FAILURE;
    }
    else {
      args->rfp = fopen(argv[0], args->mrbfile ? "rb" : "r");
      if (args->rfp == NULL) {
        printf("%s: Cannot open program file. (%s)\n", *origargv, *argv);
        return EXIT_FAILURE;
      }
      args->fname = argv[0];
      argc--; argv++;
    }
  }
  args->argv = (char **)mrb_realloc(mrb, args->argv, sizeof(char*) * (argc + 1));
  memcpy(args->argv, argv, (argc+1) * sizeof(char*));
  args->argc = argc;

  return EXIT_SUCCESS;
}

static void
cleanup(mrb_state *mrb, struct _args *args)
{
  if (args->rfp)
    fclose(args->rfp);
  if (args->srcpath)
    mrb_free(mrb, args->srcpath);
  if (args->argv)
    mrb_free(mrb, args->argv);
  mrdb_state_free(mrb);
  mrb_close(mrb);
}

static mrb_debug_context*
mrb_debug_context_new(mrb_state *mrb)
{
  mrb_debug_context *dbg = mrb_malloc(mrb, sizeof(mrb_debug_context));

  memset(dbg, 0, sizeof(mrb_debug_context));

  dbg->xm = DBG_INIT;
  dbg->xphase = DBG_PHASE_BEFORE_RUN;
  dbg->next_bpno = 1;

  return dbg;
}

mrb_debug_context*
mrb_debug_context_get(mrb_state *mrb)
{
  if (!_debug_context) {
    _debug_context = mrb_debug_context_new(mrb);
  }
  return _debug_context;
}

void
mrb_debug_context_set(mrb_debug_context *dbg)
{
  _debug_context = dbg;
}

void
mrb_debug_context_free(mrb_state *mrb)
{
  if (_debug_context) {
    mrb_debug_delete_break_all(mrb, _debug_context);
    mrb_free(mrb, _debug_context);
    _debug_context = NULL;
  }
}

static mrdb_state*
mrdb_state_new(mrb_state *mrb)
{
  mrdb_state *mrdb = mrb_malloc(mrb, sizeof(mrdb_state));

  memset(mrdb, 0, sizeof(mrdb_state));

  mrdb->dbg = mrb_debug_context_get(mrb);
  mrdb->command = mrb_malloc(mrb, MAX_COMMAND_LINE+1);
  mrdb->print_no = 1;

  return mrdb;
}

mrdb_state*
mrdb_state_get(mrb_state *mrb)
{
  if (!_mrdb_state) {
    _mrdb_state = mrdb_state_new(mrb);
  }
  return _mrdb_state;
}

void
mrdb_state_set(mrdb_state *mrdb)
{
  _mrdb_state = mrdb;
}

void
mrdb_state_free(mrb_state *mrb)
{
  mrb_debug_context_free(mrb);
  if (_mrdb_state) {
    mrb_free(mrb, _mrdb_state->command);
    mrb_free(mrb, _mrdb_state);
    _mrdb_state = NULL;
  }
}

static char*
get_command(mrb_state *mrb, mrdb_state *mrdb)
{
  int i;
  int c;

  for (i=0; i<MAX_COMMAND_LINE; i++) {
    if ((c=getchar()) == EOF || c == '\n') break;
    mrdb->command[i] = c;
  }

  if (i == 0 && feof(stdin)) {
    clearerr(stdin);
    strcpy(mrdb->command, "quit");
    i += sizeof("quit") - 1;
  }

  if (i == MAX_COMMAND_LINE) {
    for ( ; (c=getchar()) != EOF && c !='\n'; i++) ;
  }

  if (i > MAX_COMMAND_LINE) {
    printf("command line too long.\n");
    i = 0; /* discard command data */
  }
  mrdb->command[i] = '\0';

  return mrdb->command;
}

static char*
pick_out_word(mrb_state *mrb, char **pp)
{
  char *ps;

  for (ps=*pp; ISBLANK(*ps); ps++) ;
  if (*ps == '\0') {
    return NULL;
  }

  if (*ps == '\"' || *ps == '\'') {
    *pp = strchr(ps+1, *ps);
    if (*pp) (*pp)++;
  }
  else {
    *pp = strpbrk(ps, " \t");
  }

  if (!*pp) {
    *pp = ps + strlen(ps);
  }

  if (**pp != '\0') {
    **pp = '\0';
    (*pp)++;
  }

  return ps;
}

static debug_command*
parse_command(mrb_state *mrb, mrdb_state *mrdb, char *buf)
{
  debug_command *cmd = NULL;
  char *p = buf;
  size_t wlen;

  /* get word #1 */
  mrdb->words[0] = pick_out_word(mrb, &p);
  if (!mrdb->words[0]) {
    return NULL;
  }
  mrdb->wcnt = 1;
  /* set remain parameter */
  for ( ; *p && ISBLANK(*p); p++) ;
  if (*p) {
    mrdb->words[mrdb->wcnt++] = p;
  }

  /* check word #1 */
  for (cmd=(debug_command*)debug_command_list; cmd->cmd1; cmd++) {
    wlen = strlen(mrdb->words[0]);
    if (wlen >= cmd->len1 &&
        strncmp(mrdb->words[0], cmd->cmd1, wlen) == 0) {
      break;
    }
  }

  if (cmd->cmd2) {
    if (mrdb->wcnt > 1) {
      /* get word #2 */
      mrdb->words[1] = pick_out_word(mrb, &p);
      if (mrdb->words[1]) {
        /* update remain parameter */
        for ( ; *p && ISBLANK(*p); p++) ;
        if (*p) {
          mrdb->words[mrdb->wcnt++] = p;
        }
      }
    }

    /* check word #1,#2 */
    for ( ; cmd->cmd1; cmd++) {
      wlen = strlen(mrdb->words[0]);
      if (wlen < cmd->len1 ||
          strncmp(mrdb->words[0], cmd->cmd1, wlen)) {
        continue;
      }

      if (!cmd->cmd2) break;          /* word #1 only */

      if (mrdb->wcnt == 1) continue;  /* word #2 not specified */

      wlen = strlen(mrdb->words[1]);
      if (wlen >= cmd->len2 &&
          strncmp(mrdb->words[1], cmd->cmd2, wlen) == 0) {
        break;  /* word #1 and #2 */
      }
    }
  }

  /* divide remain parameters */
  if (cmd->cmd1 && cmd->div) {
    p = mrdb->words[--mrdb->wcnt];
    for ( ; mrdb->wcnt<MAX_COMMAND_WORD; mrdb->wcnt++) {
      mrdb->words[mrdb->wcnt] = pick_out_word(mrb, &p);
      if (!mrdb->words[mrdb->wcnt]) {
        break;
      }
    }
  }

  return cmd->cmd1 ? cmd : NULL;
}

static void
print_info_stopped_break(mrb_state *mrb, mrdb_state *mrdb)
{
  mrb_debug_breakpoint bp;
  int32_t ret;
  uint16_t lineno;
  const char *file;
  const char *method_name;
  const char *class_name;

  ret = mrb_debug_get_break(mrb, mrdb->dbg, mrdb->dbg->stopped_bpno, &bp);
  if (ret == 0) {
    switch(bp.type) {
      case MRB_DEBUG_BPTYPE_LINE:
        file = bp.point.linepoint.file;
        lineno = bp.point.linepoint.lineno;
        printf("Breakpoint %d, at %s:%d\n", bp.bpno, file, lineno);
        break;
      case MRB_DEBUG_BPTYPE_METHOD:
        method_name = bp.point.methodpoint.method_name;
        class_name = bp.point.methodpoint.class_name;
        if (class_name == NULL) {
          printf("Breakpoint %d, %s\n", bp.bpno, method_name);
        }
        else {
          printf("Breakpoint %d, %s:%s\n", bp.bpno, class_name, method_name);
        }
        if (mrdb->dbg->isCfunc) {
          printf("Stopped before calling the C function.\n");
        }
        break;
      default:
        break;
    }
  }
}

static void
print_info_stopped_step_next(mrb_state *mrb, mrdb_state *mrdb)
{
  const char* file = mrdb->dbg->prvfile;
  uint16_t lineno = mrdb->dbg->prvline;
  printf("%s:%d\n", file, lineno);
}

static void
print_info_stopped_code(mrb_state *mrb, mrdb_state *mrdb)
{
  char* file = mrb_debug_get_source(mrb, mrdb, mrdb->srcpath, mrdb->dbg->prvfile);
  uint16_t lineno = mrdb->dbg->prvline;
  if (file != NULL) {
    mrb_debug_list(mrb, mrdb->dbg, file, lineno, lineno);
    mrb_free(mrb, file);
  }
}

static void
print_info_stopped(mrb_state *mrb, mrdb_state *mrdb)
{
  switch(mrdb->dbg->bm) {
    case BRK_BREAK:
      print_info_stopped_break(mrb, mrdb);
      print_info_stopped_code(mrb, mrdb);
      break;
    case BRK_STEP:
    case BRK_NEXT:
      print_info_stopped_step_next(mrb, mrdb);
      print_info_stopped_code(mrb, mrdb);
      break;
    default:
      break;
  }
}

static debug_command*
get_and_parse_command(mrb_state *mrb, mrdb_state *mrdb)
{
  debug_command *cmd = NULL;
  char *p;
  int i;

  while (!cmd) {
    for (p=NULL; !p || *p=='\0'; ) {
      printf("(%s:%d) ", mrdb->dbg->prvfile, mrdb->dbg->prvline);
      fflush(stdout);
      p = get_command(mrb, mrdb);
    }

    cmd = parse_command(mrb, mrdb, p);
#ifdef _DBG_MRDB_PARSER_
    for (i=0; i<mrdb->wcnt; i++) {
      printf("%d: %s\n", i, mrdb->words[i]);
    }
#endif
    if (!cmd) {
      printf("invalid command (");
      for (i=0; i<mrdb->wcnt; i++) {
        if (i>0) {
          printf(" ");
        }
        printf("%s", mrdb->words[i]);
      }
      puts(")");
    }
  }
  return cmd;
}

static int32_t
check_method_breakpoint(mrb_state *mrb, mrb_irep *irep, mrb_code *pc, mrb_value *regs)
{
  struct RClass* c;
  mrb_sym sym;
  int32_t bpno;
  mrb_bool isCfunc;

  mrb_debug_context *dbg = mrb_debug_context_get(mrb);

  isCfunc = FALSE;
  bpno = dbg->method_bpno;
  dbg->method_bpno = 0;

  switch(GET_OPCODE(*pc)) {
    case OP_SEND:
    case OP_SENDB:
      c = mrb_class(mrb, regs[GETARG_A(*pc)]);
      sym = irep->syms[GETARG_B(*pc)];
      break;
    case OP_SUPER:
      c = mrb->c->ci->target_class->super;
      sym = mrb->c->ci->mid;
      break;
    default:
      sym = 0;
      break;
  }
  if (sym != 0) {
    dbg->method_bpno = mrb_debug_check_breakpoint_method(mrb, dbg, c, sym, &isCfunc);
    if (isCfunc) {
      bpno = dbg->method_bpno;
      dbg->method_bpno = 0;
    }
  }
  dbg->isCfunc = isCfunc;
  return bpno;
}

static void
mrb_code_fetch_hook(mrb_state *mrb, mrb_irep *irep, mrb_code *pc, mrb_value *regs)
{
  const char *file;
  int32_t line;
  int32_t bpno;

  mrb_debug_context *dbg = mrb_debug_context_get(mrb);

  mrb_assert(dbg);

  dbg->irep = irep;
  dbg->pc   = pc;
  dbg->regs = regs;

  if (dbg->xphase == DBG_PHASE_RESTART) {
    dbg->root_irep = irep;
    dbg->prvfile = NULL;
    dbg->prvline = 0;
    dbg->prvci = NULL;
    dbg->xm = DBG_RUN;
    dbg->xphase = DBG_PHASE_RUNNING;
  }

  file = mrb_debug_get_filename(irep, pc - irep->iseq);
  line = mrb_debug_get_line(irep, pc - irep->iseq);

  switch (dbg->xm) {
  case DBG_STEP:
    if (!file || (dbg->prvfile == file && dbg->prvline == line)) {
      return;
    }
    dbg->method_bpno = 0;
    dbg->bm = BRK_STEP;
    break;

  case DBG_NEXT:
    if (!file || (dbg->prvfile == file && dbg->prvline == line)) {
      return;
    }
    if ((intptr_t)(dbg->prvci) < (intptr_t)(mrb->c->ci)) {
      return;
    }
    dbg->prvci = NULL;
    dbg->method_bpno = 0;
    dbg->bm = BRK_NEXT;
    break;

  case DBG_RUN:
    bpno = check_method_breakpoint(mrb, irep, pc, regs);
    if (bpno > 0) {
      dbg->stopped_bpno = bpno;
      dbg->bm = BRK_BREAK;
      break;
    }
    if (dbg->prvfile != file || dbg->prvline != line) {
      bpno = mrb_debug_check_breakpoint_line(mrb, dbg, file, line);
      if (bpno > 0) {
        dbg->stopped_bpno = bpno;
        dbg->bm = BRK_BREAK;
        break;
      }
    }
    dbg->prvfile = file;
    dbg->prvline = line;
    return;
  case DBG_INIT:
    dbg->root_irep = irep;
    dbg->bm = BRK_INIT;
    if (!file || line < 0) {
      puts("Cannot get debugging information.");
    }
    break;

  default:
    return;
  }

  dbg->prvfile = file;
  dbg->prvline = line;

  if (dbg->bm == BRK_BREAK && --dbg->ccnt > 0) {
    return;
  }
  dbg->break_hook(mrb, dbg);

  dbg->xphase = DBG_PHASE_RUNNING;
}

static mrdb_exemode
mrb_debug_break_hook(mrb_state *mrb, mrb_debug_context *dbg)
{
  debug_command *cmd;
  dbgcmd_state st = DBGST_CONTINUE;
  mrdb_state *mrdb = mrdb_state_get(mrb);

  print_info_stopped(mrb, mrdb);

  while (1) {
    cmd = get_and_parse_command(mrb, mrdb);
    mrb_assert(cmd);

    st = cmd->func(mrb, mrdb);

    if ((st == DBGST_CONTINUE) || (st == DBGST_RESTART)) break;
  }
  return dbg->xm;
}

int
main(int argc, char **argv)
{
  mrb_state *mrb = mrb_open();
  int n = -1;
  struct _args args;
  mrb_value v;
  mrdb_state *mrdb;
  mrdb_state *mrdb_backup;
  mrb_debug_context* dbg_backup;
  debug_command *cmd;

 l_restart:

  if (mrb == NULL) {
    fputs("Invalid mrb_state, exiting mruby\n", stderr);
    return EXIT_FAILURE;
  }

  /* parse command parameters */
  n = parse_args(mrb, argc, argv, &args);
  if (n == EXIT_FAILURE || args.rfp == NULL) {
    cleanup(mrb, &args);
    usage(argv[0]);
    return n;
  }

  /* initialize debugger information */
  mrdb = mrdb_state_get(mrb);
  mrb_assert(mrdb && mrdb->dbg);
  mrdb->srcpath = args.srcpath;

  if (mrdb->dbg->xm == DBG_QUIT) {
    mrdb->dbg->xphase = DBG_PHASE_RESTART;
  }
  else {
    mrdb->dbg->xphase = DBG_PHASE_BEFORE_RUN;
  }
  mrdb->dbg->xm = DBG_INIT;
  mrdb->dbg->ccnt = 1;

  /* setup hook functions */
  mrb->code_fetch_hook = mrb_code_fetch_hook;
  mrdb->dbg->break_hook = mrb_debug_break_hook;

  if (args.mrbfile) { /* .mrb */
    v = mrb_load_irep_file(mrb, args.rfp);
  }
  else {              /* .rb */
    mrbc_context *cc = mrbc_context_new(mrb);
    mrbc_filename(mrb, cc, args.fname);
    v = mrb_load_file_cxt(mrb, args.rfp, cc);
    mrbc_context_free(mrb, cc);
  }
  if (mrdb->dbg->xm == DBG_QUIT && !mrb_undef_p(v) && mrb->exc) {
    const char *classname = mrb_obj_classname(mrb, mrb_obj_value(mrb->exc));
    if (!strcmp(classname, "DebuggerExit")) {
      cleanup(mrb, &args);
      return 0;
    }
    if (!strcmp(classname, "DebuggerRestart")) {
      mrdb_backup = mrdb_state_get(mrb);
      dbg_backup = mrb_debug_context_get(mrb);

      mrdb_state_set(NULL);
      mrb_debug_context_set(NULL);

      cleanup(mrb, &args);
      mrb = mrb_open();

      mrdb_state_set(mrdb_backup);
      mrb_debug_context_set(dbg_backup);

      goto l_restart;
    }
  }
  puts("mruby application exited.");
  mrdb->dbg->xphase = DBG_PHASE_AFTER_RUN;
  if (!mrb_undef_p(v)) {
    if (mrb->exc) {
      mrb_print_error(mrb);
    }
    else {
      printf(" => ");
      mrb_p(mrb, v);
    }
  }

  mrdb->dbg->prvfile = "-";
  mrdb->dbg->prvline = 0;

  while (1) {
    cmd = get_and_parse_command(mrb, mrdb);
    mrb_assert(cmd);

    if (cmd->id == DBGCMD_QUIT) {
      break;
    }

    if ( cmd->func(mrb, mrdb) == DBGST_RESTART ) goto l_restart;
  }

  cleanup(mrb, &args);

  return 0;
}
