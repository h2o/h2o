/*
** cmdmisc.c - mruby debugger miscellaneous command functions
**
*/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "apilist.h"
#include <mruby/compile.h>

typedef struct help_msg {
  const char *cmd1;
  const char *cmd2;
  const char *short_msg;
  const char *long_msg;
} help_msg;

static help_msg help_msg_list[] = {
  {
    "b[reak]", NULL, "Set breakpoint",
    "Usage: break [file:]line\n"
    "       break [class:]method\n"
    "\n"
    "Set breakpoint at specified line or method.\n"
    "If \'[file:]line\' is specified, break at start of code for that line (in a file).\n"
    "If \'[class:]method\' is specified, break at start of code for that method (of the class).\n"
  },
  {
    "c[ontinue]", NULL, "Continue program being debugged",
    "Usage: continue [N]\n"
    "\n"
    "Continue program stopped by a breakpoint.\n"
    "If N, which is non negative value, is passed,\n"
    "proceed program until the N-th breakpoint is coming.\n"
    "If N is not passed, N is assumed 1.\n"
  },
  {
    "d[elete]", NULL, "Delete some breakpoints",
    "Usage: delete [bpno1 [bpno2 [... [bpnoN]]]]\n"
    "\n"
    "Delete some breakpoints.\n"
    "Arguments are breakpoint numbers with spaces in between.\n"
    "To delete all breakpoints, give no argument.\n"
  },
  {
    "dis[able]", NULL, "Disable some breakpoints",
    "Usage: disable [bpno1 [bpno2 [... [bpnoN]]]]\n"
    "\n"
    "Disable some breakpoints.\n"
    "Arguments are breakpoint numbers with spaces in between.\n"
    "To disable all breakpoints, give no argument.\n"
  },
  {
    "en[able]", NULL, "Enable some breakpoints",
    "Usage: enable [bpno1 [bpno2 [... [bpnoN]]]]\n"
    "\n"
    "Enable some breakpoints.\n"
    "Arguments are breakpoint numbers with spaces in between.\n"
    "To enable all breakpoints, give no argument.\n"
  },
  {
    "ev[al]", NULL, "Evaluate expression",
    "Usage: eval expr\n"
    "\n"
    "It evaluates and prints the value of the mruby expression.\n"
    "This is equivalent to the \'print\' command.\n"
  },
  {
    "h[elp]", NULL, "Print this help",
    "Usage: help [command]\n"
    "\n"
    "With no arguments, help displays a short list of commands.\n"
    "With a command name as help argument, help displays how to use that command.\n"
  },
  {
    "i[nfo]", "b[reakpoints]", "Status of breakpoints",
    "Usage: info breakpoints [bpno1 [bpno2 [... [bpnoN]]]]\n"
    "\n"
    "Status of specified breakpoints (all user-settable breakpoints if no argument).\n"
    "Arguments are breakpoint numbers with spaces in between.\n"
  },
  {
    "i[nfo]", "l[ocals]", "Print name of local variables",
    "Usage: info locals\n"
    "\n"
    "Print name of local variables.\n"
  },
  {
    "l[ist]", NULL, "List specified line",
    "Usage: list\n"
    "       list first[,last]\n"
    "       list filename:first[,last]\n"
    "\n"
    "Print lines from a source file.\n"
    "\n"
    "With first and last, list prints lines from first to last.\n"
    "When last is empty, it stands for ten lines away from first.\n"
    "With filename, list prints lines in the specified source file.\n"
  },
  {
    "p[rint]", NULL, "Print value of expression",
    "Usage: print expr\n"
    "\n"
    "It evaluates and prints the value of the mruby expression.\n"
    "This is equivalent to the \'eval\' command.\n"
  },
  {
    "q[uit]", NULL, "Exit mrdb",
    "Usage: quit\n"
    "\n"
    "Exit mrdb.\n"
  },
  {
    "r[un]", NULL, "Start debugged program",
    "Usage: run\n"
    "\n"
    "Start debugged program.\n"
  },
  {
    "s[tep]", NULL, "Step program until it reaches a different source line",
    "Usage: step\n"
    "\n"
    "Step program until it reaches a different source line.\n"
  },
  { NULL, NULL, NULL, NULL }
};

typedef struct listcmd_parser_state {
  mrb_bool parse_error;
  mrb_bool has_line_min;
  mrb_bool has_line_max;
  char *filename;
  uint16_t line_min;
  uint16_t line_max;
} listcmd_parser_state;

static listcmd_parser_state*
listcmd_parser_state_new(mrb_state *mrb)
{
  listcmd_parser_state *st = (listcmd_parser_state*)mrb_malloc(mrb, sizeof(listcmd_parser_state));
  memset(st, 0, sizeof(listcmd_parser_state));
  return st;
}

static void
listcmd_parser_state_free(mrb_state *mrb, listcmd_parser_state *st)
{
  if (st != NULL) {
    if (st->filename != NULL) {
      mrb_free(mrb, st->filename);
    }
    mrb_free(mrb, st);
  }
}

static mrb_bool
parse_uint(char **sp, uint16_t *n)
{
  char *p;
  int i;

  if (*sp == NULL || **sp == '\0') {
    return FALSE;
  }

  for (p = *sp; *p != '\0' && ISDIGIT(*p); p++) ;

  if (p != *sp && (i = atoi(*sp)) >= 0) {
    *n = (uint16_t)i;
    *sp = p;
    return TRUE;
  }
  return FALSE;
}

static mrb_bool
skip_char(char **sp, char c)
{
  if (*sp != NULL && **sp == c) {
    ++*sp;
    return TRUE;
  }
  return FALSE;
}

static mrb_bool
parse_lineno(mrb_state *mrb, char **sp, listcmd_parser_state *st)
{
  if (*sp == NULL || **sp == '\0') {
    return FALSE;
  }

  st->has_line_min = FALSE;
  st->has_line_max = FALSE;

  if (parse_uint(sp, &st->line_min)) {
    st->has_line_min = TRUE;
  }
  else {
    return FALSE;
  }

  if (skip_char(sp, ',')) {
    if (parse_uint(sp, &st->line_max)) {
      st->has_line_max = TRUE;
    }
    else {
      st->parse_error = TRUE;
      return FALSE;
    }
  }
  return TRUE;
}

static mrb_bool
parse_filename(mrb_state *mrb, char **sp, listcmd_parser_state *st)
{
  char *p;
  int len;

  if (st->filename != NULL) {
    mrb_free(mrb, st->filename);
    st->filename = NULL;
  }

  if ((p = strchr(*sp, ':')) != NULL) {
    len = p - *sp;
  }
  else {
    len = strlen(*sp);
  }

  if (len > 0) {
    st->filename = (char*)mrb_malloc(mrb, len + 1);
    strncpy(st->filename, *sp, len);
    st->filename[len] = '\0';
    *sp += len;
    return TRUE;
  }
  else {
    return FALSE;
  }
}

char*
replace_ext(mrb_state *mrb, const char *filename, const char *ext)
{
  size_t len;
  const char *p;
  char *s;

  if (filename == NULL) {
    return NULL;
  }

  if ((p = strrchr(filename, '.')) != NULL && strchr(p, '/') == NULL) {
    len = p - filename;
  }
  else {
    len = strlen(filename);
  }

  s = (char*)mrb_malloc(mrb, len + strlen(ext) + 1);
  memset(s, '\0', len + strlen(ext) + 1);
  strncpy(s, filename, len);
  strcat(s, ext);

  return s;
}

static mrb_bool
parse_listcmd_args(mrb_state *mrb, mrdb_state *mrdb, listcmd_parser_state *st)
{
  char *p;

  switch (mrdb->wcnt) {
  case 2:
    p = mrdb->words[1];

    /* mrdb->words[1] ::= <lineno> | <filename> ':' <lineno> | <filename> */
    if (!parse_lineno(mrb, &p, st)) {
      if (parse_filename(mrb, &p, st)) {
        if (skip_char(&p, ':')) {
          if (!parse_lineno(mrb, &p, st)) {
            st->parse_error = TRUE;
          }
        }
      }
      else {
        st->parse_error = TRUE;
      }
    }
    if (*p != '\0') {
      st->parse_error = TRUE;
    }
    break;
  case 1:
  case 0:
    /* do nothing */
    break;
  default:
    st->parse_error = TRUE;
    printf("too many arguments\n");
    break;
  }

  if (!st->parse_error) {
    if (!st->has_line_min) {
      st->line_min = (!st->filename && mrdb->dbg->prvline > 0) ? mrdb->dbg->prvline : 1;
    }

    if (!st->has_line_max) {
      st->line_max = st->line_min + 9;
    }

    if (st->filename == NULL) {
      if (mrdb->dbg->prvfile && strcmp(mrdb->dbg->prvfile, "-")) {
        st->filename = replace_ext(mrb, mrdb->dbg->prvfile, ".rb");
      }
    }
  }

  if (st->parse_error || st->filename == NULL) {
    return FALSE;
  }

  return TRUE;
}

static mrb_bool
check_cmd_pattern(const char *pattern, const char *cmd)
{
  const char *lbracket, *rbracket, *p, *q;

  if (pattern == NULL && cmd == NULL) {
    return TRUE;
  }
  if (pattern == NULL || cmd == NULL) {
    return FALSE;
  }
  if ((lbracket = strchr(pattern, '[')) == NULL) {
    return !strcmp(pattern, cmd);
  }
  if ((rbracket = strchr(pattern, ']')) == NULL) {
    return FALSE;
  }
  if (strncmp(pattern, cmd, lbracket - pattern)) {
    return FALSE;
  }

  p = lbracket + 1;
  q = (char *)cmd + (lbracket - pattern);

  for ( ; p < rbracket && *q != '\0'; p++, q++) {
    if (*p != *q) {
      break;
    }
  }
  return *q == '\0';
}

static help_msg*
get_help_msg(char *cmd1, char *cmd2)
{
  help_msg *p;

  if (cmd1 == NULL) {
    return NULL;
  }
  for (p = help_msg_list; p->cmd1 != NULL; p++) {
    if (check_cmd_pattern(p->cmd1, cmd1) && check_cmd_pattern(p->cmd2, cmd2)) {
      return p;
    }
  }
  return NULL;
}

static mrb_bool
show_short_help(void)
{
  help_msg *p;

  printf("Commands\n");

  for (p = help_msg_list; p->cmd1 != NULL; p++) {
    if (p->cmd2 == NULL) {
      printf("  %s -- %s\n", p->cmd1, p->short_msg);
    }
    else {
      printf("  %s %s -- %s\n", p->cmd1, p->cmd2, p->short_msg);
    }
  }
  return TRUE;
}

static mrb_bool
show_long_help(char *cmd1, char *cmd2)
{
  help_msg *help;

  if ((help = get_help_msg(cmd1, cmd2)) == NULL) {
    return FALSE;
  }
  printf("%s", help->long_msg);
  return TRUE;
}

dbgcmd_state
dbgcmd_list(mrb_state *mrb, mrdb_state *mrdb)
{
  char *filename;
  listcmd_parser_state *st = listcmd_parser_state_new(mrb);

  if (parse_listcmd_args(mrb, mrdb, st)) {
    if ((filename = mrb_debug_get_source(mrb, mrdb, mrdb->srcpath, st->filename)) == NULL) {
      filename = st->filename;
    }
    mrb_debug_list(mrb, mrdb->dbg, filename, st->line_min, st->line_max);

    if (filename != NULL && filename != st->filename) {
      mrb_free(mrb, filename);
    }
    listcmd_parser_state_free(mrb, st);
  }

  return DBGST_PROMPT;
}

dbgcmd_state
dbgcmd_help(mrb_state *mrb, mrdb_state *mrdb)
{
  mrb_bool is_valid;
  int i;

  switch (mrdb->wcnt) {
  case 0:
  case 1:
    is_valid = show_short_help();
    break;
  case 2:
    is_valid = show_long_help(mrdb->words[1], NULL);
    break;
  case 3:
    is_valid = show_long_help(mrdb->words[1], mrdb->words[2]);
    break;
  default:
    is_valid = FALSE;
    break;
  }

  if (!is_valid) {
    printf("Invalid command \"");
    for (i = 1; i < mrdb->wcnt; i++) {
      printf("%s%s", i == 1 ? "" : " ", mrdb->words[i]);
    }
    printf("\". Try \"help\".\n");
  }

  return DBGST_PROMPT;
}

dbgcmd_state
dbgcmd_quit(mrb_state *mrb, mrdb_state *mrdb)
{
  switch (mrdb->dbg->xm) {
  case DBG_RUN:
  case DBG_STEP:
  case DBG_NEXT:
    while (1) {
      char c;
      int buf;

      printf("The program is running.  Exit anyway? (y or n) ");
      fflush(stdout);

      if ((buf = getchar()) == EOF) {
        mrdb->dbg->xm = DBG_QUIT;
        break;
      }
      c = buf;
      while (buf != '\n' && (buf = getchar()) != EOF) ;

      if (c == 'y' || c == 'Y') {
        mrdb->dbg->xm = DBG_QUIT;
        break;
      }
      else if (c == 'n' || c == 'N') {
        break;
      }
      else {
        printf("Please answer y or n.\n");
      }
    }
    break;
  default:
    mrdb->dbg->xm = DBG_QUIT;
    break;
  }

  if (mrdb->dbg->xm == DBG_QUIT) {
    struct RClass *exc;
    exc = mrb_define_class(mrb, "DebuggerExit", mrb->eException_class);
    mrb_raise(mrb, exc, "Exit mrdb.");
  }
  return DBGST_PROMPT;
}
