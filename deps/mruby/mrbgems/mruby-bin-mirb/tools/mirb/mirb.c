/*
** mirb - Embeddable Interactive Ruby Shell
**
** This program takes code from the user in
** an interactive way and executes it
** immediately. It's a REPL...
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <signal.h>
#include <setjmp.h>

#ifdef ENABLE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#define MIRB_ADD_HISTORY(line) add_history(line)
#define MIRB_READLINE(ch) readline(ch)
#define MIRB_WRITE_HISTORY(path) write_history(path)
#define MIRB_READ_HISTORY(path) read_history(path)
#define MIRB_USING_HISTORY() using_history()
#elif defined(ENABLE_LINENOISE)
#define ENABLE_READLINE
#include <linenoise.h>
#define MIRB_ADD_HISTORY(line) linenoiseHistoryAdd(line)
#define MIRB_READLINE(ch) linenoise(ch)
#define MIRB_WRITE_HISTORY(path) linenoiseHistorySave(path)
#define MIRB_READ_HISTORY(path) linenoiseHistoryLoad(history_path)
#define MIRB_USING_HISTORY()
#endif

#ifndef _WIN32
#define MIRB_SIGSETJMP(env) sigsetjmp(env, 1)
#define MIRB_SIGLONGJMP(env, val) siglongjmp(env, val)
#define SIGJMP_BUF sigjmp_buf
#else
#define MIRB_SIGSETJMP(env) setjmp(env)
#define MIRB_SIGLONGJMP(env, val) longjmp(env, val)
#define SIGJMP_BUF jmp_buf
#endif

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/proc.h>
#include <mruby/compile.h>
#include <mruby/string.h>

#ifdef ENABLE_READLINE

static const char history_file_name[] = ".mirb_history";

static char *
get_history_path(mrb_state *mrb)
{
  char *path = NULL;
  const char *home = getenv("HOME");

#ifdef _WIN32
  if (home != NULL) {
    home = getenv("USERPROFILE");
  }
#endif

  if (home != NULL) {
    int len = snprintf(NULL, 0, "%s/%s", home, history_file_name);
    if (len >= 0) {
      size_t size = len + 1;
      path = (char *)mrb_malloc_simple(mrb, size);
      if (path != NULL) {
        int n = snprintf(path, size, "%s/%s", home, history_file_name);
        if (n != len) {
          mrb_free(mrb, path);
          path = NULL;
        }
      }
    }
  }

  return path;
}

#endif

static void
p(mrb_state *mrb, mrb_value obj, int prompt)
{
  mrb_value val;

  val = mrb_funcall(mrb, obj, "inspect", 0);
  if (prompt) {
    if (!mrb->exc) {
      fputs(" => ", stdout);
    }
    else {
      val = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
    }
  }
  if (!mrb_string_p(val)) {
    val = mrb_obj_as_string(mrb, obj);
  }
  fwrite(RSTRING_PTR(val), RSTRING_LEN(val), 1, stdout);
  putc('\n', stdout);
}

/* Guess if the user might want to enter more
 * or if he wants an evaluation of his code now */
static mrb_bool
is_code_block_open(struct mrb_parser_state *parser)
{
  mrb_bool code_block_open = FALSE;

  /* check for heredoc */
  if (parser->parsing_heredoc != NULL) return TRUE;
  if (parser->heredoc_end_now) {
    parser->heredoc_end_now = FALSE;
    return FALSE;
  }

  /* check for unterminated string */
  if (parser->lex_strterm) return TRUE;

  /* check if parser error are available */
  if (0 < parser->nerr) {
    const char unexpected_end[] = "syntax error, unexpected $end";
    const char *message = parser->error_buffer[0].message;

    /* a parser error occur, we have to check if */
    /* we need to read one more line or if there is */
    /* a different issue which we have to show to */
    /* the user */

    if (strncmp(message, unexpected_end, sizeof(unexpected_end) - 1) == 0) {
      code_block_open = TRUE;
    }
    else if (strcmp(message, "syntax error, unexpected keyword_end") == 0) {
      code_block_open = FALSE;
    }
    else if (strcmp(message, "syntax error, unexpected tREGEXP_BEG") == 0) {
      code_block_open = FALSE;
    }
    return code_block_open;
  }

  switch (parser->lstate) {

  /* all states which need more code */

  case EXPR_BEG:
    /* beginning of a statement, */
    /* that means previous line ended */
    code_block_open = FALSE;
    break;
  case EXPR_DOT:
    /* a message dot was the last token, */
    /* there has to come more */
    code_block_open = TRUE;
    break;
  case EXPR_CLASS:
    /* a class keyword is not enough! */
    /* we need also a name of the class */
    code_block_open = TRUE;
    break;
  case EXPR_FNAME:
    /* a method name is necessary */
    code_block_open = TRUE;
    break;
  case EXPR_VALUE:
    /* if, elsif, etc. without condition */
    code_block_open = TRUE;
    break;

  /* now all the states which are closed */

  case EXPR_ARG:
    /* an argument is the last token */
    code_block_open = FALSE;
    break;

  /* all states which are unsure */

  case EXPR_CMDARG:
    break;
  case EXPR_END:
    /* an expression was ended */
    break;
  case EXPR_ENDARG:
    /* closing parenthese */
    break;
  case EXPR_ENDFN:
    /* definition end */
    break;
  case EXPR_MID:
    /* jump keyword like break, return, ... */
    break;
  case EXPR_MAX_STATE:
    /* don't know what to do with this token */
    break;
  default:
    /* this state is unexpected! */
    break;
  }

  return code_block_open;
}

struct _args {
  FILE *rfp;
  mrb_bool verbose      : 1;
  int argc;
  char** argv;
};

static void
usage(const char *name)
{
  static const char *const usage_msg[] = {
  "switches:",
  "-v           print version number, then run in verbose mode",
  "--verbose    run in verbose mode",
  "--version    print the version",
  "--copyright  print the copyright",
  NULL
  };
  const char *const *p = usage_msg;

  printf("Usage: %s [switches]\n", name);
  while (*p)
    printf("  %s\n", *p++);
}

static int
parse_args(mrb_state *mrb, int argc, char **argv, struct _args *args)
{
  static const struct _args args_zero = { 0 };

  *args = args_zero;

  for (argc--,argv++; argc > 0; argc--,argv++) {
    char *item;
    if (argv[0][0] != '-') break;

    item = argv[0] + 1;
    switch (*item++) {
    case 'v':
      if (!args->verbose) mrb_show_version(mrb);
      args->verbose = TRUE;
      break;
    case '-':
      if (strcmp((*argv) + 2, "version") == 0) {
        mrb_show_version(mrb);
        exit(EXIT_SUCCESS);
      }
      else if (strcmp((*argv) + 2, "verbose") == 0) {
        args->verbose = TRUE;
        break;
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
    if (*argv != NULL) {
      args->rfp = fopen(argv[0], "r");
      if (args->rfp == NULL) {
        printf("Cannot open program file. (%s)\n", *argv);
        return EXIT_FAILURE;
      }
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
  mrb_free(mrb, args->argv);
  mrb_close(mrb);
}

/* Print a short remark for the user */
static void
print_hint(void)
{
  printf("mirb - Embeddable Interactive Ruby Shell\n\n");
}

#ifndef ENABLE_READLINE
/* Print the command line prompt of the REPL */
static void
print_cmdline(int code_block_open)
{
  if (code_block_open) {
    printf("* ");
  }
  else {
    printf("> ");
  }
  fflush(stdout);
}
#endif

void mrb_codedump_all(mrb_state*, struct RProc*);

static int
check_keyword(const char *buf, const char *word)
{
  const char *p = buf;
  size_t len = strlen(word);

  /* skip preceding spaces */
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  /* check keyword */
  if (strncmp(p, word, len) != 0) {
    return 0;
  }
  p += len;
  /* skip trailing spaces */
  while (*p) {
    if (!isspace((unsigned char)*p)) return 0;
    p++;
  }
  return 1;
}


#ifndef ENABLE_READLINE
volatile sig_atomic_t input_canceled = 0;
void
ctrl_c_handler(int signo)
{
  input_canceled = 1;
}
#else
SIGJMP_BUF ctrl_c_buf;
void
ctrl_c_handler(int signo)
{
  MIRB_SIGLONGJMP(ctrl_c_buf, 1);
}
#endif

int
main(int argc, char **argv)
{
  char ruby_code[4096] = { 0 };
  char last_code_line[1024] = { 0 };
#ifndef ENABLE_READLINE
  int last_char;
  size_t char_index;
#else
  char *history_path;
  char* line;
#endif
  mrbc_context *cxt;
  struct mrb_parser_state *parser;
  mrb_state *mrb;
  mrb_value result;
  struct _args args;
  mrb_value ARGV;
  int n;
  int i;
  mrb_bool code_block_open = FALSE;
  int ai;
  unsigned int stack_keep = 0;

  /* new interpreter instance */
  mrb = mrb_open();
  if (mrb == NULL) {
    fputs("Invalid mrb interpreter, exiting mirb\n", stderr);
    return EXIT_FAILURE;
  }

  n = parse_args(mrb, argc, argv, &args);
  if (n == EXIT_FAILURE) {
    cleanup(mrb, &args);
    usage(argv[0]);
    return n;
  }

  ARGV = mrb_ary_new_capa(mrb, args.argc);
  for (i = 0; i < args.argc; i++) {
    char* utf8 = mrb_utf8_from_locale(args.argv[i], -1);
    if (utf8) {
      mrb_ary_push(mrb, ARGV, mrb_str_new_cstr(mrb, utf8));
      mrb_utf8_free(utf8);
    }
  }
  mrb_define_global_const(mrb, "ARGV", ARGV);

#ifdef ENABLE_READLINE
  history_path = get_history_path(mrb);
  if (history_path == NULL) {
    fputs("failed to get history path\n", stderr);
    mrb_close(mrb);
    return EXIT_FAILURE;
  }

  MIRB_USING_HISTORY();
  MIRB_READ_HISTORY(history_path);
#endif

  print_hint();

  cxt = mrbc_context_new(mrb);
  cxt->capture_errors = TRUE;
  cxt->lineno = 1;
  mrbc_filename(mrb, cxt, "(mirb)");
  if (args.verbose) cxt->dump_result = TRUE;

  ai = mrb_gc_arena_save(mrb);

  while (TRUE) {
    char *utf8;

    if (args.rfp) {
      if (fgets(last_code_line, sizeof(last_code_line)-1, args.rfp) != NULL)
        goto done;
      break;
    }

#ifndef ENABLE_READLINE
    print_cmdline(code_block_open);

    signal(SIGINT, ctrl_c_handler);
    char_index = 0;
    while ((last_char = getchar()) != '\n') {
      if (last_char == EOF) break;
      if (char_index >= sizeof(last_code_line)-2) {
        fputs("input string too long\n", stderr);
        continue;
      }
      last_code_line[char_index++] = last_char;
    }
    signal(SIGINT, SIG_DFL);
    if (input_canceled) {
      ruby_code[0] = '\0';
      last_code_line[0] = '\0';
      code_block_open = FALSE;
      puts("^C");
      input_canceled = 0;
      continue;
    }
    if (last_char == EOF) {
      fputs("\n", stdout);
      break;
    }

    last_code_line[char_index++] = '\n';
    last_code_line[char_index] = '\0';
#else
    if (MIRB_SIGSETJMP(ctrl_c_buf) == 0) {
      ;
    }
    else {
      ruby_code[0] = '\0';
      last_code_line[0] = '\0';
      code_block_open = FALSE;
      puts("^C");
    }
    signal(SIGINT, ctrl_c_handler);
    line = MIRB_READLINE(code_block_open ? "* " : "> ");
    signal(SIGINT, SIG_DFL);

    if (line == NULL) {
      printf("\n");
      break;
    }
    if (strlen(line) > sizeof(last_code_line)-2) {
      fputs("input string too long\n", stderr);
      continue;
    }
    strcpy(last_code_line, line);
    strcat(last_code_line, "\n");
    MIRB_ADD_HISTORY(line);
    free(line);
#endif

done:

    if (code_block_open) {
      if (strlen(ruby_code)+strlen(last_code_line) > sizeof(ruby_code)-1) {
        fputs("concatenated input string too long\n", stderr);
        continue;
      }
      strcat(ruby_code, last_code_line);
    }
    else {
      if (check_keyword(last_code_line, "quit") || check_keyword(last_code_line, "exit")) {
        break;
      }
      strcpy(ruby_code, last_code_line);
    }

    utf8 = mrb_utf8_from_locale(ruby_code, -1);
    if (!utf8) abort();

    /* parse code */
    parser = mrb_parser_new(mrb);
    if (parser == NULL) {
      fputs("create parser state error\n", stderr);
      break;
    }
    parser->s = utf8;
    parser->send = utf8 + strlen(utf8);
    parser->lineno = cxt->lineno;
    mrb_parser_parse(parser, cxt);
    code_block_open = is_code_block_open(parser);
    mrb_utf8_free(utf8);

    if (code_block_open) {
      /* no evaluation of code */
    }
    else {
      if (0 < parser->nerr) {
        /* syntax error */
        printf("line %d: %s\n", parser->error_buffer[0].lineno, parser->error_buffer[0].message);
      }
      else {
        /* generate bytecode */
        struct RProc *proc = mrb_generate_code(mrb, parser);
        if (proc == NULL) {
          fputs("codegen error\n", stderr);
          mrb_parser_free(parser);
          break;
        }

        if (args.verbose) {
          mrb_codedump_all(mrb, proc);
        }
        /* pass a proc for evaluation */
        /* evaluate the bytecode */
        result = mrb_vm_run(mrb,
            proc,
            mrb_top_self(mrb),
            stack_keep);
        stack_keep = proc->body.irep->nlocals;
        /* did an exception occur? */
        if (mrb->exc) {
          p(mrb, mrb_obj_value(mrb->exc), 0);
          mrb->exc = 0;
        }
        else {
          /* no */
          if (!mrb_respond_to(mrb, result, mrb_intern_lit(mrb, "inspect"))){
            result = mrb_any_to_s(mrb, result);
          }
          p(mrb, result, 1);
        }
      }
      ruby_code[0] = '\0';
      last_code_line[0] = '\0';
      mrb_gc_arena_restore(mrb, ai);
    }
    mrb_parser_free(parser);
    cxt->lineno++;
  }

#ifdef ENABLE_READLINE
  MIRB_WRITE_HISTORY(history_path);
  mrb_free(mrb, history_path);
#endif

  mrbc_context_free(mrb, cxt);
  mrb_close(mrb);

  return 0;
}
