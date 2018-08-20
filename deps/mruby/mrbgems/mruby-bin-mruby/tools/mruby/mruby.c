#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/compile.h>
#include <mruby/dump.h>
#include <mruby/variable.h>

#ifdef MRB_DISABLE_STDIO
static void
p(mrb_state *mrb, mrb_value obj)
{
  mrb_value val = mrb_inspect(mrb, obj);

  fwrite(RSTRING_PTR(val), RSTRING_LEN(val), 1, stdout);
  putc('\n', stdout);
}
#else
#define p(mrb,obj) mrb_p(mrb,obj)
#endif

struct _args {
  FILE *rfp;
  char* cmdline;
  mrb_bool fname        : 1;
  mrb_bool mrbfile      : 1;
  mrb_bool check_syntax : 1;
  mrb_bool verbose      : 1;
  mrb_bool debug        : 1;
  int argc;
  char** argv;
  int libc;
  char **libv;
};

static void
usage(const char *name)
{
  static const char *const usage_msg[] = {
  "switches:",
  "-b           load and execute RiteBinary (mrb) file",
  "-c           check syntax only",
  "-d           set debugging flags (set $DEBUG to true)"
  "-e 'command' one line of script",
  "-r library   load the library before executing your script",
  "-v           print version number, then run in verbose mode",
  "--verbose    run in verbose mode",
  "--version    print the version",
  "--copyright  print the copyright",
  NULL
  };
  const char *const *p = usage_msg;

  printf("Usage: %s [switches] programfile\n", name);
  while (*p)
    printf("  %s\n", *p++);
}

static char *
dup_arg_item(mrb_state *mrb, const char *item)
{
  size_t buflen = strlen(item) + 1;
  char *buf = (char*)mrb_malloc(mrb, buflen);
  memcpy(buf, item, buflen);
  return buf;
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

    if (strlen(*argv) <= 1) {
      argc--; argv++;
      args->rfp = stdin;
      break;
    }

    item = argv[0] + 1;
    switch (*item++) {
    case 'b':
      args->mrbfile = TRUE;
      break;
    case 'c':
      args->check_syntax = TRUE;
      break;
    case 'd':
      args->debug = TRUE;
      break;
    case 'e':
      if (item[0]) {
        goto append_cmdline;
      }
      else if (argc > 1) {
        argc--; argv++;
        item = argv[0];
append_cmdline:
        if (!args->cmdline) {
          args->cmdline = dup_arg_item(mrb, item);
        }
        else {
          size_t cmdlinelen;
          size_t itemlen;

          cmdlinelen = strlen(args->cmdline);
          itemlen = strlen(item);
          args->cmdline =
            (char *)mrb_realloc(mrb, args->cmdline, cmdlinelen + itemlen + 2);
          args->cmdline[cmdlinelen] = '\n';
          memcpy(args->cmdline + cmdlinelen + 1, item, itemlen + 1);
        }
      }
      else {
        printf("%s: No code specified for -e\n", *origargv);
        return EXIT_SUCCESS;
      }
      break;
    case 'r':
      if (!item[0]) {
        if (argc <= 1) {
          printf("%s: No library specified for -r\n", *origargv);
          return EXIT_FAILURE;
        }
        argc--; argv++;
        item = argv[0];
      }
      if (args->libc == 0) {
        args->libv = (char**)mrb_malloc(mrb, sizeof(char*));
      }
      else {
        args->libv = (char**)mrb_realloc(mrb, args->libv, sizeof(char*) * (args->libc + 1));
      }
      args->libv[args->libc++] = dup_arg_item(mrb, item);
      break;
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

  if (args->rfp == NULL && args->cmdline == NULL) {
    if (*argv == NULL) args->rfp = stdin;
    else {
      args->rfp = fopen(argv[0], args->mrbfile ? "rb" : "r");
      if (args->rfp == NULL) {
        printf("%s: Cannot open program file. (%s)\n", *origargv, *argv);
        return EXIT_FAILURE;
      }
      args->fname = TRUE;
      args->cmdline = argv[0];
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
  if (args->rfp && args->rfp != stdin)
    fclose(args->rfp);
  if (!args->fname)
    mrb_free(mrb, args->cmdline);
  mrb_free(mrb, args->argv);
  if (args->libc) {
    while (args->libc--) {
      mrb_free(mrb, args->libv[args->libc]);
    }
    mrb_free(mrb, args->libv);
  }
  mrb_close(mrb);
}

int
main(int argc, char **argv)
{
  mrb_state *mrb = mrb_open();
  int n = -1;
  int i;
  struct _args args;
  mrb_value ARGV;
  mrbc_context *c;
  mrb_value v;
  mrb_sym zero_sym;

  if (mrb == NULL) {
    fputs("Invalid mrb_state, exiting mruby\n", stderr);
    return EXIT_FAILURE;
  }

  n = parse_args(mrb, argc, argv, &args);
  if (n == EXIT_FAILURE || (args.cmdline == NULL && args.rfp == NULL)) {
    cleanup(mrb, &args);
    usage(argv[0]);
    return n;
  }
  else {
    int ai = mrb_gc_arena_save(mrb);
    ARGV = mrb_ary_new_capa(mrb, args.argc);
    for (i = 0; i < args.argc; i++) {
      char* utf8 = mrb_utf8_from_locale(args.argv[i], -1);
      if (utf8) {
        mrb_ary_push(mrb, ARGV, mrb_str_new_cstr(mrb, utf8));
        mrb_utf8_free(utf8);
      }
    }
    mrb_define_global_const(mrb, "ARGV", ARGV);
    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$DEBUG"), mrb_bool_value(args.debug));

    c = mrbc_context_new(mrb);
    if (args.verbose)
      c->dump_result = TRUE;
    if (args.check_syntax)
      c->no_exec = TRUE;

    /* Set $0 */
    zero_sym = mrb_intern_lit(mrb, "$0");
    if (args.rfp) {
      const char *cmdline;
      cmdline = args.cmdline ? args.cmdline : "-";
      mrbc_filename(mrb, c, cmdline);
      mrb_gv_set(mrb, zero_sym, mrb_str_new_cstr(mrb, cmdline));
    }
    else {
      mrbc_filename(mrb, c, "-e");
      mrb_gv_set(mrb, zero_sym, mrb_str_new_lit(mrb, "-e"));
    }

    /* Load libraries */
    for (i = 0; i < args.libc; i++) {
      FILE *lfp = fopen(args.libv[i], args.mrbfile ? "rb" : "r");
      if (lfp == NULL) {
        printf("Cannot open library file. (%s)\n", args.libv[i]);
        cleanup(mrb, &args);
        return EXIT_FAILURE;
      }
      if (args.mrbfile) {
        v = mrb_load_irep_file_cxt(mrb, lfp, c);
      }
      else {
        v = mrb_load_file_cxt(mrb, lfp, c);
      }
      fclose(lfp);
    }

    /* Load program */
    if (args.mrbfile) {
      v = mrb_load_irep_file_cxt(mrb, args.rfp, c);
    }
    else if (args.rfp) {
      v = mrb_load_file_cxt(mrb, args.rfp, c);
    }
    else {
      char* utf8 = mrb_utf8_from_locale(args.cmdline, -1);
      if (!utf8) abort();
      v = mrb_load_string_cxt(mrb, utf8, c);
      mrb_utf8_free(utf8);
    }

    mrb_gc_arena_restore(mrb, ai);
    mrbc_context_free(mrb, c);
    if (mrb->exc) {
      if (mrb_undef_p(v)) {
        mrb_p(mrb, mrb_obj_value(mrb->exc));
      }
      else {
        mrb_print_error(mrb);
      }
      n = -1;
    }
    else if (args.check_syntax) {
      printf("Syntax OK\n");
    }
  }
  cleanup(mrb, &args);

  return n == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
