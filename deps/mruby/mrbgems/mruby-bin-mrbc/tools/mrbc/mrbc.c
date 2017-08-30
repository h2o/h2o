#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/dump.h>
#include <mruby/proc.h>

#define RITEBIN_EXT ".mrb"
#define C_EXT       ".c"

struct mrbc_args {
  int argc;
  char **argv;
  int idx;
  const char *prog;
  const char *outfile;
  const char *initname;
  mrb_bool check_syntax : 1;
  mrb_bool verbose      : 1;
  unsigned int flags    : 4;
};

static void
usage(const char *name)
{
  static const char *const usage_msg[] = {
  "switches:",
  "-c           check syntax only",
  "-o<outfile>  place the output into <outfile>",
  "-v           print version number, then turn on verbose mode",
  "-g           produce debugging information",
  "-B<symbol>   binary <symbol> output in C language format",
  "-e           generate little endian iseq data",
  "-E           generate big endian iseq data",
  "--verbose    run at verbose mode",
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
get_outfilename(mrb_state *mrb, char *infile, const char *ext)
{
  size_t infilelen;
  size_t extlen;
  char *outfile;
  char *p;

  infilelen = strlen(infile);
  extlen = strlen(ext);
  outfile = (char*)mrb_malloc(mrb, infilelen + extlen + 1);
  memcpy(outfile, infile, infilelen + 1);
  if (*ext) {
    if ((p = strrchr(outfile, '.')) == NULL)
      p = outfile + infilelen;
    memcpy(p, ext, extlen + 1);
  }

  return outfile;
}

static int
parse_args(mrb_state *mrb, int argc, char **argv, struct mrbc_args *args)
{
  char *outfile = NULL;
  static const struct mrbc_args args_zero = { 0 };
  int i;

  *args = args_zero;
  args->argc = argc;
  args->argv = argv;
  args->prog = argv[0];

  for (i=1; i<argc; i++) {
    if (argv[i][0] == '-') {
      switch ((argv[i])[1]) {
      case 'o':
        if (args->outfile) {
          fprintf(stderr, "%s: an output file is already specified. (%s)\n",
                  args->prog, outfile);
          return -1;
        }
        if (argv[i][2] == '\0' && argv[i+1]) {
          i++;
          args->outfile = get_outfilename(mrb, argv[i], "");
        }
        else {
          args->outfile = get_outfilename(mrb, argv[i] + 2, "");
        }
        break;
      case 'B':
        if (argv[i][2] == '\0' && argv[i+1]) {
          i++;
          args->initname = argv[i];
        }
        else {
          args->initname = argv[i]+2;
        }
        if (*args->initname == '\0') {
          fprintf(stderr, "%s: function name is not specified.\n", args->prog);
          return -1;
        }
        break;
      case 'c':
        args->check_syntax = TRUE;
        break;
      case 'v':
        if (!args->verbose) mrb_show_version(mrb);
        args->verbose = TRUE;
        break;
      case 'g':
        args->flags |= DUMP_DEBUG_INFO;
        break;
      case 'E':
        args->flags = DUMP_ENDIAN_BIG | (args->flags & ~DUMP_ENDIAN_MASK);
        break;
      case 'e':
        args->flags = DUMP_ENDIAN_LIL | (args->flags & ~DUMP_ENDIAN_MASK);
        break;
      case 'h':
        return -1;
      case '-':
        if (argv[i][1] == '\n') {
          return i;
        }
        if (strcmp(argv[i] + 2, "version") == 0) {
          mrb_show_version(mrb);
          exit(EXIT_SUCCESS);
        }
        else if (strcmp(argv[i] + 2, "verbose") == 0) {
          args->verbose = TRUE;
          break;
        }
        else if (strcmp(argv[i] + 2, "copyright") == 0) {
          mrb_show_copyright(mrb);
          exit(EXIT_SUCCESS);
        }
        return -1;
      default:
        return i;
      }
    }
    else {
      break;
    }
  }
  if (args->verbose && args->initname && (args->flags & DUMP_ENDIAN_MASK) == 0) {
    fprintf(stderr, "%s: generating %s endian C file. specify -e/-E for cross compiling.\n",
            args->prog, bigendian_p() ? "big" : "little");
  }
  return i;
}

static void
cleanup(mrb_state *mrb, struct mrbc_args *args)
{
  mrb_free(mrb, (void*)args->outfile);
  mrb_close(mrb);
}

static int
partial_hook(struct mrb_parser_state *p)
{
  mrbc_context *c = p->cxt;
  struct mrbc_args *args = (struct mrbc_args *)c->partial_data;
  const char *fn;

  if (p->f) fclose(p->f);
  if (args->idx >= args->argc) {
    p->f = NULL;
    return -1;
  }
  fn = args->argv[args->idx++];
  p->f = fopen(fn, "r");
  if (p->f == NULL) {
    fprintf(stderr, "%s: cannot open program file. (%s)\n", args->prog, fn);
    return -1;
  }
  mrb_parser_set_filename(p, fn);
  return 0;
}

static mrb_value
load_file(mrb_state *mrb, struct mrbc_args *args)
{
  mrbc_context *c;
  mrb_value result;
  char *input = args->argv[args->idx];
  FILE *infile;
  mrb_bool need_close = FALSE;

  c = mrbc_context_new(mrb);
  if (args->verbose)
    c->dump_result = TRUE;
  c->no_exec = TRUE;
  if (input[0] == '-' && input[1] == '\0') {
    infile = stdin;
  }
  else {
    need_close = TRUE;
    if ((infile = fopen(input, "r")) == NULL) {
      fprintf(stderr, "%s: cannot open program file. (%s)\n", args->prog, input);
      return mrb_nil_value();
    }
  }
  mrbc_filename(mrb, c, input);
  args->idx++;
  if (args->idx < args->argc) {
    need_close = FALSE;
    mrbc_partial_hook(mrb, c, partial_hook, (void*)args);
  }

  result = mrb_load_file_cxt(mrb, infile, c);
  if (need_close) fclose(infile);
  mrbc_context_free(mrb, c);
  if (mrb_undef_p(result)) {
    return mrb_nil_value();
  }
  return result;
}

static int
dump_file(mrb_state *mrb, FILE *wfp, const char *outfile, struct RProc *proc, struct mrbc_args *args)
{
  int n = MRB_DUMP_OK;
  mrb_irep *irep = proc->body.irep;

  if (args->initname) {
    n = mrb_dump_irep_cfunc(mrb, irep, args->flags, wfp, args->initname);
    if (n == MRB_DUMP_INVALID_ARGUMENT) {
      fprintf(stderr, "%s: invalid C language symbol name\n", args->initname);
    }
  }
  else {
    n = mrb_dump_irep_binary(mrb, irep, args->flags, wfp);
  }
  if (n != MRB_DUMP_OK) {
    fprintf(stderr, "%s: error in mrb dump (%s) %d\n", args->prog, outfile, n);
  }
  return n;
}

int
main(int argc, char **argv)
{
  mrb_state *mrb = mrb_open();
  int n, result;
  struct mrbc_args args;
  FILE *wfp;
  mrb_value load;

  if (mrb == NULL) {
    fputs("Invalid mrb_state, exiting mrbc\n", stderr);
    return EXIT_FAILURE;
  }

  n = parse_args(mrb, argc, argv, &args);
  if (n < 0) {
    cleanup(mrb, &args);
    usage(argv[0]);
    return EXIT_FAILURE;
  }
  if (n == argc) {
    fprintf(stderr, "%s: no program file given\n", args.prog);
    return EXIT_FAILURE;
  }
  if (args.outfile == NULL && !args.check_syntax) {
    if (n + 1 == argc) {
      args.outfile = get_outfilename(mrb, argv[n], args.initname ? C_EXT : RITEBIN_EXT);
    }
    else {
      fprintf(stderr, "%s: output file should be specified to compile multiple files\n", args.prog);
      return EXIT_FAILURE;
    }
  }

  args.idx = n;
  load = load_file(mrb, &args);
  if (mrb_nil_p(load)) {
    cleanup(mrb, &args);
    return EXIT_FAILURE;
  }
  if (args.check_syntax) {
    printf("%s:%s:Syntax OK\n", args.prog, argv[n]);
  }

  if (args.check_syntax) {
    cleanup(mrb, &args);
    return EXIT_SUCCESS;
  }

  if (args.outfile) {
    if (strcmp("-", args.outfile) == 0) {
      wfp = stdout;
    }
    else if ((wfp = fopen(args.outfile, "wb")) == NULL) {
      fprintf(stderr, "%s: cannot open output file:(%s)\n", args.prog, args.outfile);
      return EXIT_FAILURE;
    }
  }
  else {
    fprintf(stderr, "Output file is required\n");
    return EXIT_FAILURE;
  }
  result = dump_file(mrb, wfp, args.outfile, mrb_proc_ptr(load), &args);
  fclose(wfp);
  cleanup(mrb, &args);
  if (result != MRB_DUMP_OK) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

void
mrb_init_mrblib(mrb_state *mrb)
{
}

#ifndef DISABLE_GEMS
void
mrb_init_mrbgems(mrb_state *mrb)
{
}

void
mrb_final_mrbgems(mrb_state *mrb)
{
}
#endif
