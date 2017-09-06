#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mruby.h>
#include <mruby/irep.h>
#include <mruby/dump.h>

struct strip_args {
  int argc_start;
  int argc;
  char **argv;
  mrb_bool lvar;
};


static void
irep_remove_lv(mrb_state *mrb, mrb_irep *irep)
{
  int i;

  if (irep->lv) {
    mrb_free(mrb, irep->lv);
    irep->lv = NULL;
  }

  for (i = 0; i < irep->rlen; ++i) {
    irep_remove_lv(mrb, irep->reps[i]);
  }
}

static void
print_usage(const char *f)
{
  printf("Usage: %s [switches] irepfiles\n", f);
  printf("switches:\n");
  printf("  -l, --lvar   remove LVAR section too.\n");
}

static int
parse_args(int argc, char **argv, struct strip_args *args)
{
  int i;

  args->argc_start = 0;
  args->argc = argc;
  args->argv = argv;
  args->lvar = FALSE;

  for (i = 1; i < argc; ++i) {
    const size_t len = strlen(argv[i]);
    if (len >= 2 && argv[i][0] == '-') {
      switch (argv[i][1]) {
      case 'l':
        args->lvar = TRUE;
        break;
      case '-':
        if (strncmp((*argv) + 2, "lvar", len) == 0) {
          args->lvar = TRUE;
          break;
        }
      default:
        return -1;
      }
    }
    else {
      break;
    }
  }

  args->argc_start = i;
  return i;
}

static int
strip(mrb_state *mrb, struct strip_args *args)
{
  int i;

  for (i = args->argc_start; i < args->argc; ++i) {
    char *filename;
    FILE *rfile;
    mrb_irep *irep;
    FILE *wfile;
    int dump_result;

    filename = args->argv[i];
    rfile = fopen(filename, "rb");
    if (rfile == NULL) {
      fprintf(stderr, "can't open file for reading %s\n", filename);
      return EXIT_FAILURE;
    }

    irep = mrb_read_irep_file(mrb, rfile);
    fclose(rfile);
    if (irep == NULL) {
      fprintf(stderr, "can't read irep file %s\n", filename);
      return EXIT_FAILURE;
    }

    /* clear lv if --lvar is enabled */
    if (args->lvar) {
      irep_remove_lv(mrb, irep);
    }

    wfile = fopen(filename, "wb");
    if (wfile == NULL) {
      fprintf(stderr, "can't open file for writing %s\n", filename);
      mrb_irep_decref(mrb, irep);
      return EXIT_FAILURE;
    }

    /* debug flag must always be false */
    dump_result = mrb_dump_irep_binary(mrb, irep, FALSE, wfile);

    fclose(wfile);
    mrb_irep_decref(mrb, irep);

    if (dump_result != MRB_DUMP_OK) {
      fprintf(stderr, "error occurred during dumping %s\n", filename);
      return EXIT_FAILURE;
    }
  }
  return EXIT_SUCCESS;
}

int
main(int argc, char **argv)
{
  struct strip_args args;
  int args_result;
  mrb_state *mrb;
  int ret;

  if (argc <= 1) {
    printf("no files to strip\n");
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  args_result = parse_args(argc, argv, &args);
  if (args_result < 0) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }
  mrb = mrb_open_core(mrb_default_allocf, NULL);
  if (mrb == NULL) {
    fputs("Invalid mrb_state, exiting mruby-strip\n", stderr);
    return EXIT_FAILURE;
  }

  ret = strip(mrb, &args);

  mrb_close(mrb);
  return ret;
}
