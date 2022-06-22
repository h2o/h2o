#include <mruby.h>

#ifdef MRB_NO_STDIO
# error print conflicts 'MRB_NO_STDIO' in your build configuration
#endif

#include <mruby/string.h>
#include <string.h>
#include <stdlib.h>
#if defined(_WIN32)
# include <windows.h>
# include <io.h>
#ifdef _MSC_VER
# define isatty(x) _isatty(x)
# define fileno(x) _fileno(x)
#endif
#endif

static void
printstr(mrb_state *mrb, const char *p, mrb_int len)
{
#if defined(_WIN32)
  if (isatty(fileno(stdout))) {
    DWORD written;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, p, (int)len, NULL, 0);
    wchar_t* utf16 = (wchar_t*)mrb_malloc(mrb, (wlen+1) * sizeof(wchar_t));
    if (MultiByteToWideChar(CP_UTF8, 0, p, (int)len, utf16, wlen) > 0) {
      utf16[wlen] = 0;
      WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE),
                    utf16, (DWORD)wlen, &written, NULL);
    }
    mrb_free(mrb, utf16);
  } else
#endif
    fwrite(p, (size_t)len, 1, stdout);
  fflush(stdout);
}

static mrb_value
mrb_printstr(mrb_state *mrb, mrb_value self)
{
  mrb_value s = mrb_get_arg1(mrb);

  if (mrb_string_p(s)) {
    printstr(mrb, RSTRING_PTR(s), RSTRING_LEN(s));
  }
  return s;
}

/* 15.3.1.2.10  */
/* 15.3.1.3.35 */
static mrb_value
mrb_print(mrb_state *mrb, mrb_value self)
{
  mrb_int argc, i;
  const mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);
  for (i=0; i<argc; i++) {
    mrb_value s = mrb_obj_as_string(mrb, argv[i]);
    printstr(mrb, RSTRING_PTR(s), RSTRING_LEN(s));
  }
  return mrb_nil_value();
}

/* 15.3.1.2.11  */
/* 15.3.1.3.39 */
static mrb_value
mrb_puts(mrb_state *mrb, mrb_value self)
{
  mrb_int argc, i;
  const mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);
  for (i=0; i<argc; i++) {
    mrb_value s = mrb_obj_as_string(mrb, argv[i]);
    mrb_int len = RSTRING_LEN(s);
    printstr(mrb, RSTRING_PTR(s), len);
    if (len == 0 || RSTRING_PTR(s)[len-1] != '\n') {
      printstr(mrb, "\n", 1);
    }
  }
  if (argc == 0) {
    printstr(mrb, "\n", 1);
  }
  return mrb_nil_value();
}

void
mrb_mruby_print_gem_init(mrb_state* mrb)
{
  struct RClass *krn;
  krn = mrb->kernel_module;
  mrb_define_method(mrb, krn, "__printstr__", mrb_printstr, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, krn, "print", mrb_print, MRB_ARGS_ANY());
  mrb_define_method(mrb, krn, "puts", mrb_puts, MRB_ARGS_ANY());
}

void
mrb_mruby_print_gem_final(mrb_state* mrb)
{
}
