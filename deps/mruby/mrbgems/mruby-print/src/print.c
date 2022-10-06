#include <mruby.h>

#ifdef MRB_NO_STDIO
# error print conflicts 'MRB_NO_STDIO' in your build configuration
#endif

#include <mruby/string.h>
#include <string.h>
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

void
mrb_mruby_print_gem_init(mrb_state* mrb)
{
  struct RClass *krn;
  krn = mrb->kernel_module;
  mrb_define_method(mrb, krn, "__printstr__", mrb_printstr, MRB_ARGS_REQ(1));
}

void
mrb_mruby_print_gem_final(mrb_state* mrb)
{
}
