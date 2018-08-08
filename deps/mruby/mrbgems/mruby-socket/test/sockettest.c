#include <stdio.h>
#include <stdlib.h>

#include "mruby.h"
#include "mruby/error.h"

#if defined(_WIN32) || defined(_WIN64)

#include <io.h>

#ifdef _MSC_VER

#include <fcntl.h>
#include <sys/stat.h>
#define close _close
#define unlink _unlink

static int
mkstemp(char *p)
{
  int fd;
  char* fname = _mktemp(p);
  if (fname == NULL)
    return -1;
  fd = open(fname, O_RDWR | O_CREAT | O_EXCL, _S_IREAD | _S_IWRITE);
  if (fd >= 0)
    return fd;
  return -1;
}
#endif

#else

#include <unistd.h>

#endif

mrb_value
mrb_sockettest_tmppath(mrb_state *mrb, mrb_value klass)
{
  char name[] = "mruby-socket.XXXXXXXX";
  int fd = mkstemp(name);
  if (fd == -1) {
    mrb_sys_fail(mrb, 0);
  }
  if (close(fd) == -1) {
    mrb_sys_fail(mrb, 0);
  }
  if (unlink(name) == -1) {
    mrb_sys_fail(mrb, 0);
  }
  return mrb_str_new_cstr(mrb, name);
}

mrb_value
mrb_sockettest_win_p(mrb_state *mrb, mrb_value klass)
{
#ifdef _WIN32
  return mrb_true_value();
#else
  return mrb_false_value();
#endif
}

mrb_value
mrb_sockettest_cygwin_p(mrb_state *mrb, mrb_value klass)
{
#if defined(__CYGWIN__) || defined(__CYGWIN32__)
  return mrb_true_value();
#else
  return mrb_false_value();
#endif
}

void
mrb_mruby_socket_gem_test(mrb_state* mrb)
{
  struct RClass *c = mrb_define_module(mrb, "SocketTest");
  mrb_define_class_method(mrb, c, "tmppath", mrb_sockettest_tmppath, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, c, "win?", mrb_sockettest_win_p, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, c, "cygwin?", mrb_sockettest_cygwin_p, MRB_ARGS_NONE());
}
