#include <sys/types.h>
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)

#include <winsock.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

#if (!defined __MINGW64__) && (!defined __MINGW32__)
typedef int mode_t;
#endif

#define open _open
#define close _close

#ifdef _MSC_VER
#include <sys/stat.h>

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

static char*
mkdtemp(char *temp)
{
  char *path = _mktemp(temp);
  if (path[0] == 0) return NULL;
  if (_mkdir(path) < 0) return NULL;
  return path;
}

#define umask(mode) _umask(mode)
#define rmdir(path) _rmdir(path)
#else
  #include <sys/socket.h>
  #include <unistd.h>
  #include <sys/un.h>
#endif

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/error.h"
#include "mruby/string.h"
#include "mruby/variable.h"

static mrb_value
mrb_io_test_io_setup(mrb_state *mrb, mrb_value self)
{
  char rfname[]      = "tmp.mruby-io-test-r.XXXXXXXX";
  char wfname[]      = "tmp.mruby-io-test-w.XXXXXXXX";
  char symlinkname[] = "tmp.mruby-io-test-l.XXXXXXXX";
  char socketname[]  = "tmp.mruby-io-test-s.XXXXXXXX";
  char msg[] = "mruby io test\n";
  mode_t mask;
  int fd0, fd1;
  FILE *fp;

#if !defined(_WIN32) && !defined(_WIN64)
  int fd2, fd3;
  struct sockaddr_un sun0;
#endif

  mask = umask(077);
  fd0 = mkstemp(rfname);
  fd1 = mkstemp(wfname);
  if (fd0 == -1 || fd1 == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't create temporary file");
    return mrb_nil_value();
  }
  close(fd0);
  close(fd1);

#if !defined(_WIN32) && !defined(_WIN64)
  fd2 = mkstemp(symlinkname);
  fd3 = mkstemp(socketname);
  if (fd2 == -1 || fd3 == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't create temporary file");
    return mrb_nil_value();
  }
#endif
  umask(mask);

  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_rfname"), mrb_str_new_cstr(mrb, rfname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_wfname"), mrb_str_new_cstr(mrb, wfname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_symlinkname"), mrb_str_new_cstr(mrb, symlinkname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_socketname"), mrb_str_new_cstr(mrb, socketname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_msg"), mrb_str_new_cstr(mrb, msg));

  fp = fopen(rfname, "wb");
  if (fp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't open temporary file");
    return mrb_nil_value();
  }
  fputs(msg, fp);
  fclose(fp);

  fp = fopen(wfname, "wb");
  if (fp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't open temporary file");
    return mrb_nil_value();
  }
  fclose(fp);

#if !defined(_WIN32) && !defined(_WIN64)
  unlink(symlinkname);
  close(fd2);
  if (symlink(rfname, symlinkname) == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a symbolic link");
  }

  unlink(socketname);
  close(fd3);
  fd3 = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd3 == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a socket");
  }
  sun0.sun_family = AF_UNIX;
  snprintf(sun0.sun_path, sizeof(sun0.sun_path), "%s", socketname);
  if (bind(fd3, (struct sockaddr *)&sun0, sizeof(sun0)) == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "can't bind AF_UNIX socket to %S: %S",
               mrb_str_new_cstr(mrb, sun0.sun_path),
               mrb_fixnum_value(errno));
  }
  close(fd3);
#endif

  return mrb_true_value();
}

static mrb_value
mrb_io_test_io_cleanup(mrb_state *mrb, mrb_value self)
{
  mrb_value rfname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_rfname"));
  mrb_value wfname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_wfname"));
  mrb_value symlinkname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_symlinkname"));
  mrb_value socketname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_socketname"));

  if (mrb_type(rfname) == MRB_TT_STRING) {
    remove(RSTRING_PTR(rfname));
  }
  if (mrb_type(wfname) == MRB_TT_STRING) {
    remove(RSTRING_PTR(wfname));
  }
  if (mrb_type(symlinkname) == MRB_TT_STRING) {
    remove(RSTRING_PTR(symlinkname));
  }
  if (mrb_type(socketname) == MRB_TT_STRING) {
    remove(RSTRING_PTR(socketname));
  }

  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_rfname"), mrb_nil_value());
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_wfname"), mrb_nil_value());
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_symlinkname"), mrb_nil_value());
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_socketname"), mrb_nil_value());
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_msg"), mrb_nil_value());

  return mrb_nil_value();
}

static mrb_value
mrb_io_test_file_setup(mrb_state *mrb, mrb_value self)
{
  mrb_value ary = mrb_io_test_io_setup(mrb, self);
#if !defined(_WIN32) && !defined(_WIN64)
  if (symlink("/usr/bin", "test-bin") == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a symbolic link");
  }
#endif

  return ary;
}

static mrb_value
mrb_io_test_file_cleanup(mrb_state *mrb, mrb_value self)
{
  mrb_io_test_io_cleanup(mrb, self);
  remove("test-bin");

  return mrb_nil_value();
}

static mrb_value
mrb_io_test_mkdtemp(mrb_state *mrb, mrb_value klass)
{
  mrb_value str;
  char *cp;

  mrb_get_args(mrb, "S", &str);
  cp = mrb_str_to_cstr(mrb, str);
  if (mkdtemp(cp) == NULL) {
    mrb_sys_fail(mrb, "mkdtemp");
  }
  return mrb_str_new_cstr(mrb, cp);
}

static mrb_value
mrb_io_test_rmdir(mrb_state *mrb, mrb_value klass)
{
  mrb_value str;
  char *cp;

  mrb_get_args(mrb, "S", &str);
  cp = mrb_str_to_cstr(mrb, str);
  if (rmdir(cp) == -1) {
    mrb_sys_fail(mrb, "rmdir");
  }
  return mrb_true_value();
}

mrb_value
mrb_io_win_p(mrb_state *mrb, mrb_value klass)
{
#if defined(_WIN32) || defined(_WIN64)
# if defined(__CYGWIN__) || defined(__CYGWIN32__)
  return mrb_false_value();
# else
  return mrb_true_value();
# endif
#else
  return mrb_false_value();
#endif
}

void
mrb_mruby_io_gem_test(mrb_state* mrb)
{
  struct RClass *io_test = mrb_define_module(mrb, "MRubyIOTestUtil");
  mrb_define_class_method(mrb, io_test, "io_test_setup", mrb_io_test_io_setup, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, io_test, "io_test_cleanup", mrb_io_test_io_cleanup, MRB_ARGS_NONE());

  mrb_define_class_method(mrb, io_test, "file_test_setup", mrb_io_test_file_setup, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, io_test, "file_test_cleanup", mrb_io_test_file_cleanup, MRB_ARGS_NONE());

  mrb_define_class_method(mrb, io_test, "mkdtemp", mrb_io_test_mkdtemp, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, io_test, "rmdir", mrb_io_test_rmdir, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, io_test, "win?", mrb_io_win_p, MRB_ARGS_NONE());
}
