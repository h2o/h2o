#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/string.h"
#include "mruby/variable.h"

static mrb_value
mrb_io_test_io_setup(mrb_state *mrb, mrb_value self)
{
  char rfname[]      = "tmp.mruby-io-test.XXXXXXXX";
  char wfname[]      = "tmp.mruby-io-test.XXXXXXXX";
  char symlinkname[] = "tmp.mruby-io-test.XXXXXXXX";
  char socketname[]  = "tmp.mruby-io-test.XXXXXXXX";
  char msg[] = "mruby io test\n";
  mode_t mask;
  int fd0, fd1, fd2, fd3;
  FILE *fp;
  struct sockaddr_un sun0;

  mask = umask(077);
  fd0 = mkstemp(rfname);
  fd1 = mkstemp(wfname);
  fd2 = mkstemp(symlinkname);
  fd3 = mkstemp(socketname);
  if (fd0 == -1 || fd1 == -1 || fd2 == -1 || fd3 == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't create temporary file");
    return mrb_nil_value();
  }
  umask(mask);

  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_rfname"), mrb_str_new_cstr(mrb, rfname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_wfname"), mrb_str_new_cstr(mrb, wfname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_symlinkname"), mrb_str_new_cstr(mrb, symlinkname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_socketname"), mrb_str_new_cstr(mrb, socketname));
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_msg"), mrb_str_new_cstr(mrb, msg));

  fp = fopen(rfname, "w");
  if (fp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't open temporary file");
    return mrb_nil_value();
  }
  fputs(msg, fp);
  fclose(fp);

  fp = fopen(wfname, "w");
  if (fp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't open temporary file");
    return mrb_nil_value();
  }
  fclose(fp);

  unlink(symlinkname);
  close(fd2);
  if (symlink("hoge", symlinkname) == -1) {
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
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a socket bi");
  }
  close(fd3);

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
  if (symlink("/usr/bin", "test-bin") == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a symbolic link");
  }

  return ary;
}

static mrb_value
mrb_io_test_file_cleanup(mrb_state *mrb, mrb_value self)
{
  mrb_io_test_io_cleanup(mrb, self);
  remove("test-bin");

  return mrb_nil_value();
}

void
mrb_mruby_io_gem_test(mrb_state* mrb)
{
  struct RClass *io_test = mrb_define_module(mrb, "MRubyIOTestUtil");
  mrb_define_class_method(mrb, io_test, "io_test_setup", mrb_io_test_io_setup, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, io_test, "io_test_cleanup", mrb_io_test_io_cleanup, MRB_ARGS_NONE());

  mrb_define_class_method(mrb, io_test, "file_test_setup", mrb_io_test_file_setup, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, io_test, "file_test_cleanup", mrb_io_test_file_cleanup, MRB_ARGS_NONE());

}
