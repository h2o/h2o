#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mruby.h"
#include "mruby/string.h"
#include "mruby/variable.h"


mrb_value
mrb_dirtest_setup(mrb_state *mrb, mrb_value klass)
{
  mrb_value s;
  char buf[1024];
  const char *aname = "a";
  const char *bname = "b";

  /* save current working directory */
  if (getcwd(buf, sizeof(buf)) == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "getcwd() failed");
  }
  mrb_cv_set(mrb, klass, mrb_intern_cstr(mrb, "pwd"), mrb_str_new_cstr(mrb, buf));

  /* create sandbox */
  snprintf(buf, sizeof(buf), "%s/mruby-dir-test.XXXXXX", P_tmpdir);
  if (mkdtemp(buf) == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "mkdtemp(%S) failed", mrb_str_new_cstr(mrb, buf));
  }
  s = mrb_str_new_cstr(mrb, buf);
  mrb_cv_set(mrb, klass, mrb_intern_cstr(mrb, "sandbox"), s);

  /* go to sandbox */
  if (chdir(buf) == -1) {
    rmdir(buf);
    mrb_raisef(mrb, E_RUNTIME_ERROR, "chdir(%S) failed", s);
  }
  
  /* make some directories in the sandbox */
  if (mkdir(aname, 0) == -1) {
    chdir("..");
    rmdir(buf);
    mrb_raisef(mrb, E_RUNTIME_ERROR, "mkdir(%S) failed", mrb_str_new_cstr(mrb, aname));
  }
  if (mkdir(bname, 0) == -1) {
    rmdir(aname);
    chdir("..");
    rmdir(buf);
    mrb_raisef(mrb, E_RUNTIME_ERROR, "mkdir(%S) failed", mrb_str_new_cstr(mrb, bname));
  }

  return mrb_true_value();
}

mrb_value
mrb_dirtest_teardown(mrb_state *mrb, mrb_value klass)
{
  mrb_value d, sandbox;
  DIR *dirp;
  struct dirent *dp;
  const char *path;

  /* cleanup sandbox */
  sandbox = mrb_cv_get(mrb, klass, mrb_intern_cstr(mrb, "sandbox"));
  path = mrb_str_to_cstr(mrb, sandbox);

  dirp = opendir(path);
  while ((dp = readdir(dirp)) != NULL) {
    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
      continue;
    if (rmdir(dp->d_name) == -1) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "rmdir(%S) failed", mrb_str_new_cstr(mrb, dp->d_name));
    }
  }
  closedir(dirp);

  /* back to original pwd */
  d = mrb_cv_get(mrb, klass, mrb_intern_cstr(mrb, "pwd"));
  path = mrb_str_to_cstr(mrb, d);
  if (chdir(path) == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "chdir(%S) failed", d);
  }

  /* remove sandbox directory */
  sandbox = mrb_cv_get(mrb, klass, mrb_intern_cstr(mrb, "sandbox"));
  path = mrb_str_to_cstr(mrb, sandbox);
  if (rmdir(path) == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "rmdir(%S) failed", sandbox);
  }

  return mrb_true_value();
}

mrb_value
mrb_dirtest_sandbox(mrb_state *mrb, mrb_value klass)
{
  return mrb_cv_get(mrb, klass, mrb_intern_cstr(mrb, "sandbox"));
}

void
mrb_mruby_dir_gem_test(mrb_state *mrb)
{
  struct RClass *c = mrb_define_module(mrb, "DirTest");

  mrb_define_class_method(mrb, c, "sandbox", mrb_dirtest_sandbox, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, c, "setup", mrb_dirtest_setup, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, c, "teardown", mrb_dirtest_teardown, MRB_ARGS_NONE());
}

