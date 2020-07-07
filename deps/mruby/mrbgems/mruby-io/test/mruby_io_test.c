#include <mruby/common.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)

#include <winsock.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <stdlib.h>
#include <malloc.h>

#if (!defined __MINGW64__) && (!defined __MINGW32__)
typedef int mode_t;
#endif

#define open _open
#define close _close

#if defined(_MSC_VER) || \
    (defined(MRB_MINGW32_VERSION) && MRB_MINGW32_VERSION < 3021) || \
    (defined(MRB_MINGW64_VERSION) && MRB_MINGW64_VERSION < 4000)
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
  #include <fcntl.h>
  #include <libgen.h>
#endif

#include <sys/stat.h>
#include <stdlib.h>

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/error.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include <mruby/ext/io.h>

static mrb_value
mrb_io_test_io_setup(mrb_state *mrb, mrb_value self)
{
#define GVNAME(n) "$mrbtest_io_" #n "name"
  enum {IDX_READ, IDX_WRITE, IDX_LINK, IDX_SOCKET, IDX_COUNT};
  const char *gvnames[] = {GVNAME(rf), GVNAME(wf), GVNAME(symlink), GVNAME(socket)};
  char *fnames[IDX_COUNT];
  int fds[IDX_COUNT];
  char msg[] = "mruby io test\n";
  mode_t mask;
  FILE *fp;
  int i;
#if !defined(_WIN32) && !defined(_WIN64)
  struct sockaddr_un sun0;
#endif

  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_msg"), mrb_str_new_cstr(mrb, msg));

  mask = umask(077);
  for (i = 0; i < IDX_COUNT; i++) {
    mrb_value fname = mrb_str_new_capa(mrb, 0);
#if !defined(_WIN32) && !defined(_WIN64)
    /*
     * Workaround for not being able to bind a socket to some file systems
     * (e.g. vboxsf, NFS). [#4981]
     */
    char *tmpdir = getenv("TMPDIR");
    if (tmpdir && strlen(tmpdir) > 0) {
      mrb_str_cat_cstr(mrb, fname, tmpdir);
      if (*(RSTRING_END(fname)-1) != '/') mrb_str_cat_lit(mrb, fname, "/");
    } else {
      mrb_str_cat_lit(mrb, fname, "/tmp/");
    }
#endif
    mrb_str_cat_cstr(mrb, fname, gvnames[i]+1);
    mrb_str_cat_cstr(mrb, fname, ".XXXXXXXX");
    fnames[i] = RSTRING_PTR(fname);
    fds[i] = mkstemp(fnames[i]);
    if (fds[i] == -1) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "can't create temporary file");
    }
    close(fds[i]);
    mrb_gv_set(mrb, mrb_intern_cstr(mrb, gvnames[i]), fname);
  }
  umask(mask);

  fp = fopen(fnames[IDX_READ], "wb");
  if (fp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't open temporary file");
    return mrb_nil_value();
  }
  fputs(msg, fp);
  fclose(fp);

  fp = fopen(fnames[IDX_WRITE], "wb");
  if (fp == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't open temporary file");
    return mrb_nil_value();
  }
  fclose(fp);

#if !defined(_WIN32) && !defined(_WIN64)
  unlink(fnames[IDX_LINK]);
  if (symlink(basename(fnames[IDX_READ]), fnames[IDX_LINK]) == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a symbolic link");
  }

  unlink(fnames[IDX_SOCKET]);
  fds[IDX_SOCKET] = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fds[IDX_SOCKET] == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't make a socket");
  }
  sun0.sun_family = AF_UNIX;
  strncpy(sun0.sun_path, fnames[IDX_SOCKET], sizeof(sun0.sun_path)-1);
  sun0.sun_path[sizeof(sun0.sun_path)-1] = 0;
  if (bind(fds[IDX_SOCKET], (struct sockaddr *)&sun0, sizeof(sun0)) == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "can't bind AF_UNIX socket to %s: %d",
               sun0.sun_path,
               errno);
  }
  close(fds[IDX_SOCKET]);
#endif

  return mrb_true_value();
#undef GVNAME
}

static mrb_value
mrb_io_test_io_cleanup(mrb_state *mrb, mrb_value self)
{
  mrb_value rfname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_rfname"));
  mrb_value wfname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_wfname"));
  mrb_value symlinkname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_symlinkname"));
  mrb_value socketname = mrb_gv_get(mrb, mrb_intern_cstr(mrb, "$mrbtest_io_socketname"));

  if (mrb_string_p(rfname)) {
    remove(RSTRING_PTR(rfname));
  }
  if (mrb_string_p(wfname)) {
    remove(RSTRING_PTR(wfname));
  }
  if (mrb_string_p(symlinkname)) {
    remove(RSTRING_PTR(symlinkname));
  }
  if (mrb_string_p(socketname)) {
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
  const char *cp;

  mrb_get_args(mrb, "z", &cp);
  if (rmdir(cp) == -1) {
    mrb_sys_fail(mrb, "rmdir");
  }
  return mrb_true_value();
}

static mrb_value
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

#ifdef MRB_WITH_IO_PREAD_PWRITE
# define MRB_WITH_IO_PREAD_PWRITE_ENABLED TRUE
#else
# define MRB_WITH_IO_PREAD_PWRITE_ENABLED FALSE
#endif

void
mrb_mruby_io_gem_test(mrb_state* mrb)
{
  struct RClass *io_test = mrb_define_module(mrb, "MRubyIOTestUtil");
  mrb_define_class_method(mrb, io_test, "io_test_setup", mrb_io_test_io_setup, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, io_test, "io_test_cleanup", mrb_io_test_io_cleanup, MRB_ARGS_NONE());

  mrb_define_class_method(mrb, io_test, "mkdtemp", mrb_io_test_mkdtemp, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, io_test, "rmdir", mrb_io_test_rmdir, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, io_test, "win?", mrb_io_win_p, MRB_ARGS_NONE());

  mrb_define_const(mrb, io_test, "MRB_WITH_IO_PREAD_PWRITE", mrb_bool_value(MRB_WITH_IO_PREAD_PWRITE_ENABLED));
}
