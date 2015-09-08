/*
** file.c - File class
*/

#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/ext/io.h"

#if MRUBY_RELEASE_NO < 10000
#include "error.h"
#else
#include "mruby/error.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <limits.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) || defined(_WIN64)
  #define NULL_FILE "NUL"
  #define UNLINK _unlink
  #define GETCWD _getcwd
  #define CHMOD(a, b) 0
  #define MAXPATHLEN 1024
 #if !defined(PATH_MAX)
  #define PATH_MAX _MAX_PATH
 #endif
  #define realpath(N,R) _fullpath((R),(N),_MAX_PATH)
  #include <direct.h>
#else
  #define NULL_FILE "/dev/null"
  #include <unistd.h>
  #define UNLINK unlink
  #define GETCWD getcwd
  #define CHMOD(a, b) chmod(a,b)
  #include <sys/file.h>
  #include <libgen.h>
  #include <sys/param.h>
  #include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
  #define PATH_SEPARATOR ";"
  #define FILE_SEPARATOR "\\"
#else
  #define PATH_SEPARATOR ":"
  #define FILE_SEPARATOR "/"
#endif

#ifndef LOCK_SH
#define LOCK_SH 1
#endif
#ifndef LOCK_EX
#define LOCK_EX 2
#endif
#ifndef LOCK_NB
#define LOCK_NB 4
#endif
#ifndef LOCK_UN
#define LOCK_UN 8
#endif

#define STAT(p, s)        stat(p, s)


mrb_value
mrb_file_s_umask(mrb_state *mrb, mrb_value klass)
{
#if defined(_WIN32) || defined(_WIN64)
  /* nothing to do on windows */
  return mrb_fixnum_value(0);

#else
  mrb_int mask, omask;
  if (mrb_get_args(mrb, "|i", &mask) == 0) {
    omask = umask(0);
    umask(omask);
  } else {
    omask = umask(mask);
  }
  return mrb_fixnum_value(omask);
#endif
}

static mrb_value
mrb_file_s_unlink(mrb_state *mrb, mrb_value obj)
{
  mrb_value *argv;
  mrb_value pathv;
  mrb_int argc, i;
  const char *path;

  mrb_get_args(mrb, "*", &argv, &argc);
  for (i = 0; i < argc; i++) {
    pathv = mrb_convert_type(mrb, argv[i], MRB_TT_STRING, "String", "to_str");
    path = mrb_string_value_cstr(mrb, &pathv);
    if (UNLINK(path) < 0) {
      mrb_sys_fail(mrb, path);
    }
  }
  return mrb_fixnum_value(argc);
}

static mrb_value
mrb_file_s_rename(mrb_state *mrb, mrb_value obj)
{
  mrb_value from, to;
  const char *src, *dst;

  mrb_get_args(mrb, "SS", &from, &to);
  src = mrb_string_value_cstr(mrb, &from);
  dst = mrb_string_value_cstr(mrb, &to);
  if (rename(src, dst) < 0) {
    if (CHMOD(dst, 0666) == 0 && UNLINK(dst) == 0 && rename(src, dst) == 0) {
      return mrb_fixnum_value(0);
    }
    mrb_sys_fail(mrb, mrb_str_to_cstr(mrb, mrb_format(mrb, "(%S, %S)", from, to)));
  }
  return mrb_fixnum_value(0);
}

static mrb_value
mrb_file_dirname(mrb_state *mrb, mrb_value klass)
{
  #if defined(_WIN32) || defined(_WIN64)
  char dname[_MAX_DIR], vname[_MAX_DRIVE];
  char buffer[_MAX_DRIVE + _MAX_DIR];
  char *path;
  mrb_value s;
  mrb_get_args(mrb, "S", &s);
  path = mrb_str_to_cstr(mrb, s);
  _splitpath((const char*)path, vname, dname, NULL, NULL);
  snprintf(buffer, _MAX_DRIVE + _MAX_DIR, "%s%s", vname, dname);
  return mrb_str_new_cstr(mrb, buffer);
  #else
  char *dname, *path;
  mrb_value s;
  mrb_get_args(mrb, "S", &s);
  path = mrb_str_to_cstr(mrb, s);

  if ((dname = dirname(path)) == NULL) {
    mrb_sys_fail(mrb, "dirname");
  }
  #endif
  return mrb_str_new_cstr(mrb, dname);
}

static mrb_value
mrb_file_basename(mrb_state *mrb, mrb_value klass)
{
  #if defined(_WIN32) || defined(_WIN64)
  char bname[_MAX_DIR];
  char extname[_MAX_EXT];
  char *path;
  char buffer[_MAX_DIR + _MAX_EXT];
  mrb_value s;
  mrb_get_args(mrb, "S", &s);
  path = mrb_str_to_cstr(mrb, s);
  _splitpath((const char*)path, NULL, NULL, bname, extname);
  snprintf(buffer, _MAX_DIR + _MAX_EXT, "%s%s", bname, extname);
  return mrb_str_new_cstr(mrb, buffer);
  #else
  char *bname, *path;
  mrb_value s;
  mrb_get_args(mrb, "S", &s);
  path = mrb_str_to_cstr(mrb, s);
  if ((bname = basename(path)) == NULL) {
    mrb_sys_fail(mrb, "basename");
  }
  return mrb_str_new_cstr(mrb, bname);
  #endif
}

static mrb_value
mrb_file_realpath(mrb_state *mrb, mrb_value klass)
{
  mrb_value pathname, dir_string, s, result;
  int argc;
  char *cpath;

  argc = mrb_get_args(mrb, "S|S", &pathname, &dir_string);
  if (argc == 2) {
    s = mrb_str_dup(mrb, dir_string);
    s = mrb_str_append(mrb, s, mrb_str_new_cstr(mrb, FILE_SEPARATOR));
    s = mrb_str_append(mrb, s, pathname);
    pathname = s;
  }
  cpath = mrb_str_to_cstr(mrb, pathname);
  result = mrb_str_buf_new(mrb, PATH_MAX);
  if (realpath(cpath, RSTRING_PTR(result)) == NULL)
    mrb_sys_fail(mrb, cpath);
  mrb_str_resize(mrb, result, strlen(RSTRING_PTR(result)));
  return result;
}

mrb_value
mrb_file__getwd(mrb_state *mrb, mrb_value klass)
{
  mrb_value path;

  path = mrb_str_buf_new(mrb, MAXPATHLEN);
  if (GETCWD(RSTRING_PTR(path), MAXPATHLEN) == NULL) {
    mrb_sys_fail(mrb, "getcwd(2)");
  }
  mrb_str_resize(mrb, path, strlen(RSTRING_PTR(path)));
  return path;
}

static int
mrb_file_is_absolute_path(const char *path)
{
  return (path[0] == '/');
}

static mrb_value
mrb_file__gethome(mrb_state *mrb, mrb_value klass)
{
#ifndef _WIN32
  mrb_value username;
  int argc;
  char *home;

  argc = mrb_get_args(mrb, "|S", &username);
  if (argc == 0) {
    home = getenv("HOME");
    if (home == NULL) {
      return mrb_nil_value();
    }
    if (!mrb_file_is_absolute_path(home)) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "non-absolute home");
    }
  } else {
    const char *cuser = mrb_str_to_cstr(mrb, username);
    struct passwd *pwd = getpwnam(cuser);
    if (pwd == NULL) {
      return mrb_nil_value();
    }
    home = pwd->pw_dir;
    if (!mrb_file_is_absolute_path(home)) {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "non-absolute home of ~%S", username);
    }
  }
  return mrb_str_new_cstr(mrb, home);
#else

  return mrb_nil_value();
#endif
}

#ifndef _WIN32
mrb_value
mrb_file_flock(mrb_state *mrb, mrb_value self)
{
#if defined(sun)
  mrb_raise(mrb, E_RUNTIME_ERROR, "flock is not supported on Illumos/Solaris");
#else
  mrb_int operation;
  int fd;

  mrb_get_args(mrb, "i", &operation);
  fd = mrb_fixnum(mrb_io_fileno(mrb, self));

  while (flock(fd, operation) == -1) {
    switch (errno) {
      case EINTR:
        /* retry */
        break;
      case EAGAIN:      /* NetBSD */
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
      case EWOULDBLOCK: /* FreeBSD OpenBSD Linux */
#endif
        if (operation & LOCK_NB) {
          return mrb_false_value();
        }
        /* FALLTHRU - should not happen */
      default:
        mrb_sys_fail(mrb, "flock failed");
        break;
    }
  }
#endif
  return mrb_fixnum_value(0);
}
#endif

void
mrb_init_file(mrb_state *mrb)
{
  struct RClass *io, *file, *cnst;

  io   = mrb_class_get(mrb, "IO");
  file = mrb_define_class(mrb, "File", io);
  MRB_SET_INSTANCE_TT(file, MRB_TT_DATA);
  mrb_define_class_method(mrb, file, "umask",  mrb_file_s_umask, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, file, "delete", mrb_file_s_unlink, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, file, "unlink", mrb_file_s_unlink, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, file, "rename", mrb_file_s_rename, MRB_ARGS_REQ(2));

  mrb_define_class_method(mrb, file, "dirname",   mrb_file_dirname,    MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, file, "basename",  mrb_file_basename,   MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, file, "realpath",  mrb_file_realpath,   MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, file, "_getwd",    mrb_file__getwd,     MRB_ARGS_NONE());
  mrb_define_class_method(mrb, file, "_gethome",  mrb_file__gethome,   MRB_ARGS_OPT(1));

  #ifndef _WIN32
  mrb_define_method(mrb, file, "flock", mrb_file_flock, MRB_ARGS_REQ(1));
  #endif

  cnst = mrb_define_module_under(mrb, file, "Constants");
  mrb_define_const(mrb, cnst, "LOCK_SH", mrb_fixnum_value(LOCK_SH));
  mrb_define_const(mrb, cnst, "LOCK_EX", mrb_fixnum_value(LOCK_EX));
  mrb_define_const(mrb, cnst, "LOCK_UN", mrb_fixnum_value(LOCK_UN));
  mrb_define_const(mrb, cnst, "LOCK_NB", mrb_fixnum_value(LOCK_NB));
  mrb_define_const(mrb, cnst, "SEPARATOR", mrb_str_new_cstr(mrb, FILE_SEPARATOR));
  mrb_define_const(mrb, cnst, "PATH_SEPARATOR", mrb_str_new_cstr(mrb, PATH_SEPARATOR));
  mrb_define_const(mrb, cnst, "NULL", mrb_str_new_cstr(mrb, NULL_FILE));

}
