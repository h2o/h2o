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
  #include <windows.h>
  #include <io.h>
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

#define FILE_SEPARATOR "/"

#if defined(_WIN32) || defined(_WIN64)
  #define PATH_SEPARATOR ";"
  #define FILE_ALT_SEPARATOR "\\"
#else
  #define PATH_SEPARATOR ":"
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

#ifdef _WIN32
static int
flock(int fd, int operation) {
  OVERLAPPED ov;
  HANDLE h = (HANDLE)_get_osfhandle(fd);
  DWORD flags;
  flags = ((operation & LOCK_NB) ? LOCKFILE_FAIL_IMMEDIATELY : 0)
          | ((operation & LOCK_SH) ? LOCKFILE_EXCLUSIVE_LOCK : 0);
  memset(&ov, 0, sizeof(ov));
  return LockFileEx(h, flags, 0, 0xffffffff, 0xffffffff, &ov) ? 0 : -1;
}
#endif

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
  char *path;

  mrb_get_args(mrb, "*", &argv, &argc);
  for (i = 0; i < argc; i++) {
    const char *utf8_path;
    pathv = mrb_convert_type(mrb, argv[i], MRB_TT_STRING, "String", "to_str");
    utf8_path = mrb_string_value_cstr(mrb, &pathv);
    path = mrb_locale_from_utf8(utf8_path, -1);
    if (UNLINK(path) < 0) {
      mrb_locale_free(path);
      mrb_sys_fail(mrb, utf8_path);
    }
    mrb_locale_free(path);
  }
  return mrb_fixnum_value(argc);
}

static mrb_value
mrb_file_s_rename(mrb_state *mrb, mrb_value obj)
{
  mrb_value from, to;
  char *src, *dst;

  mrb_get_args(mrb, "SS", &from, &to);
  src = mrb_locale_from_utf8(mrb_string_value_cstr(mrb, &from), -1);
  dst = mrb_locale_from_utf8(mrb_string_value_cstr(mrb, &to), -1);
  if (rename(src, dst) < 0) {
#if defined(_WIN32) || defined(_WIN64)
    if (CHMOD(dst, 0666) == 0 && UNLINK(dst) == 0 && rename(src, dst) == 0) {
      mrb_locale_free(src);
      mrb_locale_free(dst);
      return mrb_fixnum_value(0);
    }
#endif
    mrb_locale_free(src);
    mrb_locale_free(dst);
    mrb_sys_fail(mrb, mrb_str_to_cstr(mrb, mrb_format(mrb, "(%S, %S)", from, to)));
  }
  mrb_locale_free(src);
  mrb_locale_free(dst);
  return mrb_fixnum_value(0);
}

static mrb_value
mrb_file_dirname(mrb_state *mrb, mrb_value klass)
{
#if defined(_WIN32) || defined(_WIN64)
  char dname[_MAX_DIR], vname[_MAX_DRIVE];
  char buffer[_MAX_DRIVE + _MAX_DIR];
  char *path;
  size_t ridx;
  mrb_value s;
  mrb_get_args(mrb, "S", &s);
  path = mrb_locale_from_utf8(mrb_str_to_cstr(mrb, s), -1);
  _splitpath((const char*)path, vname, dname, NULL, NULL);
  snprintf(buffer, _MAX_DRIVE + _MAX_DIR, "%s%s", vname, dname);
  mrb_locale_free(path);
  ridx = strlen(buffer);
  if (ridx == 0) {
    strncpy(buffer, ".", 2);  /* null terminated */
  } else if (ridx > 1) {
    ridx--;
    while (ridx > 0 && (buffer[ridx] == '/' || buffer[ridx] == '\\')) {
      buffer[ridx] = '\0';  /* remove last char */
      ridx--;
    }
  }
  return mrb_str_new_cstr(mrb, buffer);
#else
  char *dname, *path;
  mrb_value s;
  mrb_get_args(mrb, "S", &s);
  path = mrb_locale_from_utf8(mrb_str_to_cstr(mrb, s), -1);

  if ((dname = dirname(path)) == NULL) {
    mrb_locale_free(path);
    mrb_sys_fail(mrb, "dirname");
  }
  mrb_locale_free(path);
  return mrb_str_new_cstr(mrb, dname);
#endif
}

static mrb_value
mrb_file_basename(mrb_state *mrb, mrb_value klass)
{
  // NOTE: Do not use mrb_locale_from_utf8 here
#if defined(_WIN32) || defined(_WIN64)
  char bname[_MAX_DIR];
  char extname[_MAX_EXT];
  char *path;
  size_t ridx;
  char buffer[_MAX_DIR + _MAX_EXT];
  mrb_value s;

  mrb_get_args(mrb, "S", &s);
  path = mrb_str_to_cstr(mrb, s);
  ridx = strlen(path);
  if (ridx > 0) {
    ridx--;
    while (ridx > 0 && (path[ridx] == '/' || path[ridx] == '\\')) {
      path[ridx] = '\0';
      ridx--;
    }
    if (strncmp(path, "/", 2) == 0) {
      return mrb_str_new_cstr(mrb, path);
    }
  }
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
  if (strncmp(bname, "//", 3) == 0) bname[1] = '\0';  /* patch for Cygwin */
  return mrb_str_new_cstr(mrb, bname);
#endif
}

static mrb_value
mrb_file_realpath(mrb_state *mrb, mrb_value klass)
{
  mrb_value pathname, dir_string, s, result;
  mrb_int argc;
  char *cpath;

  argc = mrb_get_args(mrb, "S|S", &pathname, &dir_string);
  if (argc == 2) {
    s = mrb_str_dup(mrb, dir_string);
    s = mrb_str_append(mrb, s, mrb_str_new_cstr(mrb, FILE_SEPARATOR));
    s = mrb_str_append(mrb, s, pathname);
    pathname = s;
  }
  cpath = mrb_locale_from_utf8(mrb_str_to_cstr(mrb, pathname), -1);
  result = mrb_str_buf_new(mrb, PATH_MAX);
  if (realpath(cpath, RSTRING_PTR(result)) == NULL) {
    mrb_locale_free(cpath);
    mrb_sys_fail(mrb, cpath);
  }
  mrb_locale_free(cpath);
  mrb_str_resize(mrb, result, strlen(RSTRING_PTR(result)));
  return result;
}

mrb_value
mrb_file__getwd(mrb_state *mrb, mrb_value klass)
{
  mrb_value path;
  char buf[MAXPATHLEN], *utf8;

  if (GETCWD(buf, MAXPATHLEN) == NULL) {
    mrb_sys_fail(mrb, "getcwd(2)");
  }
  utf8 = mrb_utf8_from_locale(buf, -1);
  path = mrb_str_new_cstr(mrb, utf8);
  mrb_utf8_free(utf8);
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
  mrb_int argc;
  char *home;
  mrb_value path;

#ifndef _WIN32
  mrb_value username;

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
  home = mrb_locale_from_utf8(home, -1);
  path = mrb_str_new_cstr(mrb, home);
  mrb_locale_free(home);
  return path;
#else
  argc = mrb_get_argc(mrb);
  if (argc == 0) {
    home = getenv("USERPROFILE");
    if (home == NULL) {
      return mrb_nil_value();
    }
    if (!mrb_file_is_absolute_path(home)) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "non-absolute home");
    }
  } else {
    return mrb_nil_value();
  }
  home = mrb_locale_from_utf8(home, -1);
  path = mrb_str_new_cstr(mrb, home);
  mrb_locale_free(home);
  return path;
#endif
}

static mrb_value
mrb_file_mtime(mrb_state *mrb, mrb_value self)
{
  mrb_value obj;
  struct stat st;
  int fd;

  obj = mrb_obj_value(mrb_class_get(mrb, "Time"));
  fd = (int)mrb_fixnum(mrb_io_fileno(mrb, self));
  if (fstat(fd, &st) == -1)
    return mrb_false_value();
#ifndef MRB_WITHOUT_FLOAT
  return mrb_funcall(mrb, obj, "at", 1, mrb_float_value(mrb, st.st_mtime));
#else
  return mrb_funcall(mrb, obj, "at", 1, mrb_fixnum_value(st.st_mtime));
#endif
}

mrb_value
mrb_file_flock(mrb_state *mrb, mrb_value self)
{
#if defined(sun)
  mrb_raise(mrb, E_NOTIMP_ERROR, "flock is not supported on Illumos/Solaris/Windows");
#else
  mrb_int operation;
  int fd;

  mrb_get_args(mrb, "i", &operation);
  fd = (int)mrb_fixnum(mrb_io_fileno(mrb, self));

  while (flock(fd, (int)operation) == -1) {
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

static mrb_value
mrb_file_s_symlink(mrb_state *mrb, mrb_value klass)
{
#if defined(_WIN32) || defined(_WIN64)
  mrb_raise(mrb, E_NOTIMP_ERROR, "symlink is not supported on this platform");
#else
  mrb_value from, to;
  const char *src, *dst;
  int ai = mrb_gc_arena_save(mrb);

  mrb_get_args(mrb, "SS", &from, &to);
  src = mrb_locale_from_utf8(mrb_str_to_cstr(mrb, from), -1);
  dst = mrb_locale_from_utf8(mrb_str_to_cstr(mrb, to), -1);

  if (symlink(src, dst) == -1) {
    mrb_locale_free(src);
    mrb_locale_free(dst);
    mrb_sys_fail(mrb, mrb_str_to_cstr(mrb, mrb_format(mrb, "(%S, %S)", from, to)));
  }
  mrb_locale_free(src);
  mrb_locale_free(dst);
  mrb_gc_arena_restore(mrb, ai);
#endif
  return mrb_fixnum_value(0);
}

static mrb_value
mrb_file_s_chmod(mrb_state *mrb, mrb_value klass) {
  mrb_int mode;
  mrb_int argc, i;
  mrb_value *filenames;
  int ai = mrb_gc_arena_save(mrb);

  mrb_get_args(mrb, "i*", &mode, &filenames, &argc);
  for (i = 0; i < argc; i++) {
    const char *utf8_path = mrb_str_to_cstr(mrb, filenames[i]);
    char *path = mrb_locale_from_utf8(utf8_path, -1);
    if (CHMOD(path, mode) == -1) {
      mrb_locale_free(path);
      mrb_sys_fail(mrb, utf8_path);
    }
    mrb_locale_free(path);
  }

  mrb_gc_arena_restore(mrb, ai);
  return mrb_fixnum_value(argc);
}

static mrb_value
mrb_file_s_readlink(mrb_state *mrb, mrb_value klass) {
#if defined(_WIN32) || defined(_WIN64)
  mrb_raise(mrb, E_NOTIMP_ERROR, "readlink is not supported on this platform");
  return mrb_nil_value(); // unreachable
#else
  char *path, *buf, *tmp;
  size_t bufsize = 100;
  ssize_t rc;
  mrb_value ret;
  int ai = mrb_gc_arena_save(mrb);

  mrb_get_args(mrb, "z", &path);
  tmp = mrb_locale_from_utf8(path, -1);

  buf = (char *)mrb_malloc(mrb, bufsize);
  while ((rc = readlink(tmp, buf, bufsize)) == (ssize_t)bufsize && rc != -1) {
    bufsize *= 2;
    buf = (char *)mrb_realloc(mrb, buf, bufsize);
  }
  mrb_locale_free(tmp);
  if (rc == -1) {
    mrb_free(mrb, buf);
    mrb_sys_fail(mrb, path);
  }
  tmp = mrb_utf8_from_locale(buf, -1);
  ret = mrb_str_new(mrb, tmp, rc);
  mrb_locale_free(tmp);
  mrb_free(mrb, buf);

  mrb_gc_arena_restore(mrb, ai);
  return ret;
#endif
}

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
  mrb_define_class_method(mrb, file, "symlink", mrb_file_s_symlink, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, file, "chmod", mrb_file_s_chmod, MRB_ARGS_REQ(1) | MRB_ARGS_REST());
  mrb_define_class_method(mrb, file, "readlink", mrb_file_s_readlink, MRB_ARGS_REQ(1));

  mrb_define_class_method(mrb, file, "dirname",   mrb_file_dirname,    MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, file, "basename",  mrb_file_basename,   MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, file, "realpath",  mrb_file_realpath,   MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, file, "_getwd",    mrb_file__getwd,     MRB_ARGS_NONE());
  mrb_define_class_method(mrb, file, "_gethome",  mrb_file__gethome,   MRB_ARGS_OPT(1));

  mrb_define_method(mrb, file, "flock", mrb_file_flock, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, file, "mtime", mrb_file_mtime, MRB_ARGS_NONE());

  cnst = mrb_define_module_under(mrb, file, "Constants");
  mrb_define_const(mrb, cnst, "LOCK_SH", mrb_fixnum_value(LOCK_SH));
  mrb_define_const(mrb, cnst, "LOCK_EX", mrb_fixnum_value(LOCK_EX));
  mrb_define_const(mrb, cnst, "LOCK_UN", mrb_fixnum_value(LOCK_UN));
  mrb_define_const(mrb, cnst, "LOCK_NB", mrb_fixnum_value(LOCK_NB));
  mrb_define_const(mrb, cnst, "SEPARATOR", mrb_str_new_cstr(mrb, FILE_SEPARATOR));
  mrb_define_const(mrb, cnst, "PATH_SEPARATOR", mrb_str_new_cstr(mrb, PATH_SEPARATOR));
#if defined(_WIN32) || defined(_WIN64)
  mrb_define_const(mrb, cnst, "ALT_SEPARATOR", mrb_str_new_cstr(mrb, FILE_ALT_SEPARATOR));
#else
  mrb_define_const(mrb, cnst, "ALT_SEPARATOR", mrb_nil_value());
#endif
  mrb_define_const(mrb, cnst, "NULL", mrb_str_new_cstr(mrb, NULL_FILE));

}
