/**
 * original is https://github.com/ruby/ruby/blob/trunk/file.c
 */

#include "mruby.h"
#include "mruby/string.h"
#include "mruby/data.h"
#include "mruby/error.h"
#include "mruby/class.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)

#if !defined S_IXUSR && !defined __MINGW32__
#  define S_IXUSR 0100
#endif
#ifndef S_IXGRP
#  define S_IXGRP 0010
#endif
#ifndef S_IXOTH
#  define S_IXOTH 0001
#endif

#else
#include <unistd.h>
#endif

#ifndef S_IRUGO
#  define S_IRUGO (S_IRUSR | S_IRGRP | S_IROTH)
#endif

#ifndef S_IWUGO
#  define S_IWUGO (S_IWUSR | S_IWGRP | S_IWOTH)
#endif

#ifndef S_IXUGO
#  define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)
#endif

#ifndef S_ISLNK
#  ifdef _S_ISLNK
#    define S_ISLNK(m) _S_ISLNK(m)
#  else
#    ifdef _S_IFLNK
#      define S_ISLNK(m) (((m) & S_IFMT) == _S_IFLNK)
#    else
#      ifdef S_IFLNK
#        define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#      endif
#    endif
#  endif
#endif

#ifdef S_IFIFO
#  ifndef S_ISFIFO
#    define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#  endif
#endif

#ifndef S_ISSOCK
#  ifdef _S_ISSOCK
#    define S_ISSOCK(m) _S_ISSOCK(m)
#  else
#    ifdef _S_IFSOCK
#      define S_ISSOCK(m) (((m) & S_IFMT) == _S_IFSOCK)
#    else
#      ifdef S_IFSOCK
#	 define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#      endif
#    endif
#  endif
#endif

#ifndef S_ISBLK
#  ifdef S_IFBLK
#    define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#  else
#    define S_ISBLK(m) (0)  /* anytime false */
#  endif
#endif

#ifndef S_ISCHR
#  define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif

#ifndef S_ISREG
#  define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

#ifndef S_ISDIR
#  define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

#include "extconf.h"

#define STAT(p,s) stat(p,s)
#ifdef HAVE_LSTAT
#  define LSTAT(p,s) lstat(p,s)
#else
#  define LSTAT(p,s) stat(p,s)
#endif
#define MRB_MAX_GROUPS (65536)

#if defined(_WIN32) || defined(_WIN64)
typedef unsigned int uid_t;
typedef unsigned int gid_t;
uid_t
getuid(void)
{
  return 0;
}
uid_t
geteuid(void)
{
  return 0;
}
gid_t
getgid(void)
{
  return 0;
}
gid_t
getegid(void)
{
  return 0;
}
#endif
#define GETGROUPS_T gid_t

#if defined(S_IXGRP) && !defined(_WIN32) && !defined(__CYGWIN__)
#  define USE_GETEUID 1
#endif

#ifdef __native_client__
#  undef USE_GETEUID
#endif

struct mrb_data_type mrb_stat_type = { "File::Stat", mrb_free };

static struct stat *
mrb_stat_alloc(mrb_state *mrb)
{
  return (struct stat *)mrb_malloc(mrb, sizeof(struct stat));
}

static mrb_value
file_s_lstat(mrb_state *mrb, mrb_value klass)
{
  struct RClass *file_class;
  struct RClass *stat_class;
  struct stat st, *ptr;
  mrb_value fname;
  mrb_get_args(mrb, "S", &fname);

  if (LSTAT(RSTRING_PTR(fname), &st) == -1) {
    mrb_sys_fail(mrb, RSTRING_PTR(fname));
  }

  file_class = mrb_class_ptr(klass);
  stat_class = mrb_class_get_under(mrb, file_class, "Stat");
  ptr = mrb_stat_alloc(mrb);
  *ptr = st;

  return mrb_obj_value(Data_Wrap_Struct(mrb, stat_class, &mrb_stat_type, ptr));
}

static mrb_value
stat_initialize(mrb_state *mrb, mrb_value self)
{
  struct stat st, *ptr;
  mrb_value fname;

  mrb_get_args(mrb, "S", &fname);

  if (STAT(RSTRING_PTR(fname), &st) == -1) {
    mrb_sys_fail(mrb, RSTRING_PTR(fname));
  }

  ptr = (struct stat *)DATA_PTR(self);
  if (ptr) {
    mrb_free(mrb, ptr);
  }

  ptr = mrb_stat_alloc(mrb);
  *ptr = st;

  DATA_TYPE(self) = &mrb_stat_type;
  DATA_PTR(self) = ptr;

  return mrb_nil_value();
}

static mrb_value
stat_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_value orig;

  mrb_get_args(mrb, "o", &orig);

  if (mrb_obj_equal(mrb, copy, orig)) return copy;

  if (!mrb_obj_is_instance_of(mrb, orig, mrb_obj_class(mrb, copy))) {
    mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }

  if (DATA_PTR(copy)) {
    mrb_free(mrb, DATA_PTR(copy));
    DATA_PTR(copy) = 0;
  }

  if (DATA_PTR(orig)) {
    DATA_PTR(copy) = mrb_malloc(mrb, sizeof(struct stat));
    DATA_TYPE(copy) = &mrb_stat_type;
    *(struct stat *)DATA_PTR(copy) = *(struct stat *)DATA_PTR(orig);
  }
  return copy;
}

static struct stat *
get_stat(mrb_state *mrb, mrb_value self)
{
  struct stat *st;

  st = (struct stat *)mrb_data_get_ptr(mrb, self, &mrb_stat_type);
  if (!st) mrb_raise(mrb, E_TYPE_ERROR, "uninitialized File::Stat");
  return st;
}

static mrb_value
mrb_ll2num(mrb_state *mrb, long long t)
{
  if (MRB_INT_MIN <= t && t <= MRB_INT_MAX) {
    return mrb_fixnum_value((mrb_int)t);
  } else {
    return mrb_float_value(mrb, (mrb_float)t);
  }
}

static mrb_value
io_stat(mrb_state *mrb, mrb_value self)
{
  struct RClass *file_class;
  struct RClass *stat_class;
  struct stat st, *ptr;
  mrb_value fileno;

  if (mrb_respond_to(mrb, self, mrb_intern_lit(mrb, "fileno"))) {
    fileno = mrb_funcall(mrb, self, "fileno", 0);
  }
  else {
    mrb_raise(mrb, E_NOTIMP_ERROR, "`fileno' is not implemented");
  }

  if (fstat(mrb_fixnum(fileno), &st) == -1) {
    mrb_sys_fail(mrb, "fstat");
  }

  file_class = mrb_class_get(mrb, "File");
  stat_class = mrb_class_get_under(mrb, file_class, "Stat");
  ptr = mrb_stat_alloc(mrb);
  *ptr = st;

  return mrb_obj_value(Data_Wrap_Struct(mrb, stat_class, &mrb_stat_type, ptr));
}

static mrb_value
stat_dev(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(get_stat(mrb, self)->st_dev);
}

static mrb_value
stat_dev_major(mrb_state *mrb, mrb_value self)
{
#if defined(major)
  return mrb_fixnum_value(major(get_stat(mrb, self)->st_dev));
#else
  return mrb_nil_value(); // NotImplemented
#endif
}

static mrb_value
stat_dev_minor(mrb_state *mrb, mrb_value self)
{
#if defined(minor)
  return mrb_fixnum_value(minor(get_stat(mrb, self)->st_dev));
#else
  return mrb_nil_value(); // NotImplemented
#endif
}

static mrb_value
stat_ino(mrb_state *mrb, mrb_value self)
{
  return mrb_ll2num(mrb, get_stat(mrb, self)->st_ino);
}

static mrb_value
stat_mode(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(get_stat(mrb, self)->st_mode);
}

static mrb_value
stat_nlink(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(get_stat(mrb, self)->st_nlink);
}

static mrb_value
stat_uid(mrb_state *mrb, mrb_value self)
{
  return mrb_ll2num(mrb, get_stat(mrb, self)->st_uid);
}

static mrb_value
stat_gid(mrb_state *mrb, mrb_value self)
{
  return mrb_ll2num(mrb, get_stat(mrb, self)->st_gid);
}

static mrb_value
stat_rdev(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(get_stat(mrb, self)->st_rdev);
}

static mrb_value
stat_rdev_major(mrb_state *mrb, mrb_value self)
{
#if defined(major)
  return mrb_fixnum_value(major(get_stat(mrb, self)->st_rdev));
#else
  return mrb_nil_value(); // NotImplemented
#endif
}

static mrb_value
stat_rdev_minor(mrb_state *mrb, mrb_value self)
{
#if defined(minor)
  return mrb_fixnum_value(minor(get_stat(mrb, self)->st_rdev));
#else
  return mrb_nil_value(); // NotImplemented
#endif
}

static mrb_value
time_at_with_sec(mrb_state *mrb, long long sec)
{
  return mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "Time")), "at", 1, mrb_ll2num(mrb, sec));
}

static mrb_value
stat_atime(mrb_state *mrb, mrb_value self)
{
  return time_at_with_sec(mrb, get_stat(mrb, self)->st_atime);
}

static mrb_value
stat_mtime(mrb_state *mrb, mrb_value self)
{
  return time_at_with_sec(mrb, get_stat(mrb, self)->st_mtime);
}

static mrb_value
stat_ctime(mrb_state *mrb, mrb_value self)
{
  return time_at_with_sec(mrb, get_stat(mrb, self)->st_ctime);
}

#if defined(HAVE_STRUCT_STAT_ST_BIRTHTIMESPEC)
static mrb_value
stat_birthtime(mrb_state *mrb, mrb_value self)
{
  return time_at_with_sec(mrb, get_stat(mrb, self)->st_birthtimespec.tv_sec);
}
# define HAVE_METHOD_BIRTHTIME 1
#elif defined(_WIN32)
# define stat_birthtime stat_ctime
# define HAVE_METHOD_BIRTHTIME 1
#endif

static mrb_value
stat_size(mrb_state *mrb, mrb_value self)
{
  return mrb_ll2num(mrb, get_stat(mrb, self)->st_size);
}

static mrb_value
stat_blksize(mrb_state *mrb, mrb_value self)
{
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
  return mrb_fixnum_value(get_stat(mrb, self)->st_blksize);
#else
  return mrb_nil_value();
#endif
}

static mrb_value
stat_blocks(mrb_state *mrb, mrb_value self)
{
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
  return mrb_ll2num(mrb, get_stat(mrb, self)->st_blocks);
#else
  return mrb_nil_value();
#endif
}

static int
mrb_group_member(mrb_state *mrb, GETGROUPS_T gid)
{
#if defined(_WIN32) || !defined(HAVE_GETGROUPS)
  return FALSE;
#else
  int rv = FALSE;
  int groups = 16;
  GETGROUPS_T *gary = NULL;
  int anum = -1;

  if (getgid() == gid || getegid() == gid)
    return TRUE;

  /*
   * On Mac OS X (Mountain Lion), NGROUPS is 16. But libc and kernel
   * accept more larger value.
   * So we don't trunk NGROUPS anymore.
   */
  while (groups <= MRB_MAX_GROUPS) {
    gary = (GETGROUPS_T*)mrb_malloc(mrb, sizeof(GETGROUPS_T) * (unsigned int)groups);
    anum = getgroups(groups, gary);
    if (anum != -1 && anum != groups)
      break;
    groups *= 2;
    if (gary) {
      mrb_free(mrb, gary);
      gary = 0;
    }
  }
  if (anum == -1)
    return FALSE;

  while (--anum >= 0) {
    if (gary[anum] == gid) {
      rv = TRUE;
      break;
    }
  }

  if (gary) {
    mrb_free(mrb, gary);
  }
  return rv;
#endif
}

static mrb_value
stat_grpowned_p(mrb_state *mrb, mrb_value self)
{
#ifndef _WIN32
  if (mrb_group_member(mrb, get_stat(mrb, self)->st_gid)) return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_readable_p(mrb_state *mrb, mrb_value self)
{
  struct stat *st;
#ifdef USE_GETEUID
  if (geteuid() == 0)
    return mrb_true_value();
#endif
  st = get_stat(mrb, self);
#ifdef S_IRUSR
  if (st->st_uid == geteuid())
    return st->st_mode & S_IRUSR ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IRGRP
  if (mrb_group_member(mrb, st->st_gid))
    return st->st_mode & S_IRGRP ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IROTH
  if (!(st->st_mode & S_IROTH))
    return mrb_false_value();
#endif
  return mrb_true_value();
}

static mrb_value
stat_readable_real_p(mrb_state *mrb, mrb_value self)
{
  struct stat *st;

#ifdef USE_GETEUID
  if (getuid() == 0)
    return mrb_true_value();
#endif
  st = get_stat(mrb, self);
#ifdef S_IRUSR
  if (st->st_uid == getuid())
    return st->st_mode & S_IRUSR ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IRGRP
  if (mrb_group_member(mrb, st->st_gid))
    return st->st_mode & S_IRGRP ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IROTH
  if (!(st->st_mode & S_IROTH)) return mrb_false_value();
#endif
  return mrb_true_value();
}

static mrb_value
stat_world_readable_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_IROTH
  struct stat *st = get_stat(mrb, self);
  if ((st->st_mode & (S_IROTH)) == S_IROTH) {
    return mrb_fixnum_value(st->st_mode & (S_IRUGO|S_IWUGO|S_IXUGO));
  }
  else {
    return mrb_nil_value();
  }
#else
  return mrb_nil_value();
#endif
}


static mrb_value
stat_writable_p(mrb_state *mrb, mrb_value self)
{
  struct stat *st;

#ifdef USE_GETEUID
  if (geteuid() == 0)
    return mrb_true_value();
#endif
  st = get_stat(mrb, self);
#ifdef S_IWUSR
  if (st->st_uid == geteuid())
    return st->st_mode & S_IWUSR ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IWGRP
  if (mrb_group_member(mrb, st->st_gid))
    return st->st_mode & S_IWGRP ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IWOTH
  if (!(st->st_mode & S_IWOTH))
    return mrb_false_value();
#endif
  return mrb_true_value();
}

static mrb_value
stat_writable_real_p(mrb_state *mrb, mrb_value self)
{
  struct stat *st;

#ifdef USE_GETEUID
  if (getuid() == 0)
    return mrb_true_value();
#endif
  st = get_stat(mrb, self);
#ifdef S_IWUSR
  if (st->st_uid == getuid())
    return st->st_mode & S_IWUSR ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IWGRP
  if (mrb_group_member(mrb, st->st_gid))
    return st->st_mode & S_IWGRP ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IWOTH
  if (!(st->st_mode & S_IWOTH)) return mrb_false_value();
#endif
  return mrb_true_value();
}

static mrb_value
stat_world_writable_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_IROTH
  struct stat *st = get_stat(mrb, self);
  if ((st->st_mode & (S_IROTH)) == S_IROTH) {
    return mrb_fixnum_value(st->st_mode & (S_IRUGO|S_IWUGO|S_IXUGO));
  }
  else {
    return mrb_nil_value();
  }
#else
  return mrb_nil_value();
#endif
}

static mrb_value
stat_executable_p(mrb_state *mrb, mrb_value self)
{
  struct stat *st = get_stat(mrb, self);

#ifdef USE_GETEUID
  if (geteuid() == 0) {
    return st->st_mode & S_IXUGO ? mrb_true_value() : mrb_false_value();
}
#endif
#ifdef S_IXUSR
  if (st->st_uid == geteuid())
    return st->st_mode & S_IXUSR ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IXGRP
  if (mrb_group_member(mrb, st->st_gid))
    return st->st_mode & S_IXGRP ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IXOTH
  if (!(st->st_mode & S_IXOTH))
    return mrb_false_value();
#endif
  return mrb_true_value();
}

static mrb_value
stat_executable_real_p(mrb_state *mrb, mrb_value self)
{
  struct stat *st = get_stat(mrb, self);

#ifdef USE_GETEUID
  if (getuid() == 0)
    return st->st_mode & S_IXUGO ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IXUSR
  if (st->st_uid == getuid())
    return st->st_mode & S_IXUSR ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IXGRP
  if (mrb_group_member(mrb, st->st_gid))
    return st->st_mode & S_IXGRP ? mrb_true_value() : mrb_false_value();
#endif
#ifdef S_IXOTH
  if (!(st->st_mode & S_IXOTH)) return mrb_false_value();
#endif
  return mrb_true_value();
}

static mrb_value
stat_symlink_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISLNK
  if (S_ISLNK(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_file_p(mrb_state *mrb, mrb_value self)
{
  if (S_ISREG(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
  return mrb_false_value();
}

static mrb_value
stat_directory_p(mrb_state *mrb, mrb_value self)
{
  if (S_ISDIR(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
  return mrb_false_value();
}

static mrb_value
stat_chardev_p(mrb_state *mrb, mrb_value self)
{
  if (S_ISCHR(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
  return mrb_false_value();
}

static mrb_value
stat_blockdev_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISBLK
  if (S_ISBLK(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_pipe_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISFIFO
  if (S_ISFIFO(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_socket_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISSOCK
  if (S_ISSOCK(get_stat(mrb, self)->st_mode))
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_setuid_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISUID
  if (get_stat(mrb, self)->st_mode & S_ISUID)
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_setgid_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISGID
  if (get_stat(mrb, self)->st_mode & S_ISGID)
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_sticky_p(mrb_state *mrb, mrb_value self)
{
#ifdef S_ISVTX
  if (get_stat(mrb, self)->st_mode & S_ISVTX)
    return mrb_true_value();
#endif
  return mrb_false_value();
}

static mrb_value
stat_ftype(mrb_state *mrb, mrb_value self)
{
  struct stat *st = get_stat(mrb, self);
  const char *t;

  if (S_ISREG(st->st_mode)) {
    t = "file";
  }
  else if (S_ISDIR(st->st_mode)) {
    t = "directory";
  }
  else if (S_ISCHR(st->st_mode)) {
    t = "characterSpecial";
  }
#ifdef S_ISBLK
  else if (S_ISBLK(st->st_mode)) {
    t = "blockSpecial";
  }
#endif
#ifdef S_ISFIFO
  else if (S_ISFIFO(st->st_mode)) {
    t = "fifo";
  }
#endif
#ifdef S_ISLNK
  else if (S_ISLNK(st->st_mode)) {
    t = "link";
  }
#endif
#ifdef S_ISSOCK
  else if (S_ISSOCK(st->st_mode)) {
    t = "socket";
  }
#endif
  else {
    t = "unknown";
  }
  return mrb_str_new_static(mrb, t, (size_t)strlen(t));
}

static mrb_value
stat_owned_p(mrb_state *mrb, mrb_value self)
{
  return get_stat(mrb, self)->st_uid == geteuid() ? mrb_true_value() : mrb_false_value();
}

static mrb_value
stat_owned_real_p(mrb_state *mrb, mrb_value self)
{
  return get_stat(mrb, self)->st_uid == getuid() ? mrb_true_value() : mrb_false_value();
}

void
mrb_mruby_file_stat_gem_init(mrb_state* mrb)
{
  struct RClass *io = mrb_define_class(mrb, "IO", mrb->object_class);
  struct RClass *file = mrb_define_class(mrb, "File", io);
  struct RClass *stat = mrb_define_class_under(mrb, file, "Stat", mrb->object_class);

  MRB_SET_INSTANCE_TT(stat, MRB_TT_DATA);

  mrb_define_method(mrb, io, "stat", io_stat, MRB_ARGS_NONE());

  mrb_define_class_method(mrb, file, "lstat", file_s_lstat, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, stat, "initialize", stat_initialize, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, stat, "initialize_copy", stat_initialize_copy, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, stat, "dev", stat_dev, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "dev_major", stat_dev_major, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "dev_minor", stat_dev_minor, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "ino", stat_ino, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "mode", stat_mode, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "nlink", stat_nlink, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "uid", stat_uid, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "gid", stat_gid, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "rdev", stat_rdev, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "rdev_major", stat_rdev_major, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "rdev_minor", stat_rdev_minor, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "atime", stat_atime, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "mtime", stat_mtime, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "ctime", stat_ctime, MRB_ARGS_NONE());
#ifdef HAVE_METHOD_BIRTHTIME
  mrb_define_method(mrb, stat, "birthtime", stat_birthtime, MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, stat, "size", stat_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "blksize", stat_blksize, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "blocks", stat_blocks, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "grpowned?", stat_grpowned_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "readable?", stat_readable_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "readable_real?", stat_readable_real_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "world_readable?", stat_world_readable_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "writable?", stat_writable_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "writable_real?", stat_writable_real_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "world_writable?", stat_world_writable_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "executable?", stat_executable_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "executable_real?", stat_executable_real_p, MRB_ARGS_NONE());

  mrb_define_method(mrb, stat, "symlink?", stat_symlink_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "file?", stat_file_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "directory?", stat_directory_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "chardev?", stat_chardev_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "blockdev?", stat_blockdev_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "pipe?", stat_pipe_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "socket?", stat_socket_p, MRB_ARGS_NONE());

  mrb_define_method(mrb, stat, "setuid?", stat_setuid_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "setgid?", stat_setgid_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "sticky?", stat_sticky_p, MRB_ARGS_NONE());

  mrb_define_method(mrb, stat, "ftype", stat_ftype, MRB_ARGS_NONE());

  mrb_define_method(mrb, stat, "owned?", stat_owned_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, stat, "owned_real?", stat_owned_real_p, MRB_ARGS_NONE());
}

void
mrb_mruby_file_stat_gem_final(mrb_state* mrb)
{
}
