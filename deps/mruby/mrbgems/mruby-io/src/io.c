/*
** io.c - IO class
*/

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/hash.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include "mruby/ext/io.h"
#include "mruby/error.h"

#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_WIN64)
  #include <winsock.h>
  #include <io.h>
  #define open  _open
  #define close _close
  #define dup _dup
  #define dup2 _dup2
  #define read  _read
  #define write _write
  #define lseek _lseek
  #define isatty _isatty
  #define WEXITSTATUS(x) (x)
  typedef int fsize_t;
  typedef long ftime_t;
  typedef long fsuseconds_t;
  typedef int fmode_t;
  typedef int mrb_io_read_write_size;

  #ifndef O_TMPFILE
    #define O_TMPFILE O_TEMPORARY
  #endif

#else
  #include <sys/wait.h>
  #include <sys/time.h>
  #include <unistd.h>
  typedef size_t fsize_t;
  typedef time_t ftime_t;
  typedef suseconds_t fsuseconds_t;
  typedef mode_t fmode_t;
  typedef ssize_t mrb_io_read_write_size;
#endif

#ifdef _MSC_VER
typedef mrb_int pid_t;
#endif

#include <fcntl.h>

#include <errno.h>
#include <string.h>

#define OPEN_ACCESS_MODE_FLAGS (O_RDONLY | O_WRONLY | O_RDWR)
#define OPEN_RDONLY_P(f)       ((mrb_bool)(((f) & OPEN_ACCESS_MODE_FLAGS) == O_RDONLY))
#define OPEN_WRONLY_P(f)       ((mrb_bool)(((f) & OPEN_ACCESS_MODE_FLAGS) == O_WRONLY))
#define OPEN_RDWR_P(f)         ((mrb_bool)(((f) & OPEN_ACCESS_MODE_FLAGS) == O_RDWR))
#define OPEN_READABLE_P(f)     ((mrb_bool)(OPEN_RDONLY_P(f) || OPEN_RDWR_P(f)))
#define OPEN_WRITABLE_P(f)     ((mrb_bool)(OPEN_WRONLY_P(f) || OPEN_RDWR_P(f)))

static void mrb_io_free(mrb_state *mrb, void *ptr);
struct mrb_data_type mrb_io_type = { "IO", mrb_io_free };


static struct mrb_io *io_get_open_fptr(mrb_state *mrb, mrb_value self);
static int mrb_io_modestr_to_flags(mrb_state *mrb, const char *modestr);
static int mrb_io_mode_to_flags(mrb_state *mrb, mrb_value mode);
static void fptr_finalize(mrb_state *mrb, struct mrb_io *fptr, int quiet);

static struct mrb_io *
io_get_open_fptr(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr;

  fptr = (struct mrb_io *)mrb_data_get_ptr(mrb, self, &mrb_io_type);
  if (fptr == NULL) {
    mrb_raise(mrb, E_IO_ERROR, "uninitialized stream.");
  }
  if (fptr->fd < 0) {
    mrb_raise(mrb, E_IO_ERROR, "closed stream.");
  }
  return fptr;
}

static void
io_set_process_status(mrb_state *mrb, pid_t pid, int status)
{
  struct RClass *c_process, *c_status;
  mrb_value v;

  c_status = NULL;
  if (mrb_class_defined(mrb, "Process")) {
    c_process = mrb_module_get(mrb, "Process");
    if (mrb_const_defined(mrb, mrb_obj_value(c_process), mrb_intern_cstr(mrb, "Status"))) {
      c_status = mrb_class_get_under(mrb, c_process, "Status");
    }
  }
  if (c_status != NULL) {
    v = mrb_funcall(mrb, mrb_obj_value(c_status), "new", 2, mrb_fixnum_value(pid), mrb_fixnum_value(status));
  } else {
    v = mrb_fixnum_value(WEXITSTATUS(status));
  }
  mrb_gv_set(mrb, mrb_intern_cstr(mrb, "$?"), v);
}

static int
mrb_io_modestr_to_flags(mrb_state *mrb, const char *mode)
{
  int flags;
  const char *m = mode;

  switch (*m++) {
    case 'r':
      flags = O_RDONLY;
      break;
    case 'w':
      flags = O_WRONLY | O_CREAT | O_TRUNC;
      break;
    case 'a':
      flags = O_WRONLY | O_CREAT | O_APPEND;
      break;
    default:
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "illegal access mode %s", mode);
      flags = 0; /* not reached */
  }

  while (*m) {
    switch (*m++) {
      case 'b':
#ifdef O_BINARY
        flags |= O_BINARY;
#endif
        break;
      case '+':
        flags = (flags & ~OPEN_ACCESS_MODE_FLAGS) | O_RDWR;
        break;
      case ':':
        /* XXX: PASSTHROUGH*/
      default:
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "illegal access mode %s", mode);
    }
  }

  return flags;
}

static int
mrb_io_mode_to_flags(mrb_state *mrb, mrb_value mode)
{
  if (mrb_nil_p(mode)) {
    return mrb_io_modestr_to_flags(mrb, "r");
  }
  else if (mrb_string_p(mode)) {
    return mrb_io_modestr_to_flags(mrb, RSTRING_CSTR(mrb, mode));
  }
  else {
    int flags = 0;
    mrb_int flags0 = mrb_int(mrb, mode);

    switch (flags0 & MRB_O_ACCMODE) {
      case MRB_O_RDONLY:
        flags |= O_RDONLY;
        break;
      case MRB_O_WRONLY:
        flags |= O_WRONLY;
        break;
      case MRB_O_RDWR:
        flags |= O_RDWR;
        break;
      default:
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "illegal access mode %v", mode);
    }

    if (flags0 & MRB_O_APPEND)        flags |= O_APPEND;
    if (flags0 & MRB_O_CREAT)         flags |= O_CREAT;
    if (flags0 & MRB_O_EXCL)          flags |= O_EXCL;
    if (flags0 & MRB_O_TRUNC)         flags |= O_TRUNC;
#ifdef O_NONBLOCK
    if (flags0 & MRB_O_NONBLOCK)      flags |= O_NONBLOCK;
#endif
#ifdef O_NOCTTY
    if (flags0 & MRB_O_NOCTTY)        flags |= O_NOCTTY;
#endif
#ifdef O_BINARY
    if (flags0 & MRB_O_BINARY)        flags |= O_BINARY;
#endif
#ifdef O_SHARE_DELETE
    if (flags0 & MRB_O_SHARE_DELETE)  flags |= O_SHARE_DELETE;
#endif
#ifdef O_SYNC
    if (flags0 & MRB_O_SYNC)          flags |= O_SYNC;
#endif
#ifdef O_DSYNC
    if (flags0 & MRB_O_DSYNC)         flags |= O_DSYNC;
#endif
#ifdef O_RSYNC
    if (flags0 & MRB_O_RSYNC)         flags |= O_RSYNC;
#endif
#ifdef O_NOFOLLOW
    if (flags0 & MRB_O_NOFOLLOW)      flags |= O_NOFOLLOW;
#endif
#ifdef O_NOATIME
    if (flags0 & MRB_O_NOATIME)       flags |= O_NOATIME;
#endif
#ifdef O_DIRECT
    if (flags0 & MRB_O_DIRECT)        flags |= O_DIRECT;
#endif
#ifdef O_TMPFILE
    if (flags0 & MRB_O_TMPFILE)       flags |= O_TMPFILE;
#endif

    return flags;
  }
}

static void
mrb_fd_cloexec(mrb_state *mrb, int fd)
{
#if defined(F_GETFD) && defined(F_SETFD) && defined(FD_CLOEXEC)
  int flags, flags2;

  flags = fcntl(fd, F_GETFD);
  if (flags == -1) {
    mrb_bug(mrb, "mrb_fd_cloexec: fcntl(%d, F_GETFD) failed: %d", fd, errno);
  }
  if (fd <= 2) {
    flags2 = flags & ~FD_CLOEXEC; /* Clear CLOEXEC for standard file descriptors: 0, 1, 2. */
  }
  else {
    flags2 = flags | FD_CLOEXEC; /* Set CLOEXEC for non-standard file descriptors: 3, 4, 5, ... */
  }
  if (flags != flags2) {
    if (fcntl(fd, F_SETFD, flags2) == -1) {
      mrb_bug(mrb, "mrb_fd_cloexec: fcntl(%d, F_SETFD, %d) failed: %d", fd, flags2, errno);
    }
  }
#endif
}

#if !defined(_WIN32) && !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
static int
mrb_cloexec_pipe(mrb_state *mrb, int fildes[2])
{
  int ret;
  ret = pipe(fildes);
  if (ret == -1)
    return -1;
  mrb_fd_cloexec(mrb, fildes[0]);
  mrb_fd_cloexec(mrb, fildes[1]);
  return ret;
}

static int
mrb_pipe(mrb_state *mrb, int pipes[2])
{
  int ret;
  ret = mrb_cloexec_pipe(mrb, pipes);
  if (ret == -1) {
    if (errno == EMFILE || errno == ENFILE) {
      mrb_garbage_collect(mrb);
      ret = mrb_cloexec_pipe(mrb, pipes);
    }
  }
  return ret;
}

static int
mrb_proc_exec(const char *pname)
{
  const char *s;
  s = pname;

  while (*s == ' ' || *s == '\t' || *s == '\n')
    s++;

  if (!*s) {
    errno = ENOENT;
    return -1;
  }

  execl("/bin/sh", "sh", "-c", pname, (char *)NULL);
  return -1;
}
#endif

static void
mrb_io_free(mrb_state *mrb, void *ptr)
{
  struct mrb_io *io = (struct mrb_io *)ptr;
  if (io != NULL) {
    fptr_finalize(mrb, io, TRUE);
    mrb_free(mrb, io);
  }
}

static struct mrb_io *
mrb_io_alloc(mrb_state *mrb)
{
  struct mrb_io *fptr;

  fptr = (struct mrb_io *)mrb_malloc(mrb, sizeof(struct mrb_io));
  fptr->fd = -1;
  fptr->fd2 = -1;
  fptr->pid = 0;
  fptr->readable = 0;
  fptr->writable = 0;
  fptr->sync = 0;
  fptr->is_socket = 0;
  return fptr;
}

#ifndef NOFILE
#define NOFILE 64
#endif

static int
option_to_fd(mrb_state *mrb, mrb_value hash, const char *key)
{
  mrb_value opt;

  if (!mrb_hash_p(hash)) return -1;
  opt = mrb_hash_fetch(mrb, hash, mrb_symbol_value(mrb_intern_static(mrb, key, strlen(key))), mrb_nil_value());
  if (mrb_nil_p(opt)) return -1;

  switch (mrb_type(opt)) {
    case MRB_TT_DATA: /* IO */
      return mrb_io_fileno(mrb, opt);
    case MRB_TT_FIXNUM:
      return (int)mrb_fixnum(opt);
    default:
      mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong exec redirect action");
      break;
  }
  return -1; /* never reached */
}

#ifdef _WIN32
static mrb_value
mrb_io_s_popen(mrb_state *mrb, mrb_value klass)
{
  mrb_value cmd, io;
  mrb_value mode = mrb_str_new_cstr(mrb, "r");
  mrb_value opt  = mrb_hash_new(mrb);

  struct mrb_io *fptr;
  const char *pname;
  int pid = 0, flags;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  SECURITY_ATTRIBUTES saAttr;

  HANDLE ifd[2];
  HANDLE ofd[2];

  int doexec;
  int opt_in, opt_out, opt_err;

  ifd[0] = INVALID_HANDLE_VALUE;
  ifd[1] = INVALID_HANDLE_VALUE;
  ofd[0] = INVALID_HANDLE_VALUE;
  ofd[1] = INVALID_HANDLE_VALUE;

  mrb_get_args(mrb, "S|oH", &cmd, &mode, &opt);
  io = mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(klass), NULL, &mrb_io_type));

  pname = RSTRING_CSTR(mrb, cmd);
  flags = mrb_io_mode_to_flags(mrb, mode);

  doexec = (strcmp("-", pname) != 0);
  opt_in = option_to_fd(mrb, opt, "in");
  opt_out = option_to_fd(mrb, opt, "out");
  opt_err = option_to_fd(mrb, opt, "err");

  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  if (OPEN_READABLE_P(flags)) {
    if (!CreatePipe(&ofd[0], &ofd[1], &saAttr, 0)
        || !SetHandleInformation(ofd[0], HANDLE_FLAG_INHERIT, 0)) {
      mrb_sys_fail(mrb, "pipe");
    }
  }

  if (OPEN_WRITABLE_P(flags)) {
    if (!CreatePipe(&ifd[0], &ifd[1], &saAttr, 0)
        || !SetHandleInformation(ifd[1], HANDLE_FLAG_INHERIT, 0)) {
      mrb_sys_fail(mrb, "pipe");
    }
  }

  if (doexec) {
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.dwFlags |= STARTF_USESTDHANDLES;
    if (OPEN_READABLE_P(flags)) {
      si.hStdOutput = ofd[1];
      si.hStdError = ofd[1];
    }
    if (OPEN_WRITABLE_P(flags)) {
      si.hStdInput = ifd[0];
    }
    if (!CreateProcess(
        NULL, (char*)pname, NULL, NULL,
        TRUE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
      CloseHandle(ifd[0]);
      CloseHandle(ifd[1]);
      CloseHandle(ofd[0]);
      CloseHandle(ofd[1]);
      mrb_raisef(mrb, E_IO_ERROR, "command not found: %v", cmd);
    }
    CloseHandle(pi.hThread);
    CloseHandle(ifd[0]);
    CloseHandle(ofd[1]);
    pid = pi.dwProcessId;
  }

  mrb_iv_set(mrb, io, mrb_intern_cstr(mrb, "@buf"), mrb_str_new_cstr(mrb, ""));

  fptr = mrb_io_alloc(mrb);
  fptr->fd = _open_osfhandle((intptr_t)ofd[0], 0);
  fptr->fd2 = _open_osfhandle((intptr_t)ifd[1], 0);
  fptr->pid = pid;
  fptr->readable = OPEN_READABLE_P(flags);
  fptr->writable = OPEN_WRITABLE_P(flags);
  fptr->sync = 0;

  DATA_TYPE(io) = &mrb_io_type;
  DATA_PTR(io)  = fptr;
  return io;
}
#elif defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
static mrb_value
mrb_io_s_popen(mrb_state *mrb, mrb_value klass)
{
  mrb_raise(mrb, E_NOTIMP_ERROR, "IO#popen is not supported on the platform");
  return mrb_false_value();
}
#else
static mrb_value
mrb_io_s_popen(mrb_state *mrb, mrb_value klass)
{
  mrb_value cmd, io, result;
  mrb_value mode = mrb_str_new_cstr(mrb, "r");
  mrb_value opt  = mrb_hash_new(mrb);

  struct mrb_io *fptr;
  const char *pname;
  int pid, flags, fd, write_fd = -1;
  int pr[2] = { -1, -1 };
  int pw[2] = { -1, -1 };
  int doexec;
  int saved_errno;
  int opt_in, opt_out, opt_err;

  mrb_get_args(mrb, "S|oH", &cmd, &mode, &opt);
  io = mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(klass), NULL, &mrb_io_type));

  pname = RSTRING_CSTR(mrb, cmd);
  flags = mrb_io_mode_to_flags(mrb, mode);

  doexec = (strcmp("-", pname) != 0);
  opt_in = option_to_fd(mrb, opt, "in");
  opt_out = option_to_fd(mrb, opt, "out");
  opt_err = option_to_fd(mrb, opt, "err");

  if (OPEN_READABLE_P(flags)) {
    if (pipe(pr) == -1) {
      mrb_sys_fail(mrb, "pipe");
    }
    mrb_fd_cloexec(mrb, pr[0]);
    mrb_fd_cloexec(mrb, pr[1]);
  }

  if (OPEN_WRITABLE_P(flags)) {
    if (pipe(pw) == -1) {
      if (pr[0] != -1) close(pr[0]);
      if (pr[1] != -1) close(pr[1]);
      mrb_sys_fail(mrb, "pipe");
    }
    mrb_fd_cloexec(mrb, pw[0]);
    mrb_fd_cloexec(mrb, pw[1]);
  }

  if (!doexec) {
    // XXX
    fflush(stdin);
    fflush(stdout);
    fflush(stderr);
  }

  result = mrb_nil_value();
  switch (pid = fork()) {
    case 0: /* child */
      if (opt_in != -1) {
        dup2(opt_in, 0);
      }
      if (opt_out != -1) {
        dup2(opt_out, 1);
      }
      if (opt_err != -1) {
        dup2(opt_err, 2);
      }
      if (OPEN_READABLE_P(flags)) {
        close(pr[0]);
        if (pr[1] != 1) {
          dup2(pr[1], 1);
          close(pr[1]);
        }
      }
      if (OPEN_WRITABLE_P(flags)) {
        close(pw[1]);
        if (pw[0] != 0) {
          dup2(pw[0], 0);
          close(pw[0]);
        }
      }
      if (doexec) {
        for (fd = 3; fd < NOFILE; fd++) {
          close(fd);
        }
        mrb_proc_exec(pname);
        mrb_raisef(mrb, E_IO_ERROR, "command not found: %v", cmd);
        _exit(127);
      }
      result = mrb_nil_value();
      break;

    default: /* parent */
      if (OPEN_RDWR_P(flags)) {
        close(pr[1]);
        fd = pr[0];
        close(pw[0]);
        write_fd = pw[1];
      } else if (OPEN_RDONLY_P(flags)) {
        close(pr[1]);
        fd = pr[0];
      } else {
        close(pw[0]);
        fd = pw[1];
      }

      mrb_iv_set(mrb, io, mrb_intern_cstr(mrb, "@buf"), mrb_str_new_cstr(mrb, ""));

      fptr = mrb_io_alloc(mrb);
      fptr->fd = fd;
      fptr->fd2 = write_fd;
      fptr->pid = pid;
      fptr->readable = OPEN_READABLE_P(flags);
      fptr->writable = OPEN_WRITABLE_P(flags);
      fptr->sync = 0;

      DATA_TYPE(io) = &mrb_io_type;
      DATA_PTR(io)  = fptr;
      result = io;
      break;

    case -1: /* error */
      saved_errno = errno;
      if (OPEN_READABLE_P(flags)) {
        close(pr[0]);
        close(pr[1]);
      }
      if (OPEN_WRITABLE_P(flags)) {
        close(pw[0]);
        close(pw[1]);
      }
      errno = saved_errno;
      mrb_sys_fail(mrb, "pipe_open failed.");
      break;
  }
  return result;
}
#endif

static int
mrb_dup(mrb_state *mrb, int fd, mrb_bool *failed)
{
  int new_fd;

  *failed = TRUE;
  if (fd < 0)
    return fd;

  new_fd = dup(fd);
  if (new_fd > 0) *failed = FALSE;
  return new_fd;
}

static mrb_value
mrb_io_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_value orig = mrb_get_arg1(mrb);
  mrb_value buf;
  struct mrb_io *fptr_copy;
  struct mrb_io *fptr_orig;
  mrb_bool failed = TRUE;

  fptr_orig = io_get_open_fptr(mrb, orig);
  fptr_copy = (struct mrb_io *)DATA_PTR(copy);
  if (fptr_orig == fptr_copy) return copy;
  if (fptr_copy != NULL) {
    fptr_finalize(mrb, fptr_copy, FALSE);
    mrb_free(mrb, fptr_copy);
  }
  fptr_copy = (struct mrb_io *)mrb_io_alloc(mrb);

  DATA_TYPE(copy) = &mrb_io_type;
  DATA_PTR(copy) = fptr_copy;

  buf = mrb_iv_get(mrb, orig, mrb_intern_cstr(mrb, "@buf"));
  mrb_iv_set(mrb, copy, mrb_intern_cstr(mrb, "@buf"), buf);

  fptr_copy->fd = mrb_dup(mrb, fptr_orig->fd, &failed);
  if (failed) {
    mrb_sys_fail(mrb, 0);
  }
  mrb_fd_cloexec(mrb, fptr_copy->fd);

  if (fptr_orig->fd2 != -1) {
    fptr_copy->fd2 = mrb_dup(mrb, fptr_orig->fd2, &failed);
    if (failed) {
      close(fptr_copy->fd);
      mrb_sys_fail(mrb, 0);
    }
    mrb_fd_cloexec(mrb, fptr_copy->fd2);
  }

  fptr_copy->pid = fptr_orig->pid;
  fptr_copy->readable = fptr_orig->readable;
  fptr_copy->writable = fptr_orig->writable;
  fptr_copy->sync = fptr_orig->sync;
  fptr_copy->is_socket = fptr_orig->is_socket;

  return copy;
}

static void
check_file_descriptor(mrb_state *mrb, mrb_int fd)
{
  struct stat sb;
  int fdi = (int)fd;

#if MRB_INT_MIN < INT_MIN || MRB_INT_MAX > INT_MAX
  if (fdi != fd) {
    goto badfd;
  }
#endif

#ifdef _WIN32
  {
    DWORD err;
    int len = sizeof(err);

    if (getsockopt(fdi, SOL_SOCKET, SO_ERROR, (char*)&err, &len) == 0) {
      return;
    }
  }

  if (fdi < 0 || fdi > _getmaxstdio()) {
    goto badfd;
  }
#endif /* _WIN32 */

  if (fstat(fdi, &sb) != 0) {
    goto badfd;
  }

  return;

badfd:
  mrb_sys_fail(mrb, "bad file descriptor");
}

static mrb_value
mrb_io_initialize(mrb_state *mrb, mrb_value io)
{
  struct mrb_io *fptr;
  mrb_int fd;
  mrb_value mode, opt;
  int flags;

  mode = opt = mrb_nil_value();

  mrb_get_args(mrb, "i|oo", &fd, &mode, &opt);
  check_file_descriptor(mrb, fd);
  if (mrb_nil_p(mode)) {
    mode = mrb_str_new_cstr(mrb, "r");
  }
  if (mrb_nil_p(opt)) {
    opt = mrb_hash_new(mrb);
  }

  flags = mrb_io_mode_to_flags(mrb, mode);

  mrb_iv_set(mrb, io, mrb_intern_cstr(mrb, "@buf"), mrb_str_new_cstr(mrb, ""));

  fptr = (struct mrb_io *)DATA_PTR(io);
  if (fptr != NULL) {
    fptr_finalize(mrb, fptr, TRUE);
    mrb_free(mrb, fptr);
  }
  fptr = mrb_io_alloc(mrb);

  DATA_TYPE(io) = &mrb_io_type;
  DATA_PTR(io) = fptr;

  fptr->fd = (int)fd;
  fptr->readable = OPEN_READABLE_P(flags);
  fptr->writable = OPEN_WRITABLE_P(flags);
  fptr->sync = 0;
  return io;
}

static void
fptr_finalize(mrb_state *mrb, struct mrb_io *fptr, int quiet)
{
  int saved_errno = 0;

  if (fptr == NULL) {
    return;
  }

  if (fptr->fd > 2) {
#ifdef _WIN32
    if (fptr->is_socket) {
      if (closesocket(fptr->fd) != 0) {
        saved_errno = WSAGetLastError();
      }
      fptr->fd = -1;
    }
#endif
    if (fptr->fd != -1) {
      if (close(fptr->fd) == -1) {
        saved_errno = errno;
      }
    }
    fptr->fd = -1;
  }

  if (fptr->fd2 > 2) {
    if (close(fptr->fd2) == -1) {
      if (saved_errno == 0) {
        saved_errno = errno;
      }
    }
    fptr->fd2 = -1;
  }

  if (fptr->pid != 0) {
#if !defined(_WIN32) && !defined(_WIN64)
    pid_t pid;
    int status;
    do {
      pid = waitpid(fptr->pid, &status, 0);
    } while (pid == -1 && errno == EINTR);
    if (!quiet && pid == fptr->pid) {
      io_set_process_status(mrb, pid, status);
    }
#else
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, fptr->pid);
    DWORD status;
    if (WaitForSingleObject(h, INFINITE) && GetExitCodeProcess(h, &status))
      if (!quiet)
        io_set_process_status(mrb, fptr->pid, (int)status);
    CloseHandle(h);
#endif
    fptr->pid = 0;
    /* Note: we don't raise an exception when waitpid(3) fails */
  }

  if (!quiet && saved_errno != 0) {
    errno = saved_errno;
    mrb_sys_fail(mrb, "fptr_finalize failed.");
  }
}

static mrb_value
mrb_io_check_readable(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr = io_get_open_fptr(mrb, self);
  if (! fptr->readable) {
    mrb_raise(mrb, E_IO_ERROR, "not opened for reading");
  }
  return mrb_nil_value();
}

static mrb_value
mrb_io_isatty(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr;

  fptr = io_get_open_fptr(mrb, self);
  if (isatty(fptr->fd) == 0)
    return mrb_false_value();
  return mrb_true_value();
}

static mrb_value
mrb_io_s_for_fd(mrb_state *mrb, mrb_value klass)
{
  struct RClass *c = mrb_class_ptr(klass);
  enum mrb_vtype ttype = MRB_INSTANCE_TT(c);
  mrb_value obj;

  /* copied from mrb_instance_alloc() */
  if (ttype == 0) ttype = MRB_TT_OBJECT;
  obj = mrb_obj_value((struct RObject*)mrb_obj_alloc(mrb, ttype, c));
  return mrb_io_initialize(mrb, obj);
}

static mrb_value
mrb_io_s_sysclose(mrb_state *mrb, mrb_value klass)
{
  mrb_int fd;
  mrb_get_args(mrb, "i", &fd);
  if (close((int)fd) == -1) {
    mrb_sys_fail(mrb, "close");
  }
  return mrb_fixnum_value(0);
}

static int
mrb_cloexec_open(mrb_state *mrb, const char *pathname, mrb_int flags, mrb_int mode)
{
  int fd, retry = FALSE;
  char* fname = mrb_locale_from_utf8(pathname, -1);

#ifdef O_CLOEXEC
  /* O_CLOEXEC is available since Linux 2.6.23.  Linux 2.6.18 silently ignore it. */
  flags |= O_CLOEXEC;
#elif defined O_NOINHERIT
  flags |= O_NOINHERIT;
#endif
reopen:
  fd = open(fname, (int)flags, (fmode_t)mode);
  if (fd == -1) {
    if (!retry) {
      switch (errno) {
        case ENFILE:
        case EMFILE:
        mrb_garbage_collect(mrb);
        retry = TRUE;
        goto reopen;
      }
    }

    mrb_sys_fail(mrb, RSTRING_CSTR(mrb, mrb_format(mrb, "open %s", pathname)));
  }
  mrb_locale_free(fname);

  if (fd <= 2) {
    mrb_fd_cloexec(mrb, fd);
  }
  return fd;
}

static mrb_value
mrb_io_s_sysopen(mrb_state *mrb, mrb_value klass)
{
  mrb_value path = mrb_nil_value();
  mrb_value mode = mrb_nil_value();
  mrb_int fd, perm = -1;
  const char *pat;
  int flags;

  mrb_get_args(mrb, "S|oi", &path, &mode, &perm);
  if (perm < 0) {
    perm = 0666;
  }

  pat = RSTRING_CSTR(mrb, path);
  flags = mrb_io_mode_to_flags(mrb, mode);
  fd = mrb_cloexec_open(mrb, pat, flags, perm);
  return mrb_fixnum_value(fd);
}

static mrb_value mrb_io_sysread_common(mrb_state *mrb,
    mrb_io_read_write_size (*readfunc)(int, void *, fsize_t, off_t),
    mrb_value io, mrb_value buf, mrb_int maxlen, off_t offset);

static mrb_io_read_write_size
mrb_sysread_dummy(int fd, void *buf, fsize_t nbytes, off_t offset)
{
  return (mrb_io_read_write_size)read(fd, buf, nbytes);
}

static mrb_value
mrb_io_sysread(mrb_state *mrb, mrb_value io)
{
  mrb_value buf = mrb_nil_value();
  mrb_int maxlen;

  mrb_get_args(mrb, "i|S", &maxlen, &buf);

  return mrb_io_sysread_common(mrb, mrb_sysread_dummy, io, buf, maxlen, 0);
}

static mrb_value
mrb_io_sysread_common(mrb_state *mrb,
    mrb_io_read_write_size (*readfunc)(int, void *, fsize_t, off_t),
    mrb_value io, mrb_value buf, mrb_int maxlen, off_t offset)
{
  struct mrb_io *fptr;
  int ret;

  if (maxlen < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "negative expanding string size");
  }
  else if (maxlen == 0) {
    return mrb_str_new(mrb, NULL, maxlen);
  }

  if (mrb_nil_p(buf)) {
    buf = mrb_str_new(mrb, NULL, maxlen);
  }

  if (RSTRING_LEN(buf) != maxlen) {
    buf = mrb_str_resize(mrb, buf, maxlen);
  }
  else {
    mrb_str_modify(mrb, RSTRING(buf));
  }

  fptr = (struct mrb_io *)io_get_open_fptr(mrb, io);
  if (!fptr->readable) {
    mrb_raise(mrb, E_IO_ERROR, "not opened for reading");
  }
  ret = readfunc(fptr->fd, RSTRING_PTR(buf), (fsize_t)maxlen, offset);
  if (ret < 0) {
    mrb_sys_fail(mrb, "sysread failed");
  }
  if (RSTRING_LEN(buf) != ret) {
    buf = mrb_str_resize(mrb, buf, ret);
  }
  if (ret == 0 && maxlen > 0) {
    mrb_raise(mrb, E_EOF_ERROR, "sysread failed: End of File");
  }
  return buf;
}

static mrb_value
mrb_io_sysseek(mrb_state *mrb, mrb_value io)
{
  struct mrb_io *fptr;
  off_t pos;
  mrb_int offset, whence = -1;

  mrb_get_args(mrb, "i|i", &offset, &whence);
  if (whence < 0) {
    whence = 0;
  }

  fptr = io_get_open_fptr(mrb, io);
  pos = lseek(fptr->fd, (off_t)offset, (int)whence);
  if (pos == -1) {
    mrb_sys_fail(mrb, "sysseek");
  }
  if (pos > MRB_INT_MAX) {
#ifndef MRB_WITHOUT_FLOAT
    return mrb_float_value(mrb, (mrb_float)pos);
#else
    mrb_raise(mrb, E_IO_ERROR, "sysseek reached too far for MRB_WITHOUT_FLOAT");
#endif
  } else {
    return mrb_fixnum_value(pos);
  }
}

static mrb_value
mrb_io_syswrite_common(mrb_state *mrb,
    mrb_io_read_write_size (*writefunc)(int, const void *, fsize_t, off_t),
    mrb_value io, mrb_value buf, off_t offset)
{
  struct mrb_io *fptr;
  int fd, length;

  fptr = io_get_open_fptr(mrb, io);
  if (! fptr->writable) {
    mrb_raise(mrb, E_IO_ERROR, "not opened for writing");
  }

  if (fptr->fd2 == -1) {
    fd = fptr->fd;
  } else {
    fd = fptr->fd2;
  }
  length = writefunc(fd, RSTRING_PTR(buf), (fsize_t)RSTRING_LEN(buf), offset);
  if (length == -1) {
    mrb_sys_fail(mrb, 0);
  }

  return mrb_fixnum_value(length);
}

static mrb_io_read_write_size
mrb_syswrite_dummy(int fd, const void *buf, fsize_t nbytes, off_t offset)
{
  return (mrb_io_read_write_size)write(fd, buf, nbytes);
}

static mrb_value
mrb_io_syswrite(mrb_state *mrb, mrb_value io)
{
  mrb_value buf;

  mrb_get_args(mrb, "S", &buf);

  return mrb_io_syswrite_common(mrb, mrb_syswrite_dummy, io, buf, 0);
}

static mrb_value
mrb_io_close(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr;
  fptr = io_get_open_fptr(mrb, self);
  fptr_finalize(mrb, fptr, FALSE);
  return mrb_nil_value();
}

static mrb_value
mrb_io_close_write(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr;
  fptr = io_get_open_fptr(mrb, self);
  if (close((int)fptr->fd2) == -1) {
    mrb_sys_fail(mrb, "close");
  }
  return mrb_nil_value();
}

static mrb_value
mrb_io_closed(mrb_state *mrb, mrb_value io)
{
  struct mrb_io *fptr;
  fptr = (struct mrb_io *)mrb_data_get_ptr(mrb, io, &mrb_io_type);
  if (fptr == NULL || fptr->fd >= 0) {
    return mrb_false_value();
  }

  return mrb_true_value();
}

static mrb_value
mrb_io_pid(mrb_state *mrb, mrb_value io)
{
  struct mrb_io *fptr;
  fptr = io_get_open_fptr(mrb, io);

  if (fptr->pid > 0) {
    return mrb_fixnum_value(fptr->pid);
  }

  return mrb_nil_value();
}

static struct timeval
time2timeval(mrb_state *mrb, mrb_value time)
{
  struct timeval t = { 0, 0 };

  switch (mrb_type(time)) {
    case MRB_TT_FIXNUM:
      t.tv_sec = (ftime_t)mrb_fixnum(time);
      t.tv_usec = 0;
      break;

#ifndef MRB_WITHOUT_FLOAT
    case MRB_TT_FLOAT:
      t.tv_sec = (ftime_t)mrb_float(time);
      t.tv_usec = (fsuseconds_t)((mrb_float(time) - t.tv_sec) * 1000000.0);
      break;
#endif

    default:
      mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }

  return t;
}

static int
mrb_io_read_data_pending(mrb_state *mrb, mrb_value io)
{
  mrb_value buf = mrb_iv_get(mrb, io, mrb_intern_cstr(mrb, "@buf"));
  if (mrb_string_p(buf) && RSTRING_LEN(buf) > 0) {
    return 1;
  }
  return 0;
}

#if !defined(_WIN32) && !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
static mrb_value
mrb_io_s_pipe(mrb_state *mrb, mrb_value klass)
{
  mrb_value r = mrb_nil_value();
  mrb_value w = mrb_nil_value();
  struct mrb_io *fptr_r;
  struct mrb_io *fptr_w;
  int pipes[2];

  if (mrb_pipe(mrb, pipes) == -1) {
    mrb_sys_fail(mrb, "pipe");
  }

  r = mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(klass), NULL, &mrb_io_type));
  mrb_iv_set(mrb, r, mrb_intern_cstr(mrb, "@buf"), mrb_str_new_cstr(mrb, ""));
  fptr_r = mrb_io_alloc(mrb);
  fptr_r->fd = pipes[0];
  fptr_r->readable = 1;
  fptr_r->writable = 0;
  fptr_r->sync = 0;
  DATA_TYPE(r) = &mrb_io_type;
  DATA_PTR(r)  = fptr_r;

  w = mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(klass), NULL, &mrb_io_type));
  mrb_iv_set(mrb, w, mrb_intern_cstr(mrb, "@buf"), mrb_str_new_cstr(mrb, ""));
  fptr_w = mrb_io_alloc(mrb);
  fptr_w->fd = pipes[1];
  fptr_w->readable = 0;
  fptr_w->writable = 1;
  fptr_w->sync = 1;
  DATA_TYPE(w) = &mrb_io_type;
  DATA_PTR(w)  = fptr_w;

  return mrb_assoc_new(mrb, r, w);
}
#endif

static mrb_value
mrb_io_s_select(mrb_state *mrb, mrb_value klass)
{
  mrb_value *argv;
  mrb_int argc;
  mrb_value read, read_io, write, except, timeout, list;
  struct timeval *tp, timerec;
  fd_set pset, rset, wset, eset;
  fd_set *rp, *wp, *ep;
  struct mrb_io *fptr;
  int pending = 0;
  mrb_value result;
  int max = 0;
  int interrupt_flag = 0;
  int i, n;

  mrb_get_args(mrb, "*", &argv, &argc);

  if (argc < 1 || argc > 4) {
    mrb_argnum_error(mrb, argc, 1, 4);
  }

  timeout = mrb_nil_value();
  except = mrb_nil_value();
  write = mrb_nil_value();
  if (argc > 3)
    timeout = argv[3];
  if (argc > 2)
    except = argv[2];
  if (argc > 1)
    write = argv[1];
  read = argv[0];

  if (mrb_nil_p(timeout)) {
    tp = NULL;
  } else {
    timerec = time2timeval(mrb, timeout);
    tp = &timerec;
  }

  FD_ZERO(&pset);
  if (!mrb_nil_p(read)) {
    mrb_check_type(mrb, read, MRB_TT_ARRAY);
    rp = &rset;
    FD_ZERO(rp);
    for (i = 0; i < RARRAY_LEN(read); i++) {
      read_io = RARRAY_PTR(read)[i];
      fptr = io_get_open_fptr(mrb, read_io);
      if (fptr->fd >= FD_SETSIZE) continue;
      FD_SET(fptr->fd, rp);
      if (mrb_io_read_data_pending(mrb, read_io)) {
        pending++;
        FD_SET(fptr->fd, &pset);
      }
      if (max < fptr->fd)
        max = fptr->fd;
    }
    if (pending) {
      timerec.tv_sec = timerec.tv_usec = 0;
      tp = &timerec;
    }
  } else {
    rp = NULL;
  }

  if (!mrb_nil_p(write)) {
    mrb_check_type(mrb, write, MRB_TT_ARRAY);
    wp = &wset;
    FD_ZERO(wp);
    for (i = 0; i < RARRAY_LEN(write); i++) {
      fptr = io_get_open_fptr(mrb, RARRAY_PTR(write)[i]);
      if (fptr->fd >= FD_SETSIZE) continue;
      FD_SET(fptr->fd, wp);
      if (max < fptr->fd)
        max = fptr->fd;
      if (fptr->fd2 >= 0) {
        FD_SET(fptr->fd2, wp);
        if (max < fptr->fd2)
          max = fptr->fd2;
      }
    }
  } else {
    wp = NULL;
  }

  if (!mrb_nil_p(except)) {
    mrb_check_type(mrb, except, MRB_TT_ARRAY);
    ep = &eset;
    FD_ZERO(ep);
    for (i = 0; i < RARRAY_LEN(except); i++) {
      fptr = io_get_open_fptr(mrb, RARRAY_PTR(except)[i]);
      if (fptr->fd >= FD_SETSIZE) continue;
      FD_SET(fptr->fd, ep);
      if (max < fptr->fd)
        max = fptr->fd;
      if (fptr->fd2 >= 0) {
        FD_SET(fptr->fd2, ep);
        if (max < fptr->fd2)
          max = fptr->fd2;
      }
    }
  } else {
    ep = NULL;
  }

  max++;

retry:
  n = select(max, rp, wp, ep, tp);
  if (n < 0) {
    if (errno != EINTR)
      mrb_sys_fail(mrb, "select failed");
    if (tp == NULL)
      goto retry;
    interrupt_flag = 1;
  }

  if (!pending && n == 0)
    return mrb_nil_value();

  result = mrb_ary_new_capa(mrb, 3);
  mrb_ary_push(mrb, result, rp? mrb_ary_new(mrb) : mrb_ary_new_capa(mrb, 0));
  mrb_ary_push(mrb, result, wp? mrb_ary_new(mrb) : mrb_ary_new_capa(mrb, 0));
  mrb_ary_push(mrb, result, ep? mrb_ary_new(mrb) : mrb_ary_new_capa(mrb, 0));

  if (interrupt_flag == 0) {
    if (rp) {
      list = RARRAY_PTR(result)[0];
      for (i = 0; i < RARRAY_LEN(read); i++) {
        fptr = io_get_open_fptr(mrb, RARRAY_PTR(read)[i]);
        if (FD_ISSET(fptr->fd, rp) ||
            FD_ISSET(fptr->fd, &pset)) {
          mrb_ary_push(mrb, list, RARRAY_PTR(read)[i]);
        }
      }
    }

    if (wp) {
      list = RARRAY_PTR(result)[1];
      for (i = 0; i < RARRAY_LEN(write); i++) {
        fptr = io_get_open_fptr(mrb, RARRAY_PTR(write)[i]);
        if (FD_ISSET(fptr->fd, wp)) {
          mrb_ary_push(mrb, list, RARRAY_PTR(write)[i]);
        } else if (fptr->fd2 >= 0 && FD_ISSET(fptr->fd2, wp)) {
          mrb_ary_push(mrb, list, RARRAY_PTR(write)[i]);
        }
      }
    }

    if (ep) {
      list = RARRAY_PTR(result)[2];
      for (i = 0; i < RARRAY_LEN(except); i++) {
        fptr = io_get_open_fptr(mrb, RARRAY_PTR(except)[i]);
        if (FD_ISSET(fptr->fd, ep)) {
          mrb_ary_push(mrb, list, RARRAY_PTR(except)[i]);
        } else if (fptr->fd2 >= 0 && FD_ISSET(fptr->fd2, ep)) {
          mrb_ary_push(mrb, list, RARRAY_PTR(except)[i]);
        }
      }
    }
  }

  return result;
}

int
mrb_io_fileno(mrb_state *mrb, mrb_value io)
{
  struct mrb_io *fptr;
  fptr = io_get_open_fptr(mrb, io);
  return fptr->fd;
}

static mrb_value
mrb_io_fileno_m(mrb_state *mrb, mrb_value io)
{
  int fd = mrb_io_fileno(mrb, io);
  return mrb_fixnum_value(fd);
}

static mrb_value
mrb_io_close_on_exec_p(mrb_state *mrb, mrb_value self)
{
#if defined(F_GETFD) && defined(F_SETFD) && defined(FD_CLOEXEC)
  struct mrb_io *fptr;
  int ret;

  fptr = io_get_open_fptr(mrb, self);

  if (fptr->fd2 >= 0) {
    if ((ret = fcntl(fptr->fd2, F_GETFD)) == -1) mrb_sys_fail(mrb, "F_GETFD failed");
    if (!(ret & FD_CLOEXEC)) return mrb_false_value();
  }

  if ((ret = fcntl(fptr->fd, F_GETFD)) == -1) mrb_sys_fail(mrb, "F_GETFD failed");
  if (!(ret & FD_CLOEXEC)) return mrb_false_value();
  return mrb_true_value();

#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "IO#close_on_exec? is not supported on the platform");
  return mrb_false_value();
#endif
}

static mrb_value
mrb_io_set_close_on_exec(mrb_state *mrb, mrb_value self)
{
#if defined(F_GETFD) && defined(F_SETFD) && defined(FD_CLOEXEC)
  struct mrb_io *fptr;
  int flag, ret;
  mrb_bool b;

  fptr = io_get_open_fptr(mrb, self);
  mrb_get_args(mrb, "b", &b);
  flag = b ? FD_CLOEXEC : 0;

  if (fptr->fd2 >= 0) {
    if ((ret = fcntl(fptr->fd2, F_GETFD)) == -1) mrb_sys_fail(mrb, "F_GETFD failed");
    if ((ret & FD_CLOEXEC) != flag) {
      ret = (ret & ~FD_CLOEXEC) | flag;
      ret = fcntl(fptr->fd2, F_SETFD, ret);

      if (ret == -1) mrb_sys_fail(mrb, "F_SETFD failed");
    }
  }

  if ((ret = fcntl(fptr->fd, F_GETFD)) == -1) mrb_sys_fail(mrb, "F_GETFD failed");
  if ((ret & FD_CLOEXEC) != flag) {
    ret = (ret & ~FD_CLOEXEC) | flag;
    ret = fcntl(fptr->fd, F_SETFD, ret);
    if (ret == -1) mrb_sys_fail(mrb, "F_SETFD failed");
  }

  return mrb_bool_value(b);
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "IO#close_on_exec= is not supported on the platform");
  return mrb_nil_value();
#endif
}

static mrb_value
mrb_io_set_sync(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr;
  mrb_bool b;

  fptr = io_get_open_fptr(mrb, self);
  mrb_get_args(mrb, "b", &b);
  fptr->sync = b;
  return mrb_bool_value(b);
}

static mrb_value
mrb_io_sync(mrb_state *mrb, mrb_value self)
{
  struct mrb_io *fptr;
  fptr = io_get_open_fptr(mrb, self);
  return mrb_bool_value(fptr->sync);
}

#ifndef MRB_WITH_IO_PREAD_PWRITE
# define mrb_io_pread   mrb_notimplement_m
# define mrb_io_pwrite  mrb_notimplement_m
#else
static off_t
value2off(mrb_state *mrb, mrb_value offv)
{
  return (off_t)mrb_int(mrb, offv);
}

/*
 * call-seq:
 *  pread(maxlen, offset, outbuf = "") -> outbuf
 */
static mrb_value
mrb_io_pread(mrb_state *mrb, mrb_value io)
{
  mrb_value buf = mrb_nil_value();
  mrb_value off;
  mrb_int maxlen;

  mrb_get_args(mrb, "io|S!", &maxlen, &off, &buf);

  return mrb_io_sysread_common(mrb, pread, io, buf, maxlen, value2off(mrb, off));
}

/*
 * call-seq:
 *  pwrite(buffer, offset) -> wrote_bytes
 */
static mrb_value
mrb_io_pwrite(mrb_state *mrb, mrb_value io)
{
  mrb_value buf, off;

  mrb_get_args(mrb, "So", &buf, &off);

  return mrb_io_syswrite_common(mrb, pwrite, io, buf, value2off(mrb, off));
}
#endif /* MRB_WITH_IO_PREAD_PWRITE */

static mrb_value
io_bufread(mrb_state *mrb, mrb_value str, mrb_int len)
{
  mrb_value str2;
  mrb_int newlen;
  struct RString *s;
  char *p;

  s = RSTRING(str);
  mrb_str_modify(mrb, s);
  p = RSTR_PTR(s);
  str2 = mrb_str_new(mrb, p, len);
  newlen = RSTR_LEN(s)-len;
  memmove(p, p+len, newlen);
  p[newlen] = '\0';
  RSTR_SET_LEN(s, newlen);

  return str2;
}

static mrb_value
mrb_io_bufread(mrb_state *mrb, mrb_value self)
{
  mrb_value str;
  mrb_int len;

  mrb_get_args(mrb, "Si", &str, &len);
  return io_bufread(mrb, str, len);
}

static mrb_value
mrb_io_readchar(mrb_state *mrb, mrb_value self)
{
  mrb_value buf;
  mrb_int len = 1;
#ifdef MRB_UTF8_STRING
  unsigned char c;
#endif

  mrb_get_args(mrb, "S", &buf);
  mrb_assert(RSTRING_LEN(buf) > 0);
  mrb_assert(RSTRING_PTR(buf) != NULL);
  mrb_str_modify(mrb, RSTRING(buf));
#ifdef MRB_UTF8_STRING
  c = RSTRING_PTR(buf)[0];
  if (c & 0x80) {
    len = mrb_utf8len(RSTRING_PTR(buf), RSTRING_END(buf));
    if (len == 1 && RSTRING_LEN(buf) < 4) { /* partial UTF-8 */
      mrb_int blen = RSTRING_LEN(buf);
      ssize_t n;

      struct mrb_io *fptr = (struct mrb_io*)io_get_open_fptr(mrb, self);

      if (!fptr->readable) {
        mrb_raise(mrb, E_IO_ERROR, "not opened for reading");
      }
      /* refill the buffer */
      mrb_str_resize(mrb, buf, 4096);
      n = read(fptr->fd, RSTRING_PTR(buf)+blen, 4096-blen);
      if (n < 0) mrb_sys_fail(mrb, "sysread failed");
      mrb_str_resize(mrb, buf, blen+n);
    }
    len = mrb_utf8len(RSTRING_PTR(buf), RSTRING_END(buf));
  }
#endif
  return io_bufread(mrb, buf, len);
}

void
mrb_init_io(mrb_state *mrb)
{
  struct RClass *io;

  io      = mrb_define_class(mrb, "IO", mrb->object_class);
  MRB_SET_INSTANCE_TT(io, MRB_TT_DATA);

  mrb_include_module(mrb, io, mrb_module_get(mrb, "Enumerable")); /* 15.2.20.3 */
  mrb_define_class_method(mrb, io, "_popen",  mrb_io_s_popen,   MRB_ARGS_ARG(1,2));
  mrb_define_class_method(mrb, io, "_sysclose",  mrb_io_s_sysclose, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, io, "for_fd",  mrb_io_s_for_fd,   MRB_ARGS_ARG(1,2));
  mrb_define_class_method(mrb, io, "select",  mrb_io_s_select,  MRB_ARGS_ARG(1,3));
  mrb_define_class_method(mrb, io, "sysopen", mrb_io_s_sysopen, MRB_ARGS_ARG(1,2));
#if !defined(_WIN32) && !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
  mrb_define_class_method(mrb, io, "_pipe", mrb_io_s_pipe, MRB_ARGS_NONE());
#endif

  mrb_define_method(mrb, io, "initialize", mrb_io_initialize, MRB_ARGS_ARG(1,2));    /* 15.2.20.5.21 (x)*/
  mrb_define_method(mrb, io, "initialize_copy", mrb_io_initialize_copy, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, io, "_check_readable", mrb_io_check_readable, MRB_ARGS_NONE());
  mrb_define_method(mrb, io, "isatty",     mrb_io_isatty,     MRB_ARGS_NONE());
  mrb_define_method(mrb, io, "sync",       mrb_io_sync,       MRB_ARGS_NONE());
  mrb_define_method(mrb, io, "sync=",      mrb_io_set_sync,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb, io, "sysread",    mrb_io_sysread,    MRB_ARGS_ARG(1,1));
  mrb_define_method(mrb, io, "sysseek",    mrb_io_sysseek,    MRB_ARGS_ARG(1,1));
  mrb_define_method(mrb, io, "syswrite",   mrb_io_syswrite,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb, io, "close",      mrb_io_close,      MRB_ARGS_NONE());   /* 15.2.20.5.1 */
  mrb_define_method(mrb, io, "close_write",    mrb_io_close_write,       MRB_ARGS_NONE());
  mrb_define_method(mrb, io, "close_on_exec=", mrb_io_set_close_on_exec, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, io, "close_on_exec?", mrb_io_close_on_exec_p,   MRB_ARGS_NONE());
  mrb_define_method(mrb, io, "closed?",    mrb_io_closed,     MRB_ARGS_NONE());   /* 15.2.20.5.2 */
  mrb_define_method(mrb, io, "pid",        mrb_io_pid,        MRB_ARGS_NONE());   /* 15.2.20.5.2 */
  mrb_define_method(mrb, io, "fileno",     mrb_io_fileno_m,   MRB_ARGS_NONE());
  mrb_define_method(mrb, io, "pread",      mrb_io_pread,      MRB_ARGS_ANY());    /* ruby 2.5 feature */
  mrb_define_method(mrb, io, "pwrite",     mrb_io_pwrite,     MRB_ARGS_ANY());    /* ruby 2.5 feature */

  mrb_define_method(mrb, io, "_readchar",  mrb_io_readchar,   MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, io, "_bufread",   mrb_io_bufread,    MRB_ARGS_REQ(2));
}
