/*
** io.h - IO class
*/

#ifndef MRUBY_IO_H
#define MRUBY_IO_H

#include <mruby.h>

#ifdef MRB_DISABLE_STDIO
# error IO and File conflicts 'MRB_DISABLE_STDIO' configuration in your 'build_config.rb'
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(MRB_WITHOUT_IO_PREAD_PWRITE)
# undef MRB_WITH_IO_PREAD_PWRITE
#elif !defined(MRB_WITH_IO_PREAD_PWRITE)
# if defined(__unix__) || defined(__MACH__)
#  define MRB_WITH_IO_PREAD_PWRITE
# endif
#endif

struct mrb_io {
  int fd;   /* file descriptor, or -1 */
  int fd2;  /* file descriptor to write if it's different from fd, or -1 */
  int pid;  /* child's pid (for pipes)  */
  unsigned int readable:1,
               writable:1,
               sync:1,
               is_socket:1;
};

#define MRB_O_RDONLY            0x0000
#define MRB_O_WRONLY            0x0001
#define MRB_O_RDWR              0x0002
#define MRB_O_ACCMODE           (MRB_O_RDONLY | MRB_O_WRONLY | MRB_O_RDWR)
#define MRB_O_NONBLOCK          0x0004
#define MRB_O_APPEND            0x0008
#define MRB_O_SYNC              0x0010
#define MRB_O_NOFOLLOW          0x0020
#define MRB_O_CREAT             0x0040
#define MRB_O_TRUNC             0x0080
#define MRB_O_EXCL              0x0100
#define MRB_O_NOCTTY            0x0200
#define MRB_O_DIRECT            0x0400
#define MRB_O_BINARY            0x0800
#define MRB_O_SHARE_DELETE      0x1000
#define MRB_O_TMPFILE           0x2000
#define MRB_O_NOATIME           0x4000
#define MRB_O_DSYNC             0x00008000
#define MRB_O_RSYNC             0x00010000

#define MRB_O_RDONLY_P(f)       ((mrb_bool)(((f) & MRB_O_ACCMODE) == MRB_O_RDONLY))
#define MRB_O_WRONLY_P(f)       ((mrb_bool)(((f) & MRB_O_ACCMODE) == MRB_O_WRONLY))
#define MRB_O_RDWR_P(f)         ((mrb_bool)(((f) & MRB_O_ACCMODE) == MRB_O_RDWR))
#define MRB_O_READABLE_P(f)     ((mrb_bool)((((f) & MRB_O_ACCMODE) | 2) == 2))
#define MRB_O_WRITABLE_P(f)     ((mrb_bool)(((((f) & MRB_O_ACCMODE) + 1) & 2) == 2))

#define E_IO_ERROR                 (mrb_class_get(mrb, "IOError"))
#define E_EOF_ERROR                (mrb_class_get(mrb, "EOFError"))

int mrb_io_fileno(mrb_state *mrb, mrb_value io);

#if defined(__cplusplus)
} /* extern "C" { */
#endif
#endif /* MRUBY_IO_H */
