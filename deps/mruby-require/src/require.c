#if !(defined(_WIN32) || defined(_WIN64))
#include <err.h>
#endif
#include <fcntl.h>
#include <setjmp.h>
#include <unistd.h>

#include "mruby.h"
#include "mruby/compile.h"
#include "mruby/dump.h"
#include "mruby/string.h"
#include "mruby/proc.h"

#include "opcode.h"
#include "error.h"

#include <stdlib.h>
#include <sys/stat.h>

#define E_LOAD_ERROR (mrb_class_get(mrb, "LoadError"))

#if MRUBY_RELEASE_NO < 10000
mrb_value mrb_yield_internal(mrb_state *mrb, mrb_value b, int argc, mrb_value *argv, mrb_value self, struct RClass *c);
#define mrb_yield_with_class mrb_yield_internal
#endif

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  int mkstemp(char *template)
  {
    DWORD pathSize;
    char pathBuffer[1000];
    char tempFilename[MAX_PATH];
    UINT uniqueNum;
    pathSize = GetTempPath(1000, pathBuffer);
    if (pathSize < 1000) { pathBuffer[pathSize] = 0; }
    else                 { pathBuffer[0] = 0; }
    uniqueNum = GetTempFileName(pathBuffer, template, 0, tempFilename);
    if (uniqueNum == 0) return -1;
    strncpy(template, tempFilename, MAX_PATH);
    return open(tempFilename, _O_RDWR|_O_BINARY);
  }
#endif

static void
replace_stop_with_return(mrb_state *mrb, mrb_irep *irep)
{
  if (irep->iseq[irep->ilen - 1] == MKOP_A(OP_STOP, 0)) {
    irep->iseq = mrb_realloc(mrb, irep->iseq, (irep->ilen + 1) * sizeof(mrb_code));
    irep->iseq[irep->ilen - 1] = MKOP_A(OP_LOADNIL, 0);
    irep->iseq[irep->ilen] = MKOP_AB(OP_RETURN, 0, OP_R_NORMAL);
    irep->ilen++;
  }
}

static int
compile_rb2mrb(mrb_state *mrb0, const char *code, int code_len, const char *path, FILE* tmpfp)
{
  mrb_state *mrb = mrb_open();
  mrb_value result;
  mrbc_context *c;
  int ret = -1;
  int debuginfo = 1;
  mrb_irep *irep;

  c = mrbc_context_new(mrb);
  c->no_exec = 1;
  if (path != NULL) {
    mrbc_filename(mrb, c, path);
  }

  result = mrb_load_nstring_cxt(mrb, code, code_len, c);
  if (mrb_undef_p(result)) {
    mrbc_context_free(mrb, c);
    mrb_close(mrb);
    return MRB_DUMP_GENERAL_FAILURE;
  }

  irep = mrb_proc_ptr(result)->body.irep;
  ret = mrb_dump_irep_binary(mrb, irep, debuginfo, tmpfp);

  mrbc_context_free(mrb, c);
  mrb_close(mrb);

  return ret;
}

static void
eval_load_irep(mrb_state *mrb, mrb_irep *irep)
{
  int ai;
  struct RProc *proc;

  replace_stop_with_return(mrb, irep);
  proc = mrb_proc_new(mrb, irep);
  proc->target_class = mrb->object_class;

  ai = mrb_gc_arena_save(mrb);
  mrb_yield_with_class(mrb, mrb_obj_value(proc), 0, NULL, mrb_top_self(mrb), mrb->object_class);
  mrb_gc_arena_restore(mrb, ai);
}

static mrb_value
mrb_require_load_rb_str(mrb_state *mrb, mrb_value self)
{
  char *path_ptr = NULL;
#if defined(_WIN32) || defined(_WIN64)
  char tmpname[MAX_PATH] = "tmp.XXXXXXXX";
#else
  char tmpname[] = "tmp.XXXXXXXX";
#endif
  mode_t mask;
  FILE *tmpfp = NULL;
  int fd = -1, ret;
  mrb_irep *irep;
  mrb_value code, path = mrb_nil_value();

  mrb_get_args(mrb, "S|S", &code, &path);
  if (!mrb_string_p(path)) {
    path = mrb_str_new_cstr(mrb, "-");
  }
  path_ptr = mrb_str_to_cstr(mrb, path);

  mask = umask(077);
  fd = mkstemp(tmpname);
  if (fd == -1) {
    mrb_sys_fail(mrb, "can't create mkstemp() at mrb_require_load_rb_str");
  }
  umask(mask);

  tmpfp = fdopen(fd, "r+");
  if (tmpfp == NULL) {
    close(fd);
    mrb_sys_fail(mrb, "can't open temporay file at mrb_require_load_rb_str");
  }

  ret = compile_rb2mrb(mrb, RSTRING_PTR(code), RSTRING_LEN(code), path_ptr, tmpfp);
  if (ret != MRB_DUMP_OK) {
    fclose(tmpfp);
    remove(tmpname);
    mrb_raisef(mrb, E_LOAD_ERROR, "can't load file -- %S", path);
    return mrb_nil_value();
  }

  rewind(tmpfp);
  irep = mrb_read_irep_file(mrb, tmpfp);
  fclose(tmpfp);
  remove(tmpname);

  if (irep) {
    eval_load_irep(mrb, irep);
  } else if (mrb->exc) {
    // fail to load
    longjmp(*(jmp_buf*)mrb->jmp, 1);
  } else {
    mrb_raisef(mrb, E_LOAD_ERROR, "can't load file -- %S", path);
    return mrb_nil_value();
  }

  return mrb_true_value();
}

static mrb_value
mrb_require_load_mrb_file(mrb_state *mrb, mrb_value self)
{
  char *path_ptr = NULL;
  FILE *fp = NULL;
  mrb_irep *irep;
  mrb_value path;

  mrb_get_args(mrb, "S", &path);
  path_ptr = mrb_str_to_cstr(mrb, path);

  fp = fopen(path_ptr, "rb");
  if (fp == NULL) {
    mrb_raisef(mrb, E_LOAD_ERROR, "can't open file -- %S", path);
  }

  irep = mrb_read_irep_file(mrb, fp);
  fclose(fp);

  if (irep) {
    eval_load_irep(mrb, irep);
  } else if (mrb->exc) {
    // fail to load
    longjmp(*(jmp_buf*)mrb->jmp, 1);
  } else {
    mrb_raisef(mrb, E_LOAD_ERROR, "can't load file -- %S", path);
    return mrb_nil_value();
  }

  return mrb_true_value();
}

void
mrb_mruby_require_gem_init(mrb_state *mrb)
{
  struct RClass *krn;
  krn = mrb->kernel_module;

  mrb_define_method(mrb, krn, "_load_rb_str",   mrb_require_load_rb_str,   MRB_ARGS_ANY());
  mrb_define_method(mrb, krn, "_load_mrb_file", mrb_require_load_mrb_file, MRB_ARGS_REQ(1));
}

void
mrb_mruby_require_gem_final(mrb_state *mrb)
{
}
