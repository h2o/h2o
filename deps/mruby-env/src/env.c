/*
** env.c - ENV is a Hash-like accessor for environment variables.
**
*/

#include "mruby.h"
#include "mruby/hash.h"
#include "mruby/khash.h"
#include "mruby/class.h"
#include "mruby/array.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
int
unsetenv(const char* name)
{
  int r;
  char* p = malloc(strlen(name) + 2);
  if (!p) return -1;
  strcpy(p, name);
  strcat(p, "=");
  r = _putenv(p);
  free(p);
  return r;
}

int
setenv(const char* name, const char* value, int overwrite)
{
  int r;
  char* p = malloc(strlen(name) + strlen(value) + 2);
  if (!p) return -1;
  strcpy(p, name);
  strcat(p, "=");
  strcat(p, value);
  r = _putenv(p);
  free(p);
  return r;
}
#define environ _environ
#else
extern char **environ;
#endif


mrb_value
mrb_env_aget(mrb_state *mrb, mrb_value self)
{
  mrb_value key;
  const char *cname, *cvalue;

  mrb_get_args(mrb, "S", &key);
  cname = mrb_string_value_cstr(mrb, &key);
  cvalue = getenv(cname);
  if (cvalue != NULL) {
    return mrb_str_new_cstr(mrb, cvalue);
  } else {
    return mrb_nil_value();
  }
}

mrb_value
mrb_env_has_key(mrb_state *mrb, mrb_value self)
{
  mrb_value name;
  const char *key;
  mrb_get_args(mrb, "S", &name);
  key = mrb_str_to_cstr(mrb, name);
  if (getenv(key) != NULL) {
    return mrb_true_value();
  } else { 
    return mrb_false_value();
  }
}

mrb_value
mrb_env_keys(mrb_state *mrb, mrb_value self)
{
  int i;
  mrb_value ary;

  ary = mrb_ary_new(mrb);
  for (i = 0; environ[i] != NULL; i++) {
    char *str = strchr(environ[i], '=');
    if (str != NULL) {
      int len = str - environ[i];
      mrb_ary_push(mrb, ary, mrb_str_new(mrb, environ[i], len));
    }
  }

  return ary;
}

mrb_value
mrb_env_values(mrb_state *mrb, mrb_value self)
{
  int i;
  mrb_value ary;

  ary = mrb_ary_new(mrb);
  for (i = 0; environ[i] != NULL; i++) {
    char *str = strchr(environ[i], '=');
    if (str) {
      int len;
      str++;
      len = strlen(str);
      mrb_ary_push(mrb, ary, mrb_str_new(mrb, str, len));
    }
  }

  return ary;
}

static mrb_value
mrb_env_size(mrb_state *mrb, mrb_value self)
{
  int i;

  for (i = 0; environ[i] != NULL; i++)
    ;

  return mrb_fixnum_value(i);
}

static mrb_value
mrb_env_to_hash(mrb_state *mrb, mrb_value self)
{
  int i;
  mrb_value hash;

  hash = mrb_hash_new(mrb);
  for (i = 0; environ[i] != NULL; i++) {
    char *str = strchr(environ[i], '=');
    if (str != NULL) {
      mrb_value val;
      int ai = mrb_gc_arena_save(mrb);
      int len = str - environ[i];
      mrb_value key = mrb_str_new(mrb, environ[i], len);
      str++;
      val = mrb_str_new(mrb, str, strlen(str));
      mrb_hash_set(mrb, hash, key, val);
      mrb_gc_arena_restore(mrb, ai);
    }
  }

  return hash;
}

static mrb_value
mrb_env_to_a(mrb_state *mrb, mrb_value self)
{
  int i;
  mrb_value ary;

  ary = mrb_ary_new(mrb);
  for (i = 0; environ[i] != NULL; i++) {
    char *str = strchr(environ[i], '=');
    if (str != NULL) {
      int ai = mrb_gc_arena_save(mrb);
      mrb_value elem = mrb_ary_new(mrb);
      int len = str - environ[i];
      mrb_ary_push(mrb, elem, mrb_str_new(mrb, environ[i], len));
      str++;
      mrb_ary_push(mrb, elem, mrb_str_new(mrb, str, strlen(str)));
      mrb_ary_push(mrb, ary, elem);
      mrb_gc_arena_restore(mrb, ai);
    }
  }

  return ary;
}

static mrb_value
mrb_env_inspect(mrb_state *mrb, mrb_value self)
{
  mrb_value hash = mrb_env_to_hash(mrb, self);
  return mrb_funcall(mrb, hash, "inspect", 0);
}

static mrb_value
mrb_env_to_s(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_cstr(mrb, "ENV");
}

static mrb_value
mrb_env_aset(mrb_state *mrb, mrb_value self)
{
  mrb_value name, value;
  const char *cname, *cvalue;

  mrb_get_args(mrb, "So", &name, &value);
  cname = mrb_string_value_cstr(mrb, &name);

  if (mrb_nil_p(value)) {
    if (unsetenv(cname) != 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "can't delete environment variable");
    }
  } else {
    mrb_convert_type(mrb, value, MRB_TT_STRING, "String", "to_str");
    cvalue = mrb_string_value_cstr(mrb, &value);
    if (setenv(cname, cvalue, 1) != 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "can't change environment variable");
    }
  }
  return value;
}

void
mrb_mruby_env_gem_init(mrb_state *mrb)
{
  struct RObject *e;

  e = (struct RObject*) mrb_obj_alloc(mrb, MRB_TT_OBJECT, mrb->object_class);
#if defined(MRUBY_RELEASE_NO) && MRUBY_RELEASE_NO >= 10000
  mrb_include_module(mrb, (struct RClass*)e, mrb_module_get(mrb, "Enumerable"));
#else
  mrb_include_module(mrb, (struct RClass*)e, mrb_class_get(mrb, "Enumerable"));
#endif

  mrb_define_singleton_method(mrb, e,"[]",       mrb_env_aget,       MRB_ARGS_REQ(1));
  mrb_define_singleton_method(mrb, e,"[]=",      mrb_env_aset,       MRB_ARGS_REQ(2));
  mrb_define_singleton_method(mrb, e,"has_key?", mrb_env_has_key,    MRB_ARGS_REQ(1));
  mrb_define_singleton_method(mrb, e,"inspect",  mrb_env_inspect,    MRB_ARGS_NONE());
  mrb_define_singleton_method(mrb, e,"keys",     mrb_env_keys,       MRB_ARGS_NONE());
  mrb_define_singleton_method(mrb, e,"size",     mrb_env_size,       MRB_ARGS_NONE());
  mrb_define_singleton_method(mrb, e,"store",    mrb_env_aset,       MRB_ARGS_REQ(2));
  mrb_define_singleton_method(mrb, e,"to_a",     mrb_env_to_a,       MRB_ARGS_NONE());
  mrb_define_singleton_method(mrb, e,"to_hash",  mrb_env_to_hash,    MRB_ARGS_NONE());
  mrb_define_singleton_method(mrb, e,"to_s",     mrb_env_to_s,       MRB_ARGS_NONE());
  mrb_define_singleton_method(mrb, e,"values",   mrb_env_values,     MRB_ARGS_NONE());

  mrb_define_global_const(mrb, "ENV", mrb_obj_value(e));
}

void
mrb_mruby_env_gem_final(mrb_state *mrb)
{
}
