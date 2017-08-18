#include <mruby.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/istruct.h>

static mrb_value
istruct_test_initialize(mrb_state *mrb, mrb_value self)
{
  char *string = (char*)mrb_istruct_ptr(self);
  mrb_int size = mrb_istruct_size();
  mrb_value object;
  mrb_get_args(mrb, "o", &object);

  if (mrb_float_p(object))
  {
    snprintf(string, size, "float(%.3f)", mrb_float(object));
  }
  else if (mrb_fixnum_p(object))
  {
    snprintf(string, size, "fixnum(%" MRB_PRId ")", mrb_fixnum(object));
  }
  else if (mrb_string_p(object))
  {
    snprintf(string, size, "string(%s)", mrb_string_value_cstr(mrb, &object));
  }

  string[size - 1] = 0; // force NULL at the end
  return self;
}

static mrb_value
istruct_test_to_s(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_cstr(mrb, (const char*)mrb_istruct_ptr(self));
}

static mrb_value
istruct_test_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(mrb_istruct_size());
}

static mrb_value
istruct_test_test_receive(mrb_state *mrb, mrb_value self)
{
  mrb_value object;
  mrb_get_args(mrb, "o", &object);
  if (mrb_obj_class(mrb, object) != mrb_class_get(mrb, "InlineStructTest"))
  {
    mrb_raisef(mrb, E_TYPE_ERROR, "Expected InlineStructTest");
  }
  return mrb_bool_value(((char*)mrb_istruct_ptr(object))[0] == 's');
}

static mrb_value
istruct_test_test_receive_direct(mrb_state *mrb, mrb_value self)
{
  char *ptr;
  mrb_get_args(mrb, "I", &ptr);
  return mrb_bool_value(ptr[0] == 's');
}

static mrb_value
istruct_test_mutate(mrb_state *mrb, mrb_value self)
{
  char *ptr = (char*)mrb_istruct_ptr(self);
  memcpy(ptr, "mutate", 6);
  return mrb_nil_value();
}

void mrb_mruby_inline_struct_gem_test(mrb_state *mrb)
{
  struct RClass *cls;

  cls = mrb_define_class(mrb, "InlineStructTest", mrb->object_class);
  MRB_SET_INSTANCE_TT(cls, MRB_TT_ISTRUCT);
  mrb_define_method(mrb, cls, "initialize", istruct_test_initialize, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cls, "to_s", istruct_test_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, cls, "mutate", istruct_test_mutate, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, cls, "length", istruct_test_length, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, cls, "test_receive", istruct_test_test_receive, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, cls, "test_receive_direct", istruct_test_test_receive_direct, MRB_ARGS_REQ(1));
}
