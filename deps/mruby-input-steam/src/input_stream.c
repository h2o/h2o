#include <string.h>
#include "mruby.h"
#include "mruby/value.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "input_stream.h"

const static struct mrb_data_type mrb_input_stream_type = {
  "InputStream",
  mrb_mruby_input_stream_free,
};

static mrb_value
mrb_input_stream_init(mrb_state *mrb, mrb_value self)
{
  mrb_value str;
  mrb_int len;
  char *ptr;
  mrb_input_stream_t *stream;
  mrb_int n = mrb_get_args(mrb, "|S", &str);
  if (n > 1) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "wrong number of arguments (%S for 1)", mrb_fixnum_value(n));
  }

  if (n == 1) {
    len = RSTRING_LEN(str);
    ptr = RSTRING_PTR(str);
    stream = mrb_input_stream_create(mrb, ptr, len);
  } else {
    stream = mrb_input_stream_create(mrb, NULL, 0);
  }

  DATA_TYPE(self) = &mrb_input_stream_type;
  DATA_PTR(self) = stream;
  return self;
}

static void
mrb_mruby_input_stream_free(mrb_state *mrb, void *ptr)
{
  mrb_input_stream_t *stream = (mrb_input_stream_t *)ptr;
  char *base = stream->base;
  if (base) {
    mrb_free(mrb, base);
  }
  mrb_free(mrb, stream);
}

mrb_input_stream_t*
mrb_input_stream_create(mrb_state *mrb, char *base, mrb_int len)
{
  mrb_input_stream_t *stream = (mrb_input_stream_t *)mrb_malloc(mrb, sizeof(mrb_input_stream_t));

  if (len > 0) {
    char *dst_base = (char *)mrb_malloc(mrb, sizeof(char)*len);
    memcpy(dst_base, base, len);
    stream->base = dst_base;
    stream->len = len;
  } else {
    stream->base = NULL;
    stream->len = 0;
  }

  stream->pos = 0;
  return stream;
}

mrb_value
mrb_input_stream_value(mrb_state *mrb, char *base, mrb_int len)
{
  mrb_input_stream_t *stream = mrb_input_stream_create(mrb, base, len);
  struct RClass *c = mrb_class_get(mrb, "InputStream");
  struct RData *d = mrb_data_object_alloc(mrb, c, stream, &mrb_input_stream_type);

  return mrb_obj_value(d);
}

mrb_value
mrb_input_stream_gets(mrb_state *mrb, mrb_value self)
{
  mrb_input_stream_t *stream = DATA_PTR(self);
  mrb_int pos = stream->pos;
  mrb_int len = seek_char(stream, '\n');
  if (len < 0) {
    return mrb_nil_value();
  }
  if (stream->pos + len < stream->len) {
    len++;
  }
  stream->pos += len;
  return mrb_str_new(mrb, (stream->base + pos), len);
}

static mrb_int
seek_char(mrb_input_stream_t *stream, char chr){
  char *base = stream->base;
  size_t len = stream->len;
  mrb_int pos = stream->pos;

  if (pos >= len) {
    return -1;
  }
  const char *end = base + len;
  char *start = base + pos;
  char *s = start;

  while (s < end) {
    if (*s == chr) {
      break;
    }
    s++;
  }
  return (s - start);
}

mrb_value
mrb_input_stream_read(mrb_state *mrb, mrb_value self)
{
  mrb_int len;
  mrb_value buf;
  mrb_int n = mrb_get_args(mrb, "|iS", &len, &buf);

  mrb_input_stream_t *stream = DATA_PTR(self);
  mrb_int pos = stream->pos;
  const char *start = stream->base + pos;

  if (pos >= stream->len) {
    return mrb_nil_value();
  }
  if (n == 0) {
    stream->pos = stream->len;
    return mrb_str_new(mrb, start, stream->len - pos);
  } else {
    mrb_int newpos = pos + len;
    if (newpos > stream->len) {
      newpos = stream->len;
    }
    stream->pos = newpos;
    if (n == 1) {
      return mrb_str_new(mrb, start, newpos - pos);
    } else {
      return mrb_str_cat(mrb, buf, start, newpos - pos);
    }
  }
}

mrb_value
mrb_input_stream_rewind(mrb_state *mrb, mrb_value self)
{
  mrb_input_stream_t *stream = DATA_PTR(self);
  stream->pos = 0;
  return self;
}


mrb_value
mrb_input_stream_byteindex(mrb_state *mrb, mrb_value self)
{
  mrb_int chr;
  mrb_int n;

  n = mrb_get_args(mrb, "i", &chr);
  if (n != 1) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "wrong number of arguments (%S for 1)", mrb_fixnum_value(n));
  }
  if (chr < 0 || chr > 255) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "index should be a byte (0 - 255)");
  }

  mrb_input_stream_t *stream = DATA_PTR(self);

  mrb_int len = seek_char(stream, chr);
  if (len < 0) {
    return mrb_nil_value();
  }

  return mrb_fixnum_value(len);
}


void
mrb_mruby_input_stream_gem_init(mrb_state* mrb)
{
  struct RClass * c = mrb_define_class(mrb, "InputStream", mrb->object_class);

  mrb_define_method(mrb, c, "gets",  mrb_input_stream_gets,  MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "read",  mrb_input_stream_read,  MRB_ARGS_ANY());
  mrb_define_method(mrb, c, "initialize",  mrb_input_stream_init,  MRB_ARGS_BLOCK());
  mrb_define_method(mrb, c, "rewind",  mrb_input_stream_rewind,  MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "byteindex",  mrb_input_stream_byteindex,  MRB_ARGS_ANY());
}

void
mrb_mruby_input_stream_gem_final(mrb_state* mrb)
{
}
