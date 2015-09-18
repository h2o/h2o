/*
 * input_stream.h
 *
 */
#ifndef input_stream_h
#define input_stream_h

typedef struct mrb_input_stream_t {
  char *base;
  mrb_int len;
  mrb_int pos;
} mrb_input_stream_t;

mrb_input_stream_t*
mrb_input_stream_create(mrb_state *mrb, char *base, mrb_int len);

mrb_value
mrb_input_stream_value(mrb_state *mrb, char *base, mrb_int len);

static void
mrb_mruby_input_stream_free(mrb_state *mrb, void *ptr);

static mrb_int
seek_char(mrb_input_stream_t *stream, const char chr);

#endif /* input_stream_h */
