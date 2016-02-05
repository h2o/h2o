/*
 * input_stream.h
 *
 */
#ifndef mruby_input_stream_h
#define mruby_input_stream_h

typedef void (*mrb_input_stream_free_callback)(mrb_state *mrb, const char *base, mrb_int len, void *cb_data);

mrb_value
mrb_input_stream_value(mrb_state *mrb, const char *base, mrb_int len);

void
mrb_input_stream_get_data(mrb_state *mrb, mrb_value self, const char **base, mrb_int *len, mrb_int *pos, mrb_input_stream_free_callback *free_cb, void **free_cb_data);

void
mrb_input_stream_set_data(mrb_state *mrb, mrb_value self, const char *base, mrb_int len, mrb_int pos, mrb_input_stream_free_callback free_cb, void *free_cb_data);

#endif /* input_stream_h */
