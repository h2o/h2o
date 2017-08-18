#include <mruby.h>
#include <mruby/irep.h>

extern const uint8_t mrblib_irep[];

void
mrb_init_mrblib(mrb_state *mrb)
{
  mrb_load_irep(mrb, mrblib_irep);
}

