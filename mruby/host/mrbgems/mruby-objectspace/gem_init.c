/*
 * This file is loading the irep
 * Ruby GEM code.
 *
 * IMPORTANT:
 *   This file was generated!
 *   All manual changes will get lost.
 */
#include <mruby.h>
void mrb_mruby_objectspace_gem_init(mrb_state *mrb);
void mrb_mruby_objectspace_gem_final(mrb_state *mrb);

void GENERATED_TMP_mrb_mruby_objectspace_gem_init(mrb_state *mrb) {
  int ai = mrb_gc_arena_save(mrb);
  mrb_mruby_objectspace_gem_init(mrb);
  mrb_gc_arena_restore(mrb, ai);
}

void GENERATED_TMP_mrb_mruby_objectspace_gem_final(mrb_state *mrb) {
  mrb_mruby_objectspace_gem_final(mrb);
}
