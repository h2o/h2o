/*
** gc.c - garbage collector for mruby
**
** See Copyright Notice in mruby.h
*/

#include <string.h>
#ifdef MRB_USE_MALLOC_TRIM
#include <malloc.h>
#endif
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/istruct.h>
#include <mruby/hash.h>
#include <mruby/proc.h>
#include <mruby/range.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/gc.h>
#include <mruby/error.h>
#include <mruby/throw.h>
#include <mruby/presym.h>

#ifdef MRB_GC_STRESS
#include <stdlib.h>
#endif

/*
  = Tri-color Incremental Garbage Collection

  mruby's GC is Tri-color Incremental GC with Mark & Sweep.
  Algorithm details are omitted.
  Instead, the implementation part is described below.

  == Object's Color

  Each object can be painted in three colors:

    * White - Unmarked.
    * Gray - Marked, But the child objects are unmarked.
    * Black - Marked, the child objects are also marked.

  Extra color

    * Red - Static (ROM object) no need to be collected.
          - All child objects should be Red as well.

  == Two White Types

  There are two white color types in a flip-flop fashion: White-A and White-B,
  which respectively represent the Current White color (the newly allocated
  objects in the current GC cycle) and the Sweep Target White color (the
  dead objects to be swept).

  A and B will be switched just at the beginning of the next GC cycle. At
  that time, all the dead objects have been swept, while the newly created
  objects in the current GC cycle which finally remains White are now
  regarded as dead objects. Instead of traversing all the White-A objects and
  painting them as White-B, just switch the meaning of White-A and White-B as
  this will be much cheaper.

  As a result, the objects we sweep in the current GC cycle are always
  left from the previous GC cycle. This allows us to sweep objects
  incrementally, without the disturbance of the newly created objects.

  == Execution Timing

  GC Execution Time and Each step interval are decided by live objects count.
  List of Adjustment API:

    * gc_interval_ratio_set
    * gc_step_ratio_set

  For details, see the comments for each function.

  == Write Barrier

  mruby implementer and C extension library writer must insert a write
  barrier when updating a reference from a field of an object.
  When updating a reference from a field of object A to object B,
  two different types of write barrier are available:

    * mrb_field_write_barrier - target B object for a mark.
    * mrb_write_barrier       - target A object for a mark.

  == Generational Mode

  mruby's GC offers an Generational Mode while re-using the tri-color GC
  infrastructure. It will treat the Black objects as Old objects after each
  sweep phase, instead of painting them White. The key ideas are still the same
  as traditional generational GC:

    * Minor GC - just traverse the Young objects (Gray objects) in the mark
                 phase, then only sweep the newly created objects, and leave
                 the Old objects live.

    * Major GC - same as a full regular GC cycle.

  The difference from "traditional" generational GC is, that the major GC
  in mruby is triggered incrementally in a tri-color manner.


  For details, see the comments for each function.

*/

struct free_obj {
  MRB_OBJECT_HEADER;
  struct RBasic *next;
};

struct RVALUE_initializer {
  MRB_OBJECT_HEADER;
  char padding[sizeof(void*) * 4 - sizeof(uint32_t)];
};

typedef struct {
  union {
    struct RVALUE_initializer init;  /* must be first member to ensure initialization */
    struct free_obj free;
    struct RBasic basic;
    struct RObject object;
    struct RClass klass;
    struct RString string;
    struct RArray array;
    struct RHash hash;
    struct RRange range;
    struct RData data;
    struct RIStruct istruct;
    struct RProc proc;
    struct REnv env;
    struct RFiber fiber;
    struct RException exc;
    struct RBreak brk;
  } as;
} RVALUE;

#ifdef GC_PROFILE
#include <stdio.h>
#include <sys/time.h>

static double program_invoke_time = 0;
static double gc_time = 0;
static double gc_total_time = 0;

static double
gettimeofday_time(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}

#define GC_INVOKE_TIME_REPORT(with) do {\
  fprintf(stderr, "%s\n", with);\
  fprintf(stderr, "gc_invoke: %19.3f\n", gettimeofday_time() - program_invoke_time);\
  fprintf(stderr, "is_generational: %d\n", is_generational(gc));\
  fprintf(stderr, "is_major_gc: %d\n", is_major_gc(gc));\
} while(0)

#define GC_TIME_START do {\
  gc_time = gettimeofday_time();\
} while(0)

#define GC_TIME_STOP_AND_REPORT do {\
  gc_time = gettimeofday_time() - gc_time;\
  gc_total_time += gc_time;\
  fprintf(stderr, "gc_state: %d\n", gc->state);\
  fprintf(stderr, "live: %zu\n", gc->live);\
  fprintf(stderr, "majorgc_old_threshold: %zu\n", gc->majorgc_old_threshold);\
  fprintf(stderr, "gc_threshold: %zu\n", gc->threshold);\
  fprintf(stderr, "gc_time: %30.20f\n", gc_time);\
  fprintf(stderr, "gc_total_time: %30.20f\n\n", gc_total_time);\
} while(0)
#else
#define GC_INVOKE_TIME_REPORT(s)
#define GC_TIME_START
#define GC_TIME_STOP_AND_REPORT
#endif

#ifdef GC_DEBUG
#define DEBUG(x) (x)
#else
#define DEBUG(x)
#endif

#ifndef MRB_HEAP_PAGE_SIZE
#define MRB_HEAP_PAGE_SIZE 1024
#endif

#define GC_STEP_SIZE 1024

/* white: 001 or 010, black: 100, gray: 000 */
#define GC_GRAY 0
#define GC_WHITE_A 1
#define GC_WHITE_B (1 << 1)
#define GC_BLACK (1 << 2)
#define GC_RED MRB_GC_RED
#define GC_WHITES (GC_WHITE_A | GC_WHITE_B)
#define GC_COLOR_MASK 7
mrb_static_assert(MRB_GC_RED <= GC_COLOR_MASK);

#define paint_gray(o) ((o)->color = GC_GRAY)
#define paint_black(o) ((o)->color = GC_BLACK)
#define paint_white(o) ((o)->color = GC_WHITES)
#define paint_partial_white(s, o) ((o)->color = (s)->current_white_part)
#define is_gray(o) ((o)->color == GC_GRAY)
#define is_white(o) ((o)->color & GC_WHITES)
#define is_black(o) ((o)->color == GC_BLACK)
#define is_red(o) ((o)->color == GC_RED)
#define flip_white_part(s) ((s)->current_white_part = other_white_part(s))
#define other_white_part(s) ((s)->current_white_part ^ GC_WHITES)
#define is_dead(s, o) (((o)->color & other_white_part(s) & GC_WHITES) || (o)->tt == MRB_TT_FREE)

#define objects(p) ((RVALUE *)p->objects)

mrb_noreturn void mrb_raise_nomemory(mrb_state *mrb);

MRB_API void*
mrb_realloc_simple(mrb_state *mrb, void *p,  size_t len)
{
  void *p2;

  p2 = (mrb->allocf)(mrb, p, len, mrb->allocf_ud);
  if (!p2 && len > 0 && mrb->gc.heaps) {
    mrb_full_gc(mrb);
    p2 = (mrb->allocf)(mrb, p, len, mrb->allocf_ud);
  }

  return p2;
}

MRB_API void*
mrb_realloc(mrb_state *mrb, void *p, size_t len)
{
  void *p2;

  p2 = mrb_realloc_simple(mrb, p, len);
  if (len == 0) return p2;
  if (p2 == NULL) {
    mrb->gc.out_of_memory = TRUE;
    mrb_raise_nomemory(mrb);
  }
  else {
    mrb->gc.out_of_memory = FALSE;
  }

  return p2;
}

MRB_API void*
mrb_malloc(mrb_state *mrb, size_t len)
{
  return mrb_realloc(mrb, 0, len);
}

MRB_API void*
mrb_malloc_simple(mrb_state *mrb, size_t len)
{
  return mrb_realloc_simple(mrb, 0, len);
}

MRB_API void*
mrb_calloc(mrb_state *mrb, size_t nelem, size_t len)
{
  void *p;

  if (nelem > 0 && len > 0 &&
      nelem <= SIZE_MAX / len) {
    size_t size;
    size = nelem * len;
    p = mrb_malloc(mrb, size);

    memset(p, 0, size);
  }
  else {
    p = NULL;
  }

  return p;
}

MRB_API void
mrb_free(mrb_state *mrb, void *p)
{
  (mrb->allocf)(mrb, p, 0, mrb->allocf_ud);
}

MRB_API void*
mrb_alloca(mrb_state *mrb, size_t size)
{
  struct RString *s;
  s = MRB_OBJ_ALLOC(mrb, MRB_TT_STRING, mrb->string_class);
  return s->as.heap.ptr = (char*)mrb_malloc(mrb, size);
}

static mrb_bool
heap_p(mrb_gc *gc, struct RBasic *object)
{
  mrb_heap_page* page;

  page = gc->heaps;
  while (page) {
    RVALUE *p;

    p = objects(page);
    if (&p[0].as.basic <= object && object <= &p[MRB_HEAP_PAGE_SIZE].as.basic) {
      return TRUE;
    }
    page = page->next;
  }
  return FALSE;
}

MRB_API mrb_bool
mrb_object_dead_p(mrb_state *mrb, struct RBasic *object) {
  mrb_gc *gc = &mrb->gc;
  if (!heap_p(gc, object)) return TRUE;
  return is_dead(gc, object);
}

static void
link_heap_page(mrb_gc *gc, mrb_heap_page *page)
{
  page->next = gc->heaps;
  if (gc->heaps)
    gc->heaps->prev = page;
  gc->heaps = page;
}

static void
unlink_heap_page(mrb_gc *gc, mrb_heap_page *page)
{
  if (page->prev)
    page->prev->next = page->next;
  if (page->next)
    page->next->prev = page->prev;
  if (gc->heaps == page)
    gc->heaps = page->next;
  page->prev = NULL;
  page->next = NULL;
}

static void
link_free_heap_page(mrb_gc *gc, mrb_heap_page *page)
{
  page->free_next = gc->free_heaps;
  if (gc->free_heaps) {
    gc->free_heaps->free_prev = page;
  }
  gc->free_heaps = page;
}

static void
unlink_free_heap_page(mrb_gc *gc, mrb_heap_page *page)
{
  if (page->free_prev)
    page->free_prev->free_next = page->free_next;
  if (page->free_next)
    page->free_next->free_prev = page->free_prev;
  if (gc->free_heaps == page)
    gc->free_heaps = page->free_next;
  page->free_prev = NULL;
  page->free_next = NULL;
}

static void
add_heap(mrb_state *mrb, mrb_gc *gc)
{
  mrb_heap_page *page = (mrb_heap_page *)mrb_calloc(mrb, 1, sizeof(mrb_heap_page) + MRB_HEAP_PAGE_SIZE * sizeof(RVALUE));
  RVALUE *p, *e;
  struct RBasic *prev = NULL;

  for (p = objects(page), e=p+MRB_HEAP_PAGE_SIZE; p<e; p++) {
    p->as.free.tt = MRB_TT_FREE;
    p->as.free.next = prev;
    prev = &p->as.basic;
  }
  page->freelist = prev;

  link_heap_page(gc, page);
  link_free_heap_page(gc, page);
}

#define DEFAULT_GC_INTERVAL_RATIO 200
#define DEFAULT_GC_STEP_RATIO 200
#define MAJOR_GC_INC_RATIO 120
#define MAJOR_GC_TOOMANY 10000
#define is_generational(gc) ((gc)->generational)
#define is_major_gc(gc) (is_generational(gc) && (gc)->full)
#define is_minor_gc(gc) (is_generational(gc) && !(gc)->full)

void
mrb_gc_init(mrb_state *mrb, mrb_gc *gc)
{
#ifndef MRB_GC_FIXED_ARENA
  gc->arena = (struct RBasic**)mrb_malloc(mrb, sizeof(struct RBasic*)*MRB_GC_ARENA_SIZE);
  gc->arena_capa = MRB_GC_ARENA_SIZE;
#endif

  gc->current_white_part = GC_WHITE_A;
  gc->heaps = NULL;
  gc->free_heaps = NULL;
  add_heap(mrb, gc);
  gc->interval_ratio = DEFAULT_GC_INTERVAL_RATIO;
  gc->step_ratio = DEFAULT_GC_STEP_RATIO;
#ifndef MRB_GC_TURN_OFF_GENERATIONAL
  gc->generational = TRUE;
  gc->full = TRUE;
#endif

#ifdef GC_PROFILE
  program_invoke_time = gettimeofday_time();
#endif
}

static void obj_free(mrb_state *mrb, struct RBasic *obj, int end);

static void
free_heap(mrb_state *mrb, mrb_gc *gc)
{
  mrb_heap_page *page = gc->heaps;
  mrb_heap_page *tmp;
  RVALUE *p, *e;

  while (page) {
    tmp = page;
    page = page->next;
    for (p = objects(tmp), e=p+MRB_HEAP_PAGE_SIZE; p<e; p++) {
      if (p->as.free.tt != MRB_TT_FREE)
        obj_free(mrb, &p->as.basic, TRUE);
    }
    mrb_free(mrb, tmp);
  }
}

void
mrb_gc_destroy(mrb_state *mrb, mrb_gc *gc)
{
  free_heap(mrb, gc);
#ifndef MRB_GC_FIXED_ARENA
  mrb_free(mrb, gc->arena);
#endif
}

static void
gc_protect(mrb_state *mrb, mrb_gc *gc, struct RBasic *p)
{
#ifdef MRB_GC_FIXED_ARENA
  if (gc->arena_idx >= MRB_GC_ARENA_SIZE) {
    /* arena overflow error */
    gc->arena_idx = MRB_GC_ARENA_SIZE - 4; /* force room in arena */
    mrb_exc_raise(mrb, mrb_obj_value(mrb->arena_err));
  }
#else
  if (gc->arena_idx >= gc->arena_capa) {
    /* extend arena */
    gc->arena_capa = (int)(gc->arena_capa * 3 / 2);
    gc->arena = (struct RBasic**)mrb_realloc(mrb, gc->arena, sizeof(struct RBasic*)*gc->arena_capa);
  }
#endif
  gc->arena[gc->arena_idx++] = p;
}

/* mrb_gc_protect() leaves the object in the arena */
MRB_API void
mrb_gc_protect(mrb_state *mrb, mrb_value obj)
{
  if (mrb_immediate_p(obj)) return;
  gc_protect(mrb, &mrb->gc, mrb_basic_ptr(obj));
}

#define GC_ROOT_SYM MRB_SYM(_gc_root_)

/* mrb_gc_register() keeps the object from GC.

   Register your object when it's exported to C world,
   without reference from Ruby world, e.g. callback
   arguments.  Don't forget to remove the object using
   mrb_gc_unregister, otherwise your object will leak.
*/

MRB_API void
mrb_gc_register(mrb_state *mrb, mrb_value obj)
{
  mrb_sym root;
  mrb_value table;

  if (mrb_immediate_p(obj)) return;
  root = GC_ROOT_SYM;
  table = mrb_gv_get(mrb, root);
  if (mrb_nil_p(table) || !mrb_array_p(table)) {
    table = mrb_ary_new(mrb);
    mrb_gv_set(mrb, root, table);
  }
  mrb_ary_push(mrb, table, obj);
}

/* mrb_gc_unregister() removes the object from GC root. */
MRB_API void
mrb_gc_unregister(mrb_state *mrb, mrb_value obj)
{
  mrb_sym root;
  mrb_value table;
  struct RArray *a;
  mrb_int i;

  if (mrb_immediate_p(obj)) return;
  root = GC_ROOT_SYM;
  table = mrb_gv_get(mrb, root);
  if (mrb_nil_p(table)) return;
  if (!mrb_array_p(table)) {
    mrb_gv_set(mrb, root, mrb_nil_value());
    return;
  }
  a = mrb_ary_ptr(table);
  mrb_ary_modify(mrb, a);
  for (i = 0; i < ARY_LEN(a); i++) {
    if (mrb_ptr(ARY_PTR(a)[i]) == mrb_ptr(obj)) {
      mrb_int len = ARY_LEN(a)-1;
      mrb_value *ptr = ARY_PTR(a);

      ARY_SET_LEN(a, len);
      memmove(&ptr[i], &ptr[i + 1], (len - i) * sizeof(mrb_value));
      break;
    }
  }
}

MRB_API struct RBasic*
mrb_obj_alloc(mrb_state *mrb, enum mrb_vtype ttype, struct RClass *cls)
{
  struct RBasic *p;
  static const RVALUE RVALUE_zero = { { { NULL, NULL, MRB_TT_FALSE } } };
  mrb_gc *gc = &mrb->gc;

  if (cls) {
    enum mrb_vtype tt;

    switch (cls->tt) {
    case MRB_TT_CLASS:
    case MRB_TT_SCLASS:
    case MRB_TT_MODULE:
    case MRB_TT_ENV:
      break;
    default:
      mrb_raise(mrb, E_TYPE_ERROR, "allocation failure");
    }
    tt = MRB_INSTANCE_TT(cls);
    if (tt != MRB_TT_FALSE &&
        ttype != MRB_TT_SCLASS &&
        ttype != MRB_TT_ICLASS &&
        ttype != MRB_TT_ENV &&
        ttype != tt) {
      mrb_raisef(mrb, E_TYPE_ERROR, "allocation failure of %C", cls);
    }
  }
  if (ttype <= MRB_TT_FREE) {
    mrb_raisef(mrb, E_TYPE_ERROR, "allocation failure of %C (type %d)", cls, (int)ttype);
  }

#ifdef MRB_GC_STRESS
  mrb_full_gc(mrb);
#endif
  if (gc->threshold < gc->live) {
    mrb_incremental_gc(mrb);
  }
  if (gc->free_heaps == NULL) {
    add_heap(mrb, gc);
  }

  p = gc->free_heaps->freelist;
  gc->free_heaps->freelist = ((struct free_obj*)p)->next;
  if (gc->free_heaps->freelist == NULL) {
    unlink_free_heap_page(gc, gc->free_heaps);
  }

  gc->live++;
  gc_protect(mrb, gc, p);
  *(RVALUE *)p = RVALUE_zero;
  p->tt = ttype;
  p->c = cls;
  paint_partial_white(gc, p);
  return p;
}

static inline void
add_gray_list(mrb_state *mrb, mrb_gc *gc, struct RBasic *obj)
{
#ifdef MRB_GC_STRESS
  if (obj->tt > MRB_TT_MAXDEFINE) {
    abort();
  }
#endif
  paint_gray(obj);
  obj->gcnext = gc->gray_list;
  gc->gray_list = obj;
}

mrb_int mrb_ci_nregs(mrb_callinfo *ci);

static void
mark_context_stack(mrb_state *mrb, struct mrb_context *c)
{
  size_t i;
  size_t e;
  mrb_value nil;

  if (c->stbase == NULL) return;
  if (c->ci) {
    e = (c->ci->stack ? c->ci->stack - c->stbase : 0);
    e += mrb_ci_nregs(c->ci);
  }
  else {
    e = 0;
  }
  if (c->stbase + e > c->stend) e = c->stend - c->stbase;
  for (i=0; i<e; i++) {
    mrb_value v = c->stbase[i];

    if (!mrb_immediate_p(v)) {
      mrb_gc_mark(mrb, mrb_basic_ptr(v));
    }
  }
  e = c->stend - c->stbase;
  nil = mrb_nil_value();
  for (; i<e; i++) {
    c->stbase[i] = nil;
  }
}

static void
mark_context(mrb_state *mrb, struct mrb_context *c)
{
  mrb_callinfo *ci;

 start:
  if (c->status == MRB_FIBER_TERMINATED) return;

  /* mark VM stack */
  mark_context_stack(mrb, c);

  /* mark call stack */
  if (c->cibase) {
    for (ci = c->cibase; ci <= c->ci; ci++) {
      mrb_gc_mark(mrb, (struct RBasic*)ci->proc);
      mrb_gc_mark(mrb, (struct RBasic*)ci->u.target_class);
    }
  }
  /* mark fibers */
  mrb_gc_mark(mrb, (struct RBasic*)c->fib);
  if (c->prev) {
    c = c->prev;
    goto start;
  }
}

static void
gc_mark_children(mrb_state *mrb, mrb_gc *gc, struct RBasic *obj)
{
  mrb_assert(is_gray(obj));
  paint_black(obj);
  mrb_gc_mark(mrb, (struct RBasic*)obj->c);
  switch (obj->tt) {
  case MRB_TT_ICLASS:
    {
      struct RClass *c = (struct RClass*)obj;
      if (MRB_FLAG_TEST(c, MRB_FL_CLASS_IS_ORIGIN))
        mrb_gc_mark_mt(mrb, c);
      mrb_gc_mark(mrb, (struct RBasic*)((struct RClass*)obj)->super);
    }
    break;

  case MRB_TT_CLASS:
  case MRB_TT_MODULE:
  case MRB_TT_SCLASS:
    {
      struct RClass *c = (struct RClass*)obj;

      mrb_gc_mark_mt(mrb, c);
      mrb_gc_mark(mrb, (struct RBasic*)c->super);
    }
    /* fall through */

  case MRB_TT_OBJECT:
  case MRB_TT_DATA:
    mrb_gc_mark_iv(mrb, (struct RObject*)obj);
    break;

  case MRB_TT_PROC:
    {
      struct RProc *p = (struct RProc*)obj;

      mrb_gc_mark(mrb, (struct RBasic*)p->upper);
      mrb_gc_mark(mrb, (struct RBasic*)p->e.env);
    }
    break;

  case MRB_TT_ENV:
    {
      struct REnv *e = (struct REnv*)obj;
      mrb_int i, len;

      if (MRB_ENV_ONSTACK_P(e) && e->cxt && e->cxt->fib) {
        mrb_gc_mark(mrb, (struct RBasic*)e->cxt->fib);
      }
      len = MRB_ENV_LEN(e);
      for (i=0; i<len; i++) {
        mrb_gc_mark_value(mrb, e->stack[i]);
      }
    }
    break;

  case MRB_TT_FIBER:
    {
      struct mrb_context *c = ((struct RFiber*)obj)->cxt;

      if (c) mark_context(mrb, c);
    }
    break;

  case MRB_TT_STRUCT:
  case MRB_TT_ARRAY:
    {
      struct RArray *a = (struct RArray*)obj;
      size_t i, e=ARY_LEN(a);
      mrb_value *p = ARY_PTR(a);

      for (i=0; i<e; i++) {
        mrb_gc_mark_value(mrb, p[i]);
      }
    }
    break;

  case MRB_TT_HASH:
    mrb_gc_mark_iv(mrb, (struct RObject*)obj);
    mrb_gc_mark_hash(mrb, (struct RHash*)obj);
    break;

  case MRB_TT_STRING:
    if (RSTR_FSHARED_P(obj)) {
      struct RString *s = (struct RString*)obj;
      mrb_gc_mark(mrb, (struct RBasic*)s->as.heap.aux.fshared);
    }
    break;

  case MRB_TT_RANGE:
    mrb_gc_mark_range(mrb, (struct RRange*)obj);
    break;

  case MRB_TT_BREAK:
    {
      struct RBreak *brk = (struct RBreak*)obj;
      mrb_gc_mark(mrb, (struct RBasic*)mrb_break_proc_get(brk));
      mrb_gc_mark_value(mrb, mrb_break_value_get(brk));
    }
    break;

  case MRB_TT_EXCEPTION:
    mrb_gc_mark_iv(mrb, (struct RObject*)obj);
    if ((obj->flags & MRB_EXC_MESG_STRING_FLAG) != 0) {
      mrb_gc_mark(mrb, (struct RBasic*)((struct RException*)obj)->mesg);
    }
    break;

  default:
    break;
  }
}

MRB_API void
mrb_gc_mark(mrb_state *mrb, struct RBasic *obj)
{
  if (obj == 0) return;
  if (!is_white(obj)) return;
  if (is_red(obj)) return;
  mrb_assert((obj)->tt != MRB_TT_FREE);
  add_gray_list(mrb, &mrb->gc, obj);
}

static void
obj_free(mrb_state *mrb, struct RBasic *obj, int end)
{
  DEBUG(fprintf(stderr, "obj_free(%p,tt=%d)\n",obj,obj->tt));
  switch (obj->tt) {
  case MRB_TT_OBJECT:
    mrb_gc_free_iv(mrb, (struct RObject*)obj);
    break;

  case MRB_TT_EXCEPTION:
    mrb_gc_free_iv(mrb, (struct RObject*)obj);
    break;

  case MRB_TT_CLASS:
  case MRB_TT_MODULE:
  case MRB_TT_SCLASS:
    mrb_gc_free_mt(mrb, (struct RClass*)obj);
    mrb_gc_free_iv(mrb, (struct RObject*)obj);
    if (!end)
      mrb_mc_clear_by_class(mrb, (struct RClass*)obj);
    break;
  case MRB_TT_ICLASS:
    if (MRB_FLAG_TEST(obj, MRB_FL_CLASS_IS_ORIGIN))
      mrb_gc_free_mt(mrb, (struct RClass*)obj);
    if (!end)
      mrb_mc_clear_by_class(mrb, (struct RClass*)obj);
    break;
  case MRB_TT_ENV:
    {
      struct REnv *e = (struct REnv*)obj;

      if (MRB_ENV_ONSTACK_P(e)) {
        /* cannot be freed */
        e->stack = NULL;
        break;
      }
      mrb_free(mrb, e->stack);
      e->stack = NULL;
    }
    break;

  case MRB_TT_FIBER:
    {
      struct mrb_context *c = ((struct RFiber*)obj)->cxt;

      if (c && c != mrb->root_c) {
        if (!end && c->status != MRB_FIBER_TERMINATED) {
          mrb_callinfo *ci = c->ci;
          mrb_callinfo *ce = c->cibase;

          while (ce <= ci) {
            struct REnv *e = ci->u.env;
            if (e && !mrb_object_dead_p(mrb, (struct RBasic*)e) &&
                e->tt == MRB_TT_ENV && MRB_ENV_ONSTACK_P(e)) {
              mrb_env_unshare(mrb, e);
            }
            ci--;
          }
        }
        mrb_free_context(mrb, c);
      }
    }
    break;

  case MRB_TT_STRUCT:
  case MRB_TT_ARRAY:
    if (ARY_SHARED_P(obj))
      mrb_ary_decref(mrb, ((struct RArray*)obj)->as.heap.aux.shared);
    else if (!ARY_EMBED_P(obj))
      mrb_free(mrb, ((struct RArray*)obj)->as.heap.ptr);
    break;

  case MRB_TT_HASH:
    mrb_gc_free_iv(mrb, (struct RObject*)obj);
    mrb_gc_free_hash(mrb, (struct RHash*)obj);
    break;

  case MRB_TT_STRING:
    mrb_gc_free_str(mrb, (struct RString*)obj);
    break;

  case MRB_TT_PROC:
    {
      struct RProc *p = (struct RProc*)obj;

      if (!MRB_PROC_CFUNC_P(p) && p->body.irep) {
        mrb_irep *irep = (mrb_irep*)p->body.irep;
        if (end) {
          mrb_irep_cutref(mrb, irep);
        }
        mrb_irep_decref(mrb, irep);
      }
    }
    break;

  case MRB_TT_RANGE:
    mrb_gc_free_range(mrb, ((struct RRange*)obj));
    break;

  case MRB_TT_DATA:
    {
      struct RData *d = (struct RData*)obj;
      if (d->type && d->type->dfree) {
        d->type->dfree(mrb, d->data);
      }
      mrb_gc_free_iv(mrb, (struct RObject*)obj);
    }
    break;

#if defined(MRB_USE_RATIONAL) && defined(MRB_INT64) && defined(MRB_32BIT)
  case MRB_TT_RATIONAL:
    {
      struct RData *o = (struct RData*)obj;
      mrb_free(mrb, o->iv);
    }
    break;
#endif

#if defined(MRB_USE_COMPLEX) && defined(MRB_32BIT) && !defined(MRB_USE_FLOAT32)
  case MRB_TT_COMPLEX:
    {
      struct RData *o = (struct RData*)obj;
      mrb_free(mrb, o->iv);
    }
    break;
#endif

  default:
    break;
  }
  obj->tt = MRB_TT_FREE;
}

static void
root_scan_phase(mrb_state *mrb, mrb_gc *gc)
{
  int i, e;

  if (!is_minor_gc(gc)) {
    gc->gray_list = NULL;
    gc->atomic_gray_list = NULL;
  }

  mrb_gc_mark_gv(mrb);
  /* mark arena */
  for (i=0,e=gc->arena_idx; i<e; i++) {
    mrb_gc_mark(mrb, gc->arena[i]);
  }
  /* mark class hierarchy */
  mrb_gc_mark(mrb, (struct RBasic*)mrb->object_class);

  /* mark built-in classes */
  mrb_gc_mark(mrb, (struct RBasic*)mrb->class_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->module_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->proc_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->string_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->array_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->hash_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->range_class);

#ifndef MRB_NO_FLOAT
  mrb_gc_mark(mrb, (struct RBasic*)mrb->float_class);
#endif
  mrb_gc_mark(mrb, (struct RBasic*)mrb->integer_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->true_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->false_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->nil_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->symbol_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->kernel_module);

  mrb_gc_mark(mrb, (struct RBasic*)mrb->eException_class);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->eStandardError_class);

  /* mark top_self */
  mrb_gc_mark(mrb, (struct RBasic*)mrb->top_self);
  /* mark exception */
  mrb_gc_mark(mrb, (struct RBasic*)mrb->exc);
  /* mark pre-allocated exception */
  mrb_gc_mark(mrb, (struct RBasic*)mrb->nomem_err);
  mrb_gc_mark(mrb, (struct RBasic*)mrb->stack_err);
#ifdef MRB_GC_FIXED_ARENA
  mrb_gc_mark(mrb, (struct RBasic*)mrb->arena_err);
#endif

  mark_context(mrb, mrb->c);
  if (mrb->root_c != mrb->c) {
    mark_context(mrb, mrb->root_c);
  }
}

/* rough estimation of number of GC marks (non recursive) */
static size_t
gc_gray_counts(mrb_state *mrb, mrb_gc *gc, struct RBasic *obj)
{
  size_t children = 0;

  switch (obj->tt) {
  case MRB_TT_ICLASS:
    children++;
    break;

  case MRB_TT_CLASS:
  case MRB_TT_SCLASS:
  case MRB_TT_MODULE:
    {
      struct RClass *c = (struct RClass*)obj;

      children += mrb_gc_mark_iv_size(mrb, (struct RObject*)obj);
      children += mrb_gc_mark_mt_size(mrb, c);
      children++;
    }
    break;

  case MRB_TT_OBJECT:
  case MRB_TT_DATA:
    children += mrb_gc_mark_iv_size(mrb, (struct RObject*)obj);
    break;

  case MRB_TT_ENV:
    children += MRB_ENV_LEN(obj);
    break;

  case MRB_TT_FIBER:
    {
      struct mrb_context *c = ((struct RFiber*)obj)->cxt;
      size_t i;
      mrb_callinfo *ci;

      if (!c || c->status == MRB_FIBER_TERMINATED) break;

      /* mark stack */
      i = c->ci->stack - c->stbase;

      if (c->ci) {
        i += mrb_ci_nregs(c->ci);
      }
      if (c->stbase + i > c->stend) i = c->stend - c->stbase;
      children += i;

      /* mark closure */
      if (c->cibase) {
        for (i=0, ci = c->cibase; ci <= c->ci; i++, ci++)
          ;
      }
      children += i;
    }
    break;

  case MRB_TT_STRUCT:
  case MRB_TT_ARRAY:
    {
      struct RArray *a = (struct RArray*)obj;
      children += ARY_LEN(a);
    }
    break;

  case MRB_TT_HASH:
    children += mrb_gc_mark_iv_size(mrb, (struct RObject*)obj);
    children += mrb_gc_mark_hash_size(mrb, (struct RHash*)obj);
    break;

  case MRB_TT_PROC:
  case MRB_TT_RANGE:
  case MRB_TT_BREAK:
    children+=2;
    break;

  case MRB_TT_EXCEPTION:
    children += mrb_gc_mark_iv_size(mrb, (struct RObject*)obj);
    if ((obj->flags & MRB_EXC_MESG_STRING_FLAG) != 0) {
      children++;
    }
    break;

  default:
    break;
  }
  return children;
}


static void
gc_mark_gray_list(mrb_state *mrb, mrb_gc *gc) {
  while (gc->gray_list) {
    struct RBasic *obj = gc->gray_list;
    gc->gray_list = obj->gcnext;
    gc_mark_children(mrb, gc, obj);
  }
}


static size_t
incremental_marking_phase(mrb_state *mrb, mrb_gc *gc, size_t limit)
{
  size_t tried_marks = 0;

  while (gc->gray_list && tried_marks < limit) {
    struct RBasic *obj = gc->gray_list;
    gc->gray_list = obj->gcnext;
    gc_mark_children(mrb, gc, obj);
    tried_marks += gc_gray_counts(mrb, gc, obj);
  }

  return tried_marks;
}

static void
final_marking_phase(mrb_state *mrb, mrb_gc *gc)
{
  int i, e;

  /* mark arena */
  for (i=0,e=gc->arena_idx; i<e; i++) {
    mrb_gc_mark(mrb, gc->arena[i]);
  }
  mrb_gc_mark_gv(mrb);
  mark_context(mrb, mrb->c);
  if (mrb->c != mrb->root_c) {
    mark_context(mrb, mrb->root_c);
  }
  mrb_gc_mark(mrb, (struct RBasic*)mrb->exc);
  gc_mark_gray_list(mrb, gc);
  mrb_assert(gc->gray_list == NULL);
  gc->gray_list = gc->atomic_gray_list;
  gc->atomic_gray_list = NULL;
  gc_mark_gray_list(mrb, gc);
  mrb_assert(gc->gray_list == NULL);
}

static void
prepare_incremental_sweep(mrb_state *mrb, mrb_gc *gc)
{
  gc->state = MRB_GC_STATE_SWEEP;
  gc->sweeps = gc->heaps;
  gc->live_after_mark = gc->live;
}

static size_t
incremental_sweep_phase(mrb_state *mrb, mrb_gc *gc, size_t limit)
{
  mrb_heap_page *page = gc->sweeps;
  size_t tried_sweep = 0;

  while (page && (tried_sweep < limit)) {
    RVALUE *p = objects(page);
    RVALUE *e = p + MRB_HEAP_PAGE_SIZE;
    size_t freed = 0;
    mrb_bool dead_slot = TRUE;
    mrb_bool full = (page->freelist == NULL);

    if (is_minor_gc(gc) && page->old) {
      /* skip a slot which doesn't contain any young object */
      p = e;
      dead_slot = FALSE;
    }
    while (p<e) {
      if (is_dead(gc, &p->as.basic)) {
        if (p->as.basic.tt != MRB_TT_FREE) {
          obj_free(mrb, &p->as.basic, FALSE);
          if (p->as.basic.tt == MRB_TT_FREE) {
            p->as.free.next = page->freelist;
            page->freelist = (struct RBasic*)p;
            freed++;
          }
          else {
            dead_slot = FALSE;
          }
        }
      }
      else {
        if (!is_generational(gc))
          paint_partial_white(gc, &p->as.basic); /* next gc target */
        dead_slot = FALSE;
      }
      p++;
    }

    /* free dead slot */
    if (dead_slot && freed < MRB_HEAP_PAGE_SIZE) {
      mrb_heap_page *next = page->next;

      unlink_heap_page(gc, page);
      unlink_free_heap_page(gc, page);
      mrb_free(mrb, page);
      page = next;
    }
    else {
      if (full && freed > 0) {
        link_free_heap_page(gc, page);
      }
      if (page->freelist == NULL && is_minor_gc(gc))
        page->old = TRUE;
      else
        page->old = FALSE;
      page = page->next;
    }
    tried_sweep += MRB_HEAP_PAGE_SIZE;
    gc->live -= freed;
    gc->live_after_mark -= freed;
  }
  gc->sweeps = page;
  return tried_sweep;
}

static size_t
incremental_gc(mrb_state *mrb, mrb_gc *gc, size_t limit)
{
  switch (gc->state) {
  case MRB_GC_STATE_ROOT:
    root_scan_phase(mrb, gc);
    gc->state = MRB_GC_STATE_MARK;
    flip_white_part(gc);
    return 0;
  case MRB_GC_STATE_MARK:
    if (gc->gray_list) {
      return incremental_marking_phase(mrb, gc, limit);
    }
    else {
      final_marking_phase(mrb, gc);
      prepare_incremental_sweep(mrb, gc);
      return 0;
    }
  case MRB_GC_STATE_SWEEP: {
     size_t tried_sweep = 0;
     tried_sweep = incremental_sweep_phase(mrb, gc, limit);
     if (tried_sweep == 0)
       gc->state = MRB_GC_STATE_ROOT;
     return tried_sweep;
  }
  default:
    /* unknown state */
    mrb_assert(0);
    return 0;
  }
}

static void
incremental_gc_until(mrb_state *mrb, mrb_gc *gc, mrb_gc_state to_state)
{
  do {
    incremental_gc(mrb, gc, SIZE_MAX);
  } while (gc->state != to_state);
}

static void
incremental_gc_step(mrb_state *mrb, mrb_gc *gc)
{
  size_t limit = 0, result = 0;
  limit = (GC_STEP_SIZE/100) * gc->step_ratio;
  while (result < limit) {
    result += incremental_gc(mrb, gc, limit);
    if (gc->state == MRB_GC_STATE_ROOT)
      break;
  }

  gc->threshold = gc->live + GC_STEP_SIZE;
}

static void
clear_all_old(mrb_state *mrb, mrb_gc *gc)
{
  mrb_bool origin_mode = gc->generational;

  mrb_assert(is_generational(gc));
  if (is_major_gc(gc)) {
    /* finish the half baked GC */
    incremental_gc_until(mrb, gc, MRB_GC_STATE_ROOT);
  }

  /* Sweep the dead objects, then reset all the live objects
   * (including all the old objects, of course) to white. */
  gc->generational = FALSE;
  prepare_incremental_sweep(mrb, gc);
  incremental_gc_until(mrb, gc, MRB_GC_STATE_ROOT);
  gc->generational = origin_mode;

  /* The gray objects have already been painted as white */
  gc->atomic_gray_list = gc->gray_list = NULL;
}

MRB_API void
mrb_incremental_gc(mrb_state *mrb)
{
  mrb_gc *gc = &mrb->gc;

  if (gc->disabled || gc->iterating) return;

  GC_INVOKE_TIME_REPORT("mrb_incremental_gc()");
  GC_TIME_START;

  if (is_minor_gc(gc)) {
    incremental_gc_until(mrb, gc, MRB_GC_STATE_ROOT);
  }
  else {
    incremental_gc_step(mrb, gc);
  }

  if (gc->state == MRB_GC_STATE_ROOT) {
    mrb_assert(gc->live >= gc->live_after_mark);
    gc->threshold = (gc->live_after_mark/100) * gc->interval_ratio;
    if (gc->threshold < GC_STEP_SIZE) {
      gc->threshold = GC_STEP_SIZE;
    }

    if (is_major_gc(gc)) {
      size_t threshold = gc->live_after_mark/100 * MAJOR_GC_INC_RATIO;

      gc->full = FALSE;
      if (threshold < MAJOR_GC_TOOMANY) {
        gc->majorgc_old_threshold = threshold;
      }
      else {
        /* too many objects allocated during incremental GC, */
        /* instead of increasing threshold, invoke full GC. */
        mrb_full_gc(mrb);
      }
    }
    else if (is_minor_gc(gc)) {
      if (gc->live > gc->majorgc_old_threshold) {
        clear_all_old(mrb, gc);
        gc->full = TRUE;
      }
    }
  }

  GC_TIME_STOP_AND_REPORT;
}

/* Perform a full gc cycle */
MRB_API void
mrb_full_gc(mrb_state *mrb)
{
  mrb_gc *gc = &mrb->gc;

  if (!mrb->c) return;
  if (gc->disabled || gc->iterating) return;

  GC_INVOKE_TIME_REPORT("mrb_full_gc()");
  GC_TIME_START;

  if (is_generational(gc)) {
    /* clear all the old objects back to young */
    clear_all_old(mrb, gc);
    gc->full = TRUE;
  }
  else if (gc->state != MRB_GC_STATE_ROOT) {
    /* finish half baked GC cycle */
    incremental_gc_until(mrb, gc, MRB_GC_STATE_ROOT);
  }

  incremental_gc_until(mrb, gc, MRB_GC_STATE_ROOT);
  gc->threshold = (gc->live_after_mark/100) * gc->interval_ratio;

  if (is_generational(gc)) {
    gc->majorgc_old_threshold = gc->live_after_mark/100 * MAJOR_GC_INC_RATIO;
    gc->full = FALSE;
  }

#ifdef MRB_USE_MALLOC_TRIM
  malloc_trim(0);
#endif
  GC_TIME_STOP_AND_REPORT;
}

MRB_API void
mrb_garbage_collect(mrb_state *mrb)
{
  mrb_full_gc(mrb);
}

/*
 * Field write barrier
 *   Paint obj(Black) -> value(White) to obj(Black) -> value(Gray).
 */

MRB_API void
mrb_field_write_barrier(mrb_state *mrb, struct RBasic *obj, struct RBasic *value)
{
  mrb_gc *gc = &mrb->gc;

  if (!is_black(obj)) return;
  if (!is_white(value)) return;

  mrb_assert(gc->state == MRB_GC_STATE_MARK || (!is_dead(gc, value) && !is_dead(gc, obj)));
  mrb_assert(is_generational(gc) || gc->state != MRB_GC_STATE_ROOT);

  if (is_generational(gc) || gc->state == MRB_GC_STATE_MARK) {
    add_gray_list(mrb, gc, value);
  }
  else {
    mrb_assert(gc->state == MRB_GC_STATE_SWEEP);
    paint_partial_white(gc, obj); /* for never write barriers */
  }
}

/*
 * Write barrier
 *   Paint obj(Black) to obj(Gray).
 *
 *   The object that is painted gray will be traversed atomically in final
 *   mark phase. So you use this write barrier if it's frequency written spot.
 *   e.g. Set element on Array.
 */

MRB_API void
mrb_write_barrier(mrb_state *mrb, struct RBasic *obj)
{
  mrb_gc *gc = &mrb->gc;

  if (!is_black(obj)) return;

  mrb_assert(!is_dead(gc, obj));
  mrb_assert(is_generational(gc) || gc->state != MRB_GC_STATE_ROOT);
  paint_gray(obj);
  obj->gcnext = gc->atomic_gray_list;
  gc->atomic_gray_list = obj;
}

/*
 *  call-seq:
 *     GC.start                     -> nil
 *
 *  Initiates full garbage collection.
 *
 */

static mrb_value
gc_start(mrb_state *mrb, mrb_value obj)
{
  mrb_full_gc(mrb);
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     GC.enable    -> true or false
 *
 *  Enables garbage collection, returning <code>true</code> if garbage
 *  collection was previously disabled.
 *
 *     GC.disable   #=> false
 *     GC.enable    #=> true
 *     GC.enable    #=> false
 *
 */

static mrb_value
gc_enable(mrb_state *mrb, mrb_value obj)
{
  mrb_bool old = mrb->gc.disabled;

  mrb->gc.disabled = FALSE;

  return mrb_bool_value(old);
}

/*
 *  call-seq:
 *     GC.disable    -> true or false
 *
 *  Disables garbage collection, returning <code>true</code> if garbage
 *  collection was already disabled.
 *
 *     GC.disable   #=> false
 *     GC.disable   #=> true
 *
 */

static mrb_value
gc_disable(mrb_state *mrb, mrb_value obj)
{
  mrb_bool old = mrb->gc.disabled;

  mrb->gc.disabled = TRUE;

  return mrb_bool_value(old);
}

/*
 *  call-seq:
 *     GC.interval_ratio      -> int
 *
 *  Returns ratio of GC interval. Default value is 200(%).
 *
 */

static mrb_value
gc_interval_ratio_get(mrb_state *mrb, mrb_value obj)
{
  return mrb_int_value(mrb, mrb->gc.interval_ratio);
}

/*
 *  call-seq:
 *     GC.interval_ratio = int    -> nil
 *
 *  Updates ratio of GC interval. Default value is 200(%).
 *  GC start as soon as after end all step of GC if you set 100(%).
 *
 */

static mrb_value
gc_interval_ratio_set(mrb_state *mrb, mrb_value obj)
{
  mrb_int ratio;

  mrb_get_args(mrb, "i", &ratio);
  mrb->gc.interval_ratio = (int)ratio;
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     GC.step_ratio    -> int
 *
 *  Returns step span ratio of Incremental GC. Default value is 200(%).
 *
 */

static mrb_value
gc_step_ratio_get(mrb_state *mrb, mrb_value obj)
{
  return mrb_int_value(mrb, mrb->gc.step_ratio);
}

/*
 *  call-seq:
 *     GC.step_ratio = int   -> nil
 *
 *  Updates step span ratio of Incremental GC. Default value is 200(%).
 *  1 step of incrementalGC becomes long if a rate is big.
 *
 */

static mrb_value
gc_step_ratio_set(mrb_state *mrb, mrb_value obj)
{
  mrb_int ratio;

  mrb_get_args(mrb, "i", &ratio);
  mrb->gc.step_ratio = (int)ratio;
  return mrb_nil_value();
}

static void
change_gen_gc_mode(mrb_state *mrb, mrb_gc *gc, mrb_bool enable)
{
  if (gc->disabled || gc->iterating) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "generational mode changed when GC disabled");
    return;
  }
  if (is_generational(gc) && !enable) {
    clear_all_old(mrb, gc);
    mrb_assert(gc->state == MRB_GC_STATE_ROOT);
    gc->full = FALSE;
  }
  else if (!is_generational(gc) && enable) {
    incremental_gc_until(mrb, gc, MRB_GC_STATE_ROOT);
    gc->majorgc_old_threshold = gc->live_after_mark/100 * MAJOR_GC_INC_RATIO;
    gc->full = FALSE;
  }
  gc->generational = enable;
}

/*
 *  call-seq:
 *     GC.generational_mode -> true or false
 *
 *  Returns generational or normal gc mode.
 *
 */

static mrb_value
gc_generational_mode_get(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(mrb->gc.generational);
}

/*
 *  call-seq:
 *     GC.generational_mode = true or false -> true or false
 *
 *  Changes to generational or normal gc mode.
 *
 */

static mrb_value
gc_generational_mode_set(mrb_state *mrb, mrb_value self)
{
  mrb_bool enable;

  mrb_get_args(mrb, "b", &enable);
  if (mrb->gc.generational != enable)
    change_gen_gc_mode(mrb, &mrb->gc, enable);

  return mrb_bool_value(enable);
}


static void
gc_each_objects(mrb_state *mrb, mrb_gc *gc, mrb_each_object_callback *callback, void *data)
{
  mrb_heap_page* page;

  page = gc->heaps;
  while (page != NULL) {
    RVALUE *p;
    int i;

    p = objects(page);
    for (i=0; i < MRB_HEAP_PAGE_SIZE; i++) {
      if ((*callback)(mrb, &p[i].as.basic, data) == MRB_EACH_OBJ_BREAK)
        return;
    }
    page = page->next;
  }
}

void
mrb_objspace_each_objects(mrb_state *mrb, mrb_each_object_callback *callback, void *data)
{
  mrb_bool iterating = mrb->gc.iterating;

  mrb_full_gc(mrb);
  mrb->gc.iterating = TRUE;
  if (iterating) {
    gc_each_objects(mrb, &mrb->gc, callback, data);
  }
  else {
    struct mrb_jmpbuf *prev_jmp = mrb->jmp;
    struct mrb_jmpbuf c_jmp;

    MRB_TRY(&c_jmp) {
      mrb->jmp = &c_jmp;
      gc_each_objects(mrb, &mrb->gc, callback, data);
      mrb->jmp = prev_jmp;
      mrb->gc.iterating = iterating;
   } MRB_CATCH(&c_jmp) {
      mrb->gc.iterating = iterating;
      mrb->jmp = prev_jmp;
      MRB_THROW(prev_jmp);
    } MRB_END_EXC(&c_jmp);
  }
}

size_t
mrb_objspace_page_slot_size(void)
{
  return sizeof(RVALUE);
}


void
mrb_init_gc(mrb_state *mrb)
{
  struct RClass *gc;

  mrb_static_assert(sizeof(RVALUE) <= sizeof(void*) * 6,
                    "RVALUE size must be within 6 words");

  gc = mrb_define_module(mrb, "GC");

  mrb_define_class_method(mrb, gc, "start", gc_start, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, gc, "enable", gc_enable, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, gc, "disable", gc_disable, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, gc, "interval_ratio", gc_interval_ratio_get, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, gc, "interval_ratio=", gc_interval_ratio_set, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, gc, "step_ratio", gc_step_ratio_get, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, gc, "step_ratio=", gc_step_ratio_set, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, gc, "generational_mode=", gc_generational_mode_set, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, gc, "generational_mode", gc_generational_mode_get, MRB_ARGS_NONE());
}
