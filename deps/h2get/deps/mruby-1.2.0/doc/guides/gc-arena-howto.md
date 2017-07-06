# How to use `mrb_gc_arena_save()`/`mrb_gc_arena_restore()`

This is basically English translation of [Matz's blog post](http://www.rubyist.net/~matz/20130731.html) written in Japanese.
Some parts are updated to reflect recent changes.

When you are extending mruby using C language, you may encounter
mysterious "arena overflow error" or memory leak or very slow
execution speed.  This is an error indicating overflow of "GC arena"
implementing "conservative GC".

GC (garbage collector) must ensure that object is "alive", in other
words, that it is referenced by somewhere from program.  This can be
determined by checking that that object can be directly or indirectly
referenced by root.  The local variables, global variables and
constants etc are root.

If program execution is performed inside mruby VM, there is nothing to
worry about because GC can access all roots owned by VM.

The problem arises when executing C functions.  The object referenced
by C variable is also "alive", but mruby GC cannot aware of this, so
it might mistakenly recognize the objects referenced by only C
variables as dead.

It is a fatal bug for GC to collect live objects.

In CRuby, we scan C stack area, and use C variable as root to check
whether object is alive or not.  Of course, because we are accessing C
stack just as memory region, we never know it is an integer or a
pointer.  We workaround this by assuming that if it looks like a
pointer, then assume it as a pointer.  We call it "conservative".

By the way, CRuby's "conservative GC" has some problems.

Its biggest problem is we have no way to access to the stack area in
portable way.  Therefore, we cannot use this method if we'd like to
implement highly portable runtime, like mruby.

So we came up an another plan to implement "conservative GC" in mruby.

Again, the problem is that there is an object which was created in C
function, and is not referenced by Ruby world, and cannot be treated
as garbage.

In mruby, we recognize all objects created in C function are alive.
Then we have no problem such as recognizing live object as dead.

This means that because we cannot collect truly dead object, we may
get a little bit less efficiency, but GC itself is highly portable.
We can say goodbye to the problem that GC deletes live objects due to
optimization which sometimes occurs in CRuby.

According to this idea, we have a table, called "GC arena", which
remembers objects created in C function.  The arena is stack
structure, when C function execution is returned to mruby VM, all
objects registered in the arena are popped.

This works very well, but GC arena causes another problem.  "arena
overflow error" or memory leak.

As of this writing, mruby automatically extend arena to remember
objects (See `MRB_GC_FIXED_ARENA` and `MRB_GC_ARENA_SIZE` in
doc/mrbconf/README.md).  If you keep creating objects in C functions,
it increases memory usage, since GC never kick in.  This memory usage
may look like memory leak, and also makes execution slower.

With the build time configuration, you can limit the maximum size of
arena (e.g., 100).  Then if you create many objects, arena overflows,
thus you will get "arena overflow error".

To workaround these problems, we have `mrb_gc_arena_save()` and
`mrb_gc_arena_restore()` functions.

`int mrb_gc_arena_save(mrb)` returns the current position of the stack
top of GC arena, and `void mrb_gc_arena_restore(mrb, idx)` sets the
stack top position to back to given idx.  We uses them like so:

```c
int arena_idx = mrb_gc_arena_save(mrb);

...create objects...
mrb_gc_arena_restore(mrb, arena_idx);

```

In mruby, C function call are surrounded by this save/restore, but we
can further optimize memory usage by surrounding save/restore, and can
avoid arena overflow.

Let's take a real example.  Here is the source code of `Array#inspect`:

```c
static mrb_value
inspect_ary(mrb_state *mrb, mrb_value ary, mrb_value list)
{
  mrb_int i;
  mrb_value s, arystr;
  char head[] = { '[' };
  char sep[] = { ',', ' ' };
  char tail[] = { ']' };

  /* check recursive */
  for(i=0; i<RARRAY_LEN(list); i++) {
    if (mrb_obj_equal(mrb, ary, RARRAY_PTR(list)[i])) {
      return mrb_str_new(mrb, "[...]", 5);
    }
  }

  mrb_ary_push(mrb, list, ary);

  arystr = mrb_str_buf_new(mrb, 64);
  mrb_str_buf_cat(mrb, arystr, head, sizeof(head));

  for(i=0; i<RARRAY_LEN(ary); i++) {
    int ai = mrb_gc_arena_save(mrb);

    if (i > 0) {
      mrb_str_buf_cat(mrb, arystr, sep, sizeof(sep));
    }
    if (mrb_array_p(RARRAY_PTR(ary)[i])) {
      s = inspect_ary(mrb, RARRAY_PTR(ary)[i], list);
    }
    else {
      s = mrb_inspect(mrb, RARRAY_PTR(ary)[i]);
    }
    mrb_str_buf_cat(mrb, arystr, RSTRING_PTR(s), RSTRING_LEN(s));
    mrb_gc_arena_restore(mrb, ai);
  }

  mrb_str_buf_cat(mrb, arystr, tail, sizeof(tail));
  mrb_ary_pop(mrb, list);

  return arystr;
}
```

This is a real example, so a little bit complicated, so bear with me.
The essence of `Array#inspect` is that after stringifying each element
of array using `inspect` method, we join them together so that we can
get `inspect` representation of entire array.

After the `inspect` representation of entire array is created, we no
longer require the individual string representation.  That means that
we don't have to register these temporal objects into GC arena.

Therefore, in `ary_inspect()` function, we do:

* save the position of the stack top using `mrb_gc_arena_save()`.
* get `inspect` representation of each element.
* append it to the constructing entire `inspect` representation of array.
* restore stack top position using `mrb_gc_arena_restore()`.

to keep the arena size small.

Please note that the final `inspect` representation of entire array
was created before the call of `mrb_gc_arena_restore()`.  Otherwise,
required temporal object may be deleted by GC.

We may have a usecase that after creating many temporal objects, we'd
like to keep some of them.  In this case, we cannot use the same idea
in `ary_inspect()` like appending objects to existing one.  Instead,
after `mrb_gc_arena_restore()`, we register back the objects we'd like
to keep to the arena using `mrb_gc_protect(mrb, obj)`.  Use
`mrb_gc_protect()` with caution because its usage could lead to arena
overflow error.

We also have to mention that when `mrb_funcall` is called in top
level, its return value is also registered to GC arena, so calling
them repeatedly eventually lead to arena overflow error.  Use
`mrb_gc_arena_save()` and `mrb_gc_arena_restore()` or possible use of
`mrb_gc_protect()` to workaround this.
