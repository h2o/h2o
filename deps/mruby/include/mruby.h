/*
** mruby - An embeddable Ruby implementation
**
** Copyright (c) mruby developers 2010-2020
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
** [ MIT license: http://www.opensource.org/licenses/mit-license.php ]
*/

/**
 * @file mruby.h
 */

#ifndef MRUBY_H
#define MRUBY_H

#ifdef __cplusplus
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#ifdef __cplusplus
#ifndef SIZE_MAX
#ifdef __SIZE_MAX__
#define SIZE_MAX __SIZE_MAX__
#else
#define SIZE_MAX std::numeric_limits<size_t>::max()
#endif
#endif
#endif

#ifdef MRB_DEBUG
#include <assert.h>
#define mrb_assert(p) assert(p)
#define mrb_assert_int_fit(t1,n,t2,max) assert((n)>=0 && ((sizeof(n)<=sizeof(t2))||(n<=(t1)(max))))
#else
#define mrb_assert(p) ((void)0)
#define mrb_assert_int_fit(t1,n,t2,max) ((void)0)
#endif

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 201112L
#define mrb_static_assert(exp, str) _Static_assert(exp, str)
#else
#define mrb_static_assert(exp, str) mrb_assert(exp)
#endif

#include "mrbconf.h"

#include <mruby/common.h>
#include <mruby/value.h>
#include <mruby/gc.h>
#include <mruby/version.h>

#ifndef MRB_WITHOUT_FLOAT
#include <float.h>
#ifndef FLT_EPSILON
#define FLT_EPSILON (1.19209290e-07f)
#endif
#ifndef DBL_EPSILON
#define DBL_EPSILON ((double)2.22044604925031308085e-16L)
#endif
#ifndef LDBL_EPSILON
#define LDBL_EPSILON (1.08420217248550443401e-19L)
#endif

#ifdef MRB_USE_FLOAT
#define MRB_FLOAT_EPSILON FLT_EPSILON
#else
#define MRB_FLOAT_EPSILON DBL_EPSILON
#endif
#endif

/**
 * MRuby C API entry point
 */
MRB_BEGIN_DECL

typedef uint8_t mrb_code;

/**
 * \class mrb_aspec
 *
 * Specifies the number of arguments a function takes
 *
 * Example: `MRB_ARGS_REQ(2) | MRB_ARGS_OPT(1)` for a method that expects 2..3 arguments
 */
typedef uint32_t mrb_aspec;

struct mrb_irep;
struct mrb_state;

/**
 * Function pointer type of custom allocator used in @see mrb_open_allocf.
 *
 * The function pointing it must behave similarly as realloc except:
 * - If ptr is NULL it must allocate new space.
 * - If s is NULL, ptr must be freed.
 *
 * See @see mrb_default_allocf for the default implementation.
 */
typedef void* (*mrb_allocf) (struct mrb_state *mrb, void*, size_t, void *ud);

#ifndef MRB_FIXED_STATE_ATEXIT_STACK_SIZE
#define MRB_FIXED_STATE_ATEXIT_STACK_SIZE 5
#endif

typedef struct {
  mrb_sym mid;
  struct RProc *proc;
  mrb_value *stackent;
  uint16_t ridx;
  uint16_t epos;
  struct REnv *env;
  const mrb_code *pc;           /* return address */
  const mrb_code *err;          /* error position */
  int argc;
  int acc;
  struct RClass *target_class;
} mrb_callinfo;

enum mrb_fiber_state {
  MRB_FIBER_CREATED = 0,
  MRB_FIBER_RUNNING,
  MRB_FIBER_RESUMED,
  MRB_FIBER_SUSPENDED,
  MRB_FIBER_TRANSFERRED,
  MRB_FIBER_TERMINATED,
};

struct mrb_context {
  struct mrb_context *prev;

  mrb_value *stack;                       /* stack of virtual machine */
  mrb_value *stbase, *stend;

  mrb_callinfo *ci;
  mrb_callinfo *cibase, *ciend;

  uint16_t *rescue;                       /* exception handler stack */
  uint16_t rsize;
  struct RProc **ensure;                  /* ensure handler stack */
  uint16_t esize, eidx;

  enum mrb_fiber_state status : 4;
  mrb_bool vmexec : 1;
  struct RFiber *fib;
};

#ifdef MRB_METHOD_CACHE_SIZE
# define MRB_METHOD_CACHE
#else
/* default method cache size: 128 */
/* cache size needs to be power of 2 */
# define MRB_METHOD_CACHE_SIZE (1<<7)
#endif

/**
 * Function pointer type for a function callable by mruby.
 *
 * The arguments to the function are stored on the mrb_state. To get them see mrb_get_args
 *
 * @param mrb The mruby state
 * @param self The self object
 * @return [mrb_value] The function's return value
 */
typedef mrb_value (*mrb_func_t)(struct mrb_state *mrb, mrb_value self);

#ifndef MRB_METHOD_T_STRUCT
typedef uintptr_t mrb_method_t;
#else
typedef struct {
  uint8_t flags;
  union {
    struct RProc *proc;
    mrb_func_t func;
  };
} mrb_method_t;
#endif

#ifdef MRB_METHOD_CACHE
struct mrb_cache_entry {
  struct RClass *c, *c0;
  mrb_sym mid;
  mrb_method_t m;
};
#endif

struct mrb_jmpbuf;

typedef void (*mrb_atexit_func)(struct mrb_state*);

typedef struct mrb_state {
  struct mrb_jmpbuf *jmp;

  mrb_allocf allocf;                      /* memory allocation function */
  void *allocf_ud;                        /* auxiliary data of allocf */

  struct mrb_context *c;
  struct mrb_context *root_c;
  struct iv_tbl *globals;                 /* global variable table */

  struct RObject *exc;                    /* exception */

  struct RObject *top_self;
  struct RClass *object_class;            /* Object class */
  struct RClass *class_class;
  struct RClass *module_class;
  struct RClass *proc_class;
  struct RClass *string_class;
  struct RClass *array_class;
  struct RClass *hash_class;
  struct RClass *range_class;

#ifndef MRB_WITHOUT_FLOAT
  struct RClass *float_class;
#endif
  struct RClass *fixnum_class;
  struct RClass *true_class;
  struct RClass *false_class;
  struct RClass *nil_class;
  struct RClass *symbol_class;
  struct RClass *kernel_module;

  mrb_gc gc;

#ifdef MRB_METHOD_CACHE
  struct mrb_cache_entry cache[MRB_METHOD_CACHE_SIZE];
#endif

  mrb_sym symidx;
  struct symbol_name *symtbl;   /* symbol table */
  mrb_sym symhash[256];
  size_t symcapa;
#ifndef MRB_ENABLE_SYMBOLL_ALL
  char symbuf[8];               /* buffer for small symbol names */
#endif

#ifdef MRB_ENABLE_DEBUG_HOOK
  void (*code_fetch_hook)(struct mrb_state* mrb, struct mrb_irep *irep, const mrb_code *pc, mrb_value *regs);
  void (*debug_op_hook)(struct mrb_state* mrb, struct mrb_irep *irep, const mrb_code *pc, mrb_value *regs);
#endif

#ifdef MRB_BYTECODE_DECODE_OPTION
  mrb_code (*bytecode_decoder)(struct mrb_state* mrb, mrb_code code);
#endif

  struct RClass *eException_class;
  struct RClass *eStandardError_class;
  struct RObject *nomem_err;              /* pre-allocated NoMemoryError */
  struct RObject *stack_err;              /* pre-allocated SysStackError */
#ifdef MRB_GC_FIXED_ARENA
  struct RObject *arena_err;              /* pre-allocated arena overfow error */
#endif

  void *ud; /* auxiliary data */

#ifdef MRB_FIXED_STATE_ATEXIT_STACK
  mrb_atexit_func atexit_stack[MRB_FIXED_STATE_ATEXIT_STACK_SIZE];
#else
  mrb_atexit_func *atexit_stack;
#endif
  uint16_t atexit_stack_len;
  uint16_t ecall_nest;                    /* prevent infinite recursive ecall() */
} mrb_state;

/**
 * Defines a new class.
 *
 * If you're creating a gem it may look something like this:
 *
 *      !!!c
 *      void mrb_example_gem_init(mrb_state* mrb) {
 *          struct RClass *example_class;
 *          example_class = mrb_define_class(mrb, "Example_Class", mrb->object_class);
 *      }
 *
 *      void mrb_example_gem_final(mrb_state* mrb) {
 *          //free(TheAnimals);
 *      }
 *
 * @param mrb The current mruby state.
 * @param name The name of the defined class.
 * @param super The new class parent.
 * @return [struct RClass *] Reference to the newly defined class.
 * @see mrb_define_class_under
 */
MRB_API struct RClass *mrb_define_class(mrb_state *mrb, const char *name, struct RClass *super);

/**
 * Defines a new module.
 *
 * @param mrb The current mruby state.
 * @param name The name of the module.
 * @return [struct RClass *] Reference to the newly defined module.
 */
MRB_API struct RClass *mrb_define_module(mrb_state *mrb, const char *name);

MRB_API mrb_value mrb_singleton_class(mrb_state *mrb, mrb_value val);
MRB_API struct RClass *mrb_singleton_class_ptr(mrb_state *mrb, mrb_value val);

/**
 * Include a module in another class or module.
 * Equivalent to:
 *
 *   module B
 *     include A
 *   end
 * @param mrb The current mruby state.
 * @param cla A reference to module or a class.
 * @param included A reference to the module to be included.
 */
MRB_API void mrb_include_module(mrb_state *mrb, struct RClass *cla, struct RClass *included);

/**
 * Prepends a module in another class or module.
 *
 * Equivalent to:
 *  module B
 *    prepend A
 *  end
 * @param mrb The current mruby state.
 * @param cla A reference to module or a class.
 * @param prepended A reference to the module to be prepended.
 */
MRB_API void mrb_prepend_module(mrb_state *mrb, struct RClass *cla, struct RClass *prepended);

/**
 * Defines a global function in ruby.
 *
 * If you're creating a gem it may look something like this
 *
 * Example:
 *
 *     mrb_value example_method(mrb_state* mrb, mrb_value self)
 *     {
 *          puts("Executing example command!");
 *          return self;
 *     }
 *
 *     void mrb_example_gem_init(mrb_state* mrb)
 *     {
 *           mrb_define_method(mrb, mrb->kernel_module, "example_method", example_method, MRB_ARGS_NONE());
 *     }
 *
 * @param mrb The MRuby state reference.
 * @param cla The class pointer where the method will be defined.
 * @param name The name of the method being defined.
 * @param func The function pointer to the method definition.
 * @param aspec The method parameters declaration.
 */
MRB_API void mrb_define_method(mrb_state *mrb, struct RClass *cla, const char *name, mrb_func_t func, mrb_aspec aspec);

/**
 * Defines a class method.
 *
 * Example:
 *
 *     # Ruby style
 *     class Foo
 *       def Foo.bar
 *       end
 *     end
 *     // C style
 *     mrb_value bar_method(mrb_state* mrb, mrb_value self){
 *       return mrb_nil_value();
 *     }
 *     void mrb_example_gem_init(mrb_state* mrb){
 *       struct RClass *foo;
 *       foo = mrb_define_class(mrb, "Foo", mrb->object_class);
 *       mrb_define_class_method(mrb, foo, "bar", bar_method, MRB_ARGS_NONE());
 *     }
 * @param mrb The MRuby state reference.
 * @param cla The class where the class method will be defined.
 * @param name The name of the class method being defined.
 * @param fun The function pointer to the class method definition.
 * @param aspec The method parameters declaration.
 */
MRB_API void mrb_define_class_method(mrb_state *mrb, struct RClass *cla, const char *name, mrb_func_t fun, mrb_aspec aspec);

/**
 * Defines a singleton method
 *
 * @see mrb_define_class_method
 */
MRB_API void mrb_define_singleton_method(mrb_state *mrb, struct RObject *cla, const char *name, mrb_func_t fun, mrb_aspec aspec);

/**
 *  Defines a module function.
 *
 * Example:
 *
 *        # Ruby style
 *        module Foo
 *          def Foo.bar
 *          end
 *        end
 *        // C style
 *        mrb_value bar_method(mrb_state* mrb, mrb_value self){
 *          return mrb_nil_value();
 *        }
 *        void mrb_example_gem_init(mrb_state* mrb){
 *          struct RClass *foo;
 *          foo = mrb_define_module(mrb, "Foo");
 *          mrb_define_module_function(mrb, foo, "bar", bar_method, MRB_ARGS_NONE());
 *        }
 *  @param mrb The MRuby state reference.
 *  @param cla The module where the module function will be defined.
 *  @param name The name of the module function being defined.
 *  @param fun The function pointer to the module function definition.
 *  @param aspec The method parameters declaration.
 */
MRB_API void mrb_define_module_function(mrb_state *mrb, struct RClass *cla, const char *name, mrb_func_t fun, mrb_aspec aspec);

/**
 *  Defines a constant.
 *
 * Example:
 *
 *          # Ruby style
 *          class ExampleClass
 *            AGE = 22
 *          end
 *          // C style
 *          #include <stdio.h>
 *          #include <mruby.h>
 *
 *          void
 *          mrb_example_gem_init(mrb_state* mrb){
 *            mrb_define_const(mrb, mrb->kernel_module, "AGE", mrb_fixnum_value(22));
 *          }
 *
 *          mrb_value
 *          mrb_example_gem_final(mrb_state* mrb){
 *          }
 *  @param mrb The MRuby state reference.
 *  @param cla A class or module the constant is defined in.
 *  @param name The name of the constant being defined.
 *  @param val The value for the constant.
 */
MRB_API void mrb_define_const(mrb_state* mrb, struct RClass* cla, const char *name, mrb_value val);

/**
 * Undefines a method.
 *
 * Example:
 *
 *     # Ruby style
 *
 *     class ExampleClassA
 *       def example_method
 *         "example"
 *       end
 *     end
 *     ExampleClassA.new.example_method # => example
 *
 *     class ExampleClassB < ExampleClassA
 *       undef_method :example_method
 *     end
 *
 *     ExampleClassB.new.example_method # => undefined method 'example_method' for ExampleClassB (NoMethodError)
 *
 *     // C style
 *     #include <stdio.h>
 *     #include <mruby.h>
 *
 *     mrb_value
 *     mrb_example_method(mrb_state *mrb){
 *       return mrb_str_new_lit(mrb, "example");
 *     }
 *
 *     void
 *     mrb_example_gem_init(mrb_state* mrb){
 *       struct RClass *example_class_a;
 *       struct RClass *example_class_b;
 *       struct RClass *example_class_c;
 *
 *       example_class_a = mrb_define_class(mrb, "ExampleClassA", mrb->object_class);
 *       mrb_define_method(mrb, example_class_a, "example_method", mrb_example_method, MRB_ARGS_NONE());
 *       example_class_b = mrb_define_class(mrb, "ExampleClassB", example_class_a);
 *       example_class_c = mrb_define_class(mrb, "ExampleClassC", example_class_b);
 *       mrb_undef_method(mrb, example_class_c, "example_method");
 *     }
 *
 *     mrb_example_gem_final(mrb_state* mrb){
 *     }
 * @param mrb The mruby state reference.
 * @param cla The class the method will be undefined from.
 * @param name The name of the method to be undefined.
 */
MRB_API void mrb_undef_method(mrb_state *mrb, struct RClass *cla, const char *name);
MRB_API void mrb_undef_method_id(mrb_state*, struct RClass*, mrb_sym);

/**
 * Undefine a class method.
 * Example:
 *
 *      # Ruby style
 *      class ExampleClass
 *        def self.example_method
 *          "example"
 *        end
 *      end
 *
 *     ExampleClass.example_method
 *
 *     // C style
 *     #include <stdio.h>
 *     #include <mruby.h>
 *
 *     mrb_value
 *     mrb_example_method(mrb_state *mrb){
 *       return mrb_str_new_lit(mrb, "example");
 *     }
 *
 *     void
 *     mrb_example_gem_init(mrb_state* mrb){
 *       struct RClass *example_class;
 *       example_class = mrb_define_class(mrb, "ExampleClass", mrb->object_class);
 *       mrb_define_class_method(mrb, example_class, "example_method", mrb_example_method, MRB_ARGS_NONE());
 *       mrb_undef_class_method(mrb, example_class, "example_method");
 *      }
 *
 *      void
 *      mrb_example_gem_final(mrb_state* mrb){
 *      }
 * @param mrb The mruby state reference.
 * @param cls A class the class method will be undefined from.
 * @param name The name of the class method to be undefined.
 */
MRB_API void mrb_undef_class_method(mrb_state *mrb, struct RClass *cls, const char *name);

/**
 * Initialize a new object instance of c class.
 *
 * Example:
 *
 *     # Ruby style
 *     class ExampleClass
 *     end
 *
 *     p ExampleClass # => #<ExampleClass:0x9958588>
 *     // C style
 *     #include <stdio.h>
 *     #include <mruby.h>
 *
 *     void
 *     mrb_example_gem_init(mrb_state* mrb) {
 *       struct RClass *example_class;
 *       mrb_value obj;
 *       example_class = mrb_define_class(mrb, "ExampleClass", mrb->object_class); # => class ExampleClass; end
 *       obj = mrb_obj_new(mrb, example_class, 0, NULL); # => ExampleClass.new
 *       mrb_p(mrb, obj); // => Kernel#p
 *      }
 * @param mrb The current mruby state.
 * @param c Reference to the class of the new object.
 * @param argc Number of arguments in argv
 * @param argv Array of mrb_value to initialize the object
 * @return [mrb_value] The newly initialized object
 */
MRB_API mrb_value mrb_obj_new(mrb_state *mrb, struct RClass *c, mrb_int argc, const mrb_value *argv);

/** @see mrb_obj_new */
MRB_INLINE mrb_value mrb_class_new_instance(mrb_state *mrb, mrb_int argc, const mrb_value *argv, struct RClass *c)
{
  return mrb_obj_new(mrb,c,argc,argv);
}

/**
 * Creates a new instance of Class, Class.
 *
 * Example:
 *
 *      void
 *      mrb_example_gem_init(mrb_state* mrb) {
 *        struct RClass *example_class;
 *
 *        mrb_value obj;
 *        example_class = mrb_class_new(mrb, mrb->object_class);
 *        obj = mrb_obj_new(mrb, example_class, 0, NULL); // => #<#<Class:0x9a945b8>:0x9a94588>
 *        mrb_p(mrb, obj); // => Kernel#p
 *       }
 *
 * @param mrb The current mruby state.
 * @param super The super class or parent.
 * @return [struct RClass *] Reference to the new class.
 */
MRB_API struct RClass * mrb_class_new(mrb_state *mrb, struct RClass *super);

/**
 * Creates a new module, Module.
 *
 * Example:
 *      void
 *      mrb_example_gem_init(mrb_state* mrb) {
 *        struct RClass *example_module;
 *
 *        example_module = mrb_module_new(mrb);
 *      }
 *
 * @param mrb The current mruby state.
 * @return [struct RClass *] Reference to the new module.
 */
MRB_API struct RClass * mrb_module_new(mrb_state *mrb);

/**
 * Returns an mrb_bool. True if class was defined, and false if the class was not defined.
 *
 * Example:
 *     void
 *     mrb_example_gem_init(mrb_state* mrb) {
 *       struct RClass *example_class;
 *       mrb_bool cd;
 *
 *       example_class = mrb_define_class(mrb, "ExampleClass", mrb->object_class);
 *       cd = mrb_class_defined(mrb, "ExampleClass");
 *
 *       // If mrb_class_defined returns 1 then puts "True"
 *       // If mrb_class_defined returns 0 then puts "False"
 *       if (cd == 1){
 *         puts("True");
 *       }
 *       else {
 *         puts("False");
 *       }
 *      }
 *
 * @param mrb The current mruby state.
 * @param name A string representing the name of the class.
 * @return [mrb_bool] A boolean value.
 */
MRB_API mrb_bool mrb_class_defined(mrb_state *mrb, const char *name);

/**
 * Gets a class.
 * @param mrb The current mruby state.
 * @param name The name of the class.
 * @return [struct RClass *] A reference to the class.
*/
MRB_API struct RClass * mrb_class_get(mrb_state *mrb, const char *name);

/**
 * Gets a exception class.
 * @param mrb The current mruby state.
 * @param name The name of the class.
 * @return [struct RClass *] A reference to the class.
*/
MRB_API struct RClass * mrb_exc_get(mrb_state *mrb, const char *name);

/**
 * Returns an mrb_bool. True if inner class was defined, and false if the inner class was not defined.
 *
 * Example:
 *     void
 *     mrb_example_gem_init(mrb_state* mrb) {
 *       struct RClass *example_outer, *example_inner;
 *       mrb_bool cd;
 *
 *       example_outer = mrb_define_module(mrb, "ExampleOuter");
 *
 *       example_inner = mrb_define_class_under(mrb, example_outer, "ExampleInner", mrb->object_class);
 *       cd = mrb_class_defined_under(mrb, example_outer, "ExampleInner");
 *
 *       // If mrb_class_defined_under returns 1 then puts "True"
 *       // If mrb_class_defined_under returns 0 then puts "False"
 *       if (cd == 1){
 *         puts("True");
 *       }
 *       else {
 *         puts("False");
 *       }
 *      }
 *
 * @param mrb The current mruby state.
 * @param outer The name of the outer class.
 * @param name A string representing the name of the inner class.
 * @return [mrb_bool] A boolean value.
 */
MRB_API mrb_bool mrb_class_defined_under(mrb_state *mrb, struct RClass *outer, const char *name);

/**
 * Gets a child class.
 * @param mrb The current mruby state.
 * @param outer The name of the parent class.
 * @param name The name of the class.
 * @return [struct RClass *] A reference to the class.
*/
MRB_API struct RClass * mrb_class_get_under(mrb_state *mrb, struct RClass *outer, const char *name);

/**
 * Gets a module.
 * @param mrb The current mruby state.
 * @param name The name of the module.
 * @return [struct RClass *] A reference to the module.
*/
MRB_API struct RClass * mrb_module_get(mrb_state *mrb, const char *name);

/**
 * Gets a module defined under another module.
 * @param mrb The current mruby state.
 * @param outer The name of the outer module.
 * @param name The name of the module.
 * @return [struct RClass *] A reference to the module.
*/
MRB_API struct RClass * mrb_module_get_under(mrb_state *mrb, struct RClass *outer, const char *name);
/* a function to raise NotImplementedError with current method name */
MRB_API void mrb_notimplement(mrb_state*);
/* a function to be replacement of unimplemented method */
MRB_API mrb_value mrb_notimplement_m(mrb_state*, mrb_value);

/**
 * Duplicate an object.
 *
 * Equivalent to:
 *   Object#dup
 * @param mrb The current mruby state.
 * @param obj Object to be duplicate.
 * @return [mrb_value] The newly duplicated object.
 */
MRB_API mrb_value mrb_obj_dup(mrb_state *mrb, mrb_value obj);

/**
 * Returns true if obj responds to the given method. If the method was defined for that
 * class it returns true, it returns false otherwise.
 *
 *      Example:
 *      # Ruby style
 *      class ExampleClass
 *        def example_method
 *        end
 *      end
 *
 *      ExampleClass.new.respond_to?(:example_method) # => true
 *
 *      // C style
 *      void
 *      mrb_example_gem_init(mrb_state* mrb) {
 *        struct RClass *example_class;
 *        mrb_sym mid;
 *        mrb_bool obj_resp;
 *
 *        example_class = mrb_define_class(mrb, "ExampleClass", mrb->object_class);
 *        mrb_define_method(mrb, example_class, "example_method", exampleMethod, MRB_ARGS_NONE());
 *        mid = mrb_intern_str(mrb, mrb_str_new_lit(mrb, "example_method" ));
 *        obj_resp = mrb_obj_respond_to(mrb, example_class, mid); // => 1(true in Ruby world)
 *
 *        // If mrb_obj_respond_to returns 1 then puts "True"
 *        // If mrb_obj_respond_to returns 0 then puts "False"
 *        if (obj_resp == 1) {
 *          puts("True");
 *        }
 *        else if (obj_resp == 0) {
 *          puts("False");
 *        }
 *      }
 *
 * @param mrb The current mruby state.
 * @param c A reference to a class.
 * @param mid A symbol referencing a method id.
 * @return [mrb_bool] A boolean value.
 */
MRB_API mrb_bool mrb_obj_respond_to(mrb_state *mrb, struct RClass* c, mrb_sym mid);

/**
 * Defines a new class under a given module
 *
 * @param mrb The current mruby state.
 * @param outer Reference to the module under which the new class will be defined
 * @param name The name of the defined class
 * @param super The new class parent
 * @return [struct RClass *] Reference to the newly defined class
 * @see mrb_define_class
 */
MRB_API struct RClass * mrb_define_class_under(mrb_state *mrb, struct RClass *outer, const char *name, struct RClass *super);

MRB_API struct RClass * mrb_define_module_under(mrb_state *mrb, struct RClass *outer, const char *name);

/**
 * Function requires n arguments.
 *
 * @param n
 *      The number of required arguments.
 */
#define MRB_ARGS_REQ(n)     ((mrb_aspec)((n)&0x1f) << 18)

/**
 * Function takes n optional arguments
 *
 * @param n
 *      The number of optional arguments.
 */
#define MRB_ARGS_OPT(n)     ((mrb_aspec)((n)&0x1f) << 13)

/**
 * Function takes n1 mandatory arguments and n2 optional arguments
 *
 * @param n1
 *      The number of required arguments.
 * @param n2
 *      The number of optional arguments.
 */
#define MRB_ARGS_ARG(n1,n2)   (MRB_ARGS_REQ(n1)|MRB_ARGS_OPT(n2))

/** rest argument */
#define MRB_ARGS_REST()     ((mrb_aspec)(1 << 12))

/** required arguments after rest */
#define MRB_ARGS_POST(n)    ((mrb_aspec)((n)&0x1f) << 7)

/** keyword arguments (n of keys, kdict) */
#define MRB_ARGS_KEY(n1,n2) ((mrb_aspec)((((n1)&0x1f) << 2) | ((n2)?(1<<1):0)))

/**
 * Function takes a block argument
 */
#define MRB_ARGS_BLOCK()    ((mrb_aspec)1)

/**
 * Function accepts any number of arguments
 */
#define MRB_ARGS_ANY()      MRB_ARGS_REST()

/**
 * Function accepts no arguments
 */
#define MRB_ARGS_NONE()     ((mrb_aspec)0)

/**
 * Format specifiers for {mrb_get_args} function
 *
 * Must be a C string composed of the following format specifiers:
 *
 * | char | Ruby type      | C types           | Notes                                              |
 * |:----:|----------------|-------------------|----------------------------------------------------|
 * | `o`  | {Object}       | {mrb_value}       | Could be used to retrieve any type of argument     |
 * | `C`  | {Class}/{Module} | {mrb_value}     |                                                    |
 * | `S`  | {String}       | {mrb_value}       | when `!` follows, the value may be `nil`           |
 * | `A`  | {Array}        | {mrb_value}       | when `!` follows, the value may be `nil`           |
 * | `H`  | {Hash}         | {mrb_value}       | when `!` follows, the value may be `nil`           |
 * | `s`  | {String}       | char *, {mrb_int} | Receive two arguments; `s!` gives (`NULL`,`0`) for `nil`        |
 * | `z`  | {String}       | char *            | `NULL` terminated string; `z!` gives `NULL` for `nil`           |
 * | `a`  | {Array}        | {mrb_value} *, {mrb_int} | Receive two arguments; `a!` gives (`NULL`,`0`) for `nil` |
 * | `f`  | {Fixnum}/{Float} | {mrb_float}       |                                                    |
 * | `i`  | {Fixnum}/{Float} | {mrb_int}         |                                                    |
 * | `b`  | boolean        | {mrb_bool}        |                                                    |
 * | `n`  | {String}/{Symbol} | {mrb_sym}         |                                                    |
 * | `d`  | data           | void *, {mrb_data_type} const | 2nd argument will be used to check data type so it won't be modified; when `!` follows, the value may be `nil` |
 * | `I`  | inline struct  | void *          |                                                    |
 * | `&`  | block          | {mrb_value}       | &! raises exception if no block given.             |
 * | `*`  | rest arguments | {mrb_value} *, {mrb_int} | Receive the rest of arguments as an array; `*!` avoid copy of the stack.  |
 * | <code>\|</code> | optional     |                   | After this spec following specs would be optional. |
 * | `?`  | optional given | {mrb_bool}        | `TRUE` if preceding argument is given. Used to check optional argument is given. |
 * | `:`  | keyword args   | {mrb_kwargs} const | Get keyword arguments. @see mrb_kwargs |
 *
 * @see mrb_get_args
 */
typedef const char *mrb_args_format;

/**
 * Get keyword arguments by `mrb_get_args()` with `:` specifier.
 *
 * `mrb_kwargs::num` indicates that the number of keyword values.
 *
 * `mrb_kwargs::values` is an object array, and the keyword argument corresponding to the string array is assigned.
 * Note that `undef` is assigned if there is no keyword argument corresponding to `mrb_kwargs::optional`.
 *
 * `mrb_kwargs::table` accepts a string array.
 *
 * `mrb_kwargs::required` indicates that the specified number of keywords starting from the beginning of the string array are required.
 *
 * `mrb_kwargs::rest` is the remaining keyword argument that can be accepted as `**rest` in Ruby.
 * If `NULL` is specified, `ArgumentError` is raised when there is an undefined keyword.
 *
 * Examples:
 *
 *      // def method(a: 1, b: 2)
 *
 *      uint32_t kw_num = 2;
 *      const char *kw_names[kw_num] = { "a", "b" };
 *      uint32_t kw_required = 0;
 *      mrb_value kw_values[kw_num];
 *      const mrb_kwargs kwargs = { kw_num, kw_values, kw_names, kw_required, NULL };
 *
 *      mrb_get_args(mrb, ":", &kwargs);
 *      if (mrb_undef_p(kw_values[0])) { kw_values[0] = mrb_fixnum_value(1); }
 *      if (mrb_undef_p(kw_values[1])) { kw_values[1] = mrb_fixnum_value(2); }
 *
 *
 *      // def method(str, x:, y: 2, z: "default string", **opts)
 *
 *      mrb_value str, kw_rest;
 *      uint32_t kw_num = 3;
 *      const char *kw_names[kw_num] = { "x", "y", "z" };
 *      uint32_t kw_required = 1;
 *      mrb_value kw_values[kw_num];
 *      const mrb_kwargs kwargs = { kw_num, kw_values, kw_names, kw_required, &kw_rest };
 *
 *      mrb_get_args(mrb, "S:", &str, &kwargs);
 *      // or: mrb_get_args(mrb, ":S", &kwargs, &str);
 *      if (mrb_undef_p(kw_values[1])) { kw_values[1] = mrb_fixnum_value(2); }
 *      if (mrb_undef_p(kw_values[2])) { kw_values[2] = mrb_str_new_cstr(mrb, "default string"); }
 */
typedef struct mrb_kwargs mrb_kwargs;

struct mrb_kwargs
{
  uint32_t num;
  mrb_value *values;
  const char *const *table;
  uint32_t required;
  mrb_value *rest;
};

/**
 * Retrieve arguments from mrb_state.
 *
 * @param mrb The current MRuby state.
 * @param format is a list of format specifiers
 * @param ... The passing variadic arguments must be a pointer of retrieving type.
 * @return the number of arguments retrieved.
 * @see mrb_args_format
 * @see mrb_kwargs
 */
MRB_API mrb_int mrb_get_args(mrb_state *mrb, mrb_args_format format, ...);

MRB_INLINE mrb_sym
mrb_get_mid(mrb_state *mrb) /* get method symbol */
{
  return mrb->c->ci->mid;
}

/**
 * Retrieve number of arguments from mrb_state.
 *
 * Correctly handles *splat arguments.
 */
MRB_API mrb_int mrb_get_argc(mrb_state *mrb);

/**
 * Retrieve an array of arguments from mrb_state.
 *
 * Correctly handles *splat arguments.
 */
MRB_API mrb_value* mrb_get_argv(mrb_state *mrb);

/**
 * Retrieve the first and only argument from mrb_state.
 * Raises ArgumentError unless the number of arguments is exactly one.
 *
 * Correctly handles *splat arguments.
 */
MRB_API mrb_value mrb_get_arg1(mrb_state *mrb);

/* `strlen` for character string literals (use with caution or `strlen` instead)
    Adjacent string literals are concatenated in C/C++ in translation phase 6.
    If `lit` is not one, the compiler will report a syntax error:
     MSVC: "error C2143: syntax error : missing ')' before 'string'"
     GCC:  "error: expected ')' before string constant"
*/
#define mrb_strlen_lit(lit) (sizeof(lit "") - 1)

/**
 * Call existing ruby functions.
 *
 * Example:
 *
 *      #include <stdio.h>
 *      #include <mruby.h>
 *      #include "mruby/compile.h"
 *
 *      int
 *      main()
 *      {
 *        mrb_int i = 99;
 *        mrb_state *mrb = mrb_open();
 *
 *        if (!mrb) { }
 *        FILE *fp = fopen("test.rb","r");
 *        mrb_value obj = mrb_load_file(mrb,fp);
 *        mrb_funcall(mrb, obj, "method_name", 1, mrb_fixnum_value(i));
 *        fclose(fp);
 *        mrb_close(mrb);
 *      }
 *
 * @param mrb The current mruby state.
 * @param val A reference to an mruby value.
 * @param name The name of the method.
 * @param argc The number of arguments the method has.
 * @param ... Variadic values(not type safe!).
 * @return [mrb_value] mruby function value.
 */
MRB_API mrb_value mrb_funcall(mrb_state *mrb, mrb_value val, const char *name, mrb_int argc, ...);
/**
 * Call existing ruby functions. This is basically the type safe version of mrb_funcall.
 *
 *      #include <stdio.h>
 *      #include <mruby.h>
 *      #include "mruby/compile.h"
 *      int
 *      main()
 *      {
 *        mrb_int i = 99;
 *        mrb_state *mrb = mrb_open();
 *
 *        if (!mrb) { }
 *        mrb_sym m_sym = mrb_intern_lit(mrb, "method_name"); // Symbol for method.
 *
 *        FILE *fp = fopen("test.rb","r");
 *        mrb_value obj = mrb_load_file(mrb,fp);
 *        mrb_funcall_argv(mrb, obj, m_sym, 1, &obj); // Calling ruby function from test.rb.
 *        fclose(fp);
 *        mrb_close(mrb);
 *       }
 * @param mrb The current mruby state.
 * @param val A reference to an mruby value.
 * @param name_sym The symbol representing the method.
 * @param argc The number of arguments the method has.
 * @param obj Pointer to the object.
 * @return [mrb_value] mrb_value mruby function value.
 * @see mrb_funcall
 */
MRB_API mrb_value mrb_funcall_argv(mrb_state *mrb, mrb_value val, mrb_sym name, mrb_int argc, const mrb_value *argv);
/**
 * Call existing ruby functions with a block.
 */
MRB_API mrb_value mrb_funcall_with_block(mrb_state *mrb, mrb_value val, mrb_sym name, mrb_int argc, const mrb_value *argv, mrb_value block);
/**
 * Create a symbol
 *
 * Example:
 *
 *     # Ruby style:
 *     :pizza # => :pizza
 *
 *     // C style:
 *     mrb_sym m_sym = mrb_intern_lit(mrb, "pizza"); //  => :pizza
 *
 * @param mrb The current mruby state.
 * @param str The string to be symbolized
 * @return [mrb_sym] mrb_sym A symbol.
 */
MRB_API mrb_sym mrb_intern_cstr(mrb_state *mrb, const char* str);
MRB_API mrb_sym mrb_intern(mrb_state*,const char*,size_t);
MRB_API mrb_sym mrb_intern_static(mrb_state*,const char*,size_t);
#define mrb_intern_lit(mrb, lit) mrb_intern_static(mrb, lit, mrb_strlen_lit(lit))
MRB_API mrb_sym mrb_intern_str(mrb_state*,mrb_value);
MRB_API mrb_value mrb_check_intern_cstr(mrb_state*,const char*);
MRB_API mrb_value mrb_check_intern(mrb_state*,const char*,size_t);
MRB_API mrb_value mrb_check_intern_str(mrb_state*,mrb_value);
MRB_API const char *mrb_sym_name(mrb_state*,mrb_sym);
MRB_API const char *mrb_sym_name_len(mrb_state*,mrb_sym,mrb_int*);
MRB_API const char *mrb_sym_dump(mrb_state*,mrb_sym);
MRB_API mrb_value mrb_sym_str(mrb_state*,mrb_sym);
#define mrb_sym2name(mrb,sym) mrb_sym_name(mrb,sym)
#define mrb_sym2name_len(mrb,sym,len) mrb_sym_name_len(mrb,sym,len)
#define mrb_sym2str(mrb,sym) mrb_sym_str(mrb,sym)

MRB_API void *mrb_malloc(mrb_state*, size_t);         /* raise RuntimeError if no mem */
MRB_API void *mrb_calloc(mrb_state*, size_t, size_t); /* ditto */
MRB_API void *mrb_realloc(mrb_state*, void*, size_t); /* ditto */
MRB_API void *mrb_realloc_simple(mrb_state*, void*, size_t); /* return NULL if no memory available */
MRB_API void *mrb_malloc_simple(mrb_state*, size_t);  /* return NULL if no memory available */
MRB_API struct RBasic *mrb_obj_alloc(mrb_state*, enum mrb_vtype, struct RClass*);
MRB_API void mrb_free(mrb_state*, void*);

MRB_API mrb_value mrb_str_new(mrb_state *mrb, const char *p, size_t len);

/**
 * Turns a C string into a Ruby string value.
 */
MRB_API mrb_value mrb_str_new_cstr(mrb_state*, const char*);
MRB_API mrb_value mrb_str_new_static(mrb_state *mrb, const char *p, size_t len);
#define mrb_str_new_lit(mrb, lit) mrb_str_new_static(mrb, (lit), mrb_strlen_lit(lit))

MRB_API mrb_value mrb_obj_freeze(mrb_state*, mrb_value);
#define mrb_str_new_frozen(mrb,p,len) mrb_obj_freeze(mrb,mrb_str_new(mrb,p,len))
#define mrb_str_new_cstr_frozen(mrb,p) mrb_obj_freeze(mrb,mrb_str_new_cstr(mrb,p))
#define mrb_str_new_static_frozen(mrb,p,len) mrb_obj_freeze(mrb,mrb_str_new_static(mrb,p,len))
#define mrb_str_new_lit_frozen(mrb,lit) mrb_obj_freeze(mrb,mrb_str_new_lit(mrb,lit))

#ifdef _WIN32
MRB_API char* mrb_utf8_from_locale(const char *p, int len);
MRB_API char* mrb_locale_from_utf8(const char *p, int len);
#define mrb_locale_free(p) free(p)
#define mrb_utf8_free(p) free(p)
#else
#define mrb_utf8_from_locale(p, l) ((char*)(p))
#define mrb_locale_from_utf8(p, l) ((char*)(p))
#define mrb_locale_free(p)
#define mrb_utf8_free(p)
#endif

/**
 * Creates new mrb_state.
 *
 * @return
 *      Pointer to the newly created mrb_state.
 */
MRB_API mrb_state* mrb_open(void);

/**
 * Create new mrb_state with custom allocators.
 *
 * @param f
 *      Reference to the allocation function.
 * @param ud
 *      User data will be passed to custom allocator f.
 *      If user data isn't required just pass NULL.
 * @return
 *      Pointer to the newly created mrb_state.
 */
MRB_API mrb_state* mrb_open_allocf(mrb_allocf f, void *ud);

/**
 * Create new mrb_state with just the MRuby core
 *
 * @param f
 *      Reference to the allocation function.
 *      Use mrb_default_allocf for the default
 * @param ud
 *      User data will be passed to custom allocator f.
 *      If user data isn't required just pass NULL.
 * @return
 *      Pointer to the newly created mrb_state.
 */
MRB_API mrb_state* mrb_open_core(mrb_allocf f, void *ud);

/**
 * Closes and frees a mrb_state.
 *
 * @param mrb
 *      Pointer to the mrb_state to be closed.
 */
MRB_API void mrb_close(mrb_state *mrb);

/**
 * The default allocation function.
 *
 * @see mrb_allocf
 */
MRB_API void* mrb_default_allocf(mrb_state*, void*, size_t, void*);

MRB_API mrb_value mrb_top_self(mrb_state *mrb);
MRB_API mrb_value mrb_top_run(mrb_state *mrb, struct RProc *proc, mrb_value self, unsigned int stack_keep);
MRB_API mrb_value mrb_vm_run(mrb_state *mrb, struct RProc *proc, mrb_value self, unsigned int stack_keep);
MRB_API mrb_value mrb_vm_exec(mrb_state *mrb, struct RProc *proc, const mrb_code *iseq);
/* compatibility macros */
#define mrb_toplevel_run_keep(m,p,k) mrb_top_run((m),(p),mrb_top_self(m),(k))
#define mrb_toplevel_run(m,p) mrb_toplevel_run_keep((m),(p),0)
#define mrb_context_run(m,p,s,k) mrb_vm_run((m),(p),(s),(k))

MRB_API void mrb_p(mrb_state*, mrb_value);
MRB_API mrb_int mrb_obj_id(mrb_value obj);
MRB_API mrb_sym mrb_obj_to_sym(mrb_state *mrb, mrb_value name);

MRB_API mrb_bool mrb_obj_eq(mrb_state *mrb, mrb_value a, mrb_value b);
MRB_API mrb_bool mrb_obj_equal(mrb_state *mrb, mrb_value a, mrb_value b);
MRB_API mrb_bool mrb_equal(mrb_state *mrb, mrb_value obj1, mrb_value obj2);
MRB_API mrb_value mrb_convert_to_integer(mrb_state *mrb, mrb_value val, mrb_int base);
MRB_API mrb_value mrb_Integer(mrb_state *mrb, mrb_value val);
#ifndef MRB_WITHOUT_FLOAT
MRB_API mrb_value mrb_Float(mrb_state *mrb, mrb_value val);
#endif
MRB_API mrb_value mrb_inspect(mrb_state *mrb, mrb_value obj);
MRB_API mrb_bool mrb_eql(mrb_state *mrb, mrb_value obj1, mrb_value obj2);
/* mrb_cmp(mrb, obj1, obj2): 1:0:-1; -2 for error */
MRB_API mrb_int mrb_cmp(mrb_state *mrb, mrb_value obj1, mrb_value obj2);

MRB_INLINE int
mrb_gc_arena_save(mrb_state *mrb)
{
  return mrb->gc.arena_idx;
}

MRB_INLINE void
mrb_gc_arena_restore(mrb_state *mrb, int idx)
{
  mrb->gc.arena_idx = idx;
}

MRB_API void mrb_garbage_collect(mrb_state*);
MRB_API void mrb_full_gc(mrb_state*);
MRB_API void mrb_incremental_gc(mrb_state *);
MRB_API void mrb_gc_mark(mrb_state*,struct RBasic*);
#define mrb_gc_mark_value(mrb,val) do {\
  if (!mrb_immediate_p(val)) mrb_gc_mark((mrb), mrb_basic_ptr(val)); \
} while (0)
MRB_API void mrb_field_write_barrier(mrb_state *, struct RBasic*, struct RBasic*);
#define mrb_field_write_barrier_value(mrb, obj, val) do{\
  if (!mrb_immediate_p(val)) mrb_field_write_barrier((mrb), (obj), mrb_basic_ptr(val)); \
} while (0)
MRB_API void mrb_write_barrier(mrb_state *, struct RBasic*);

MRB_API mrb_value mrb_check_convert_type(mrb_state *mrb, mrb_value val, enum mrb_vtype type, const char *tname, const char *method);
MRB_API mrb_value mrb_any_to_s(mrb_state *mrb, mrb_value obj);
MRB_API const char * mrb_obj_classname(mrb_state *mrb, mrb_value obj);
MRB_API struct RClass* mrb_obj_class(mrb_state *mrb, mrb_value obj);
MRB_API mrb_value mrb_class_path(mrb_state *mrb, struct RClass *c);
MRB_API mrb_value mrb_convert_type(mrb_state *mrb, mrb_value val, enum mrb_vtype type, const char *tname, const char *method);
MRB_API mrb_bool mrb_obj_is_kind_of(mrb_state *mrb, mrb_value obj, struct RClass *c);
MRB_API mrb_value mrb_obj_inspect(mrb_state *mrb, mrb_value self);
MRB_API mrb_value mrb_obj_clone(mrb_state *mrb, mrb_value self);

#ifndef ISPRINT
#define ISASCII(c) ((unsigned)(c) <= 0x7f)
#define ISPRINT(c) (((unsigned)(c) - 0x20) < 0x5f)
#define ISSPACE(c) ((c) == ' ' || (unsigned)(c) - '\t' < 5)
#define ISUPPER(c) (((unsigned)(c) - 'A') < 26)
#define ISLOWER(c) (((unsigned)(c) - 'a') < 26)
#define ISALPHA(c) ((((unsigned)(c) | 0x20) - 'a') < 26)
#define ISDIGIT(c) (((unsigned)(c) - '0') < 10)
#define ISXDIGIT(c) (ISDIGIT(c) || ((unsigned)(c) | 0x20) - 'a' < 6)
#define ISALNUM(c) (ISALPHA(c) || ISDIGIT(c))
#define ISBLANK(c) ((c) == ' ' || (c) == '\t')
#define ISCNTRL(c) ((unsigned)(c) < 0x20 || (c) == 0x7f)
#define TOUPPER(c) (ISLOWER(c) ? ((c) & 0x5f) : (c))
#define TOLOWER(c) (ISUPPER(c) ? ((c) | 0x20) : (c))
#endif

MRB_API mrb_value mrb_exc_new(mrb_state *mrb, struct RClass *c, const char *ptr, size_t len);
MRB_API mrb_noreturn void mrb_exc_raise(mrb_state *mrb, mrb_value exc);

MRB_API mrb_noreturn void mrb_raise(mrb_state *mrb, struct RClass *c, const char *msg);
MRB_API mrb_noreturn void mrb_raisef(mrb_state *mrb, struct RClass *c, const char *fmt, ...);
MRB_API mrb_noreturn void mrb_name_error(mrb_state *mrb, mrb_sym id, const char *fmt, ...);
MRB_API mrb_noreturn void mrb_frozen_error(mrb_state *mrb, void *frozen_obj);
MRB_API mrb_noreturn void mrb_argnum_error(mrb_state *mrb, mrb_int argc, int min, int max);
MRB_API void mrb_warn(mrb_state *mrb, const char *fmt, ...);
MRB_API mrb_noreturn void mrb_bug(mrb_state *mrb, const char *fmt, ...);
MRB_API void mrb_print_backtrace(mrb_state *mrb);
MRB_API void mrb_print_error(mrb_state *mrb);
/* function for `raisef` formatting */
MRB_API mrb_value mrb_vformat(mrb_state *mrb, const char *format, va_list ap);

/* macros to get typical exception objects
   note:
   + those E_* macros requires mrb_state* variable named mrb.
   + exception objects obtained from those macros are local to mrb
*/
#define E_RUNTIME_ERROR             (mrb_exc_get(mrb, "RuntimeError"))
#define E_TYPE_ERROR                (mrb_exc_get(mrb, "TypeError"))
#define E_ARGUMENT_ERROR            (mrb_exc_get(mrb, "ArgumentError"))
#define E_INDEX_ERROR               (mrb_exc_get(mrb, "IndexError"))
#define E_RANGE_ERROR               (mrb_exc_get(mrb, "RangeError"))
#define E_NAME_ERROR                (mrb_exc_get(mrb, "NameError"))
#define E_NOMETHOD_ERROR            (mrb_exc_get(mrb, "NoMethodError"))
#define E_SCRIPT_ERROR              (mrb_exc_get(mrb, "ScriptError"))
#define E_SYNTAX_ERROR              (mrb_exc_get(mrb, "SyntaxError"))
#define E_LOCALJUMP_ERROR           (mrb_exc_get(mrb, "LocalJumpError"))
#define E_REGEXP_ERROR              (mrb_exc_get(mrb, "RegexpError"))
#define E_FROZEN_ERROR              (mrb_exc_get(mrb, "FrozenError"))

#define E_NOTIMP_ERROR              (mrb_exc_get(mrb, "NotImplementedError"))
#ifndef MRB_WITHOUT_FLOAT
#define E_FLOATDOMAIN_ERROR         (mrb_exc_get(mrb, "FloatDomainError"))
#endif

#define E_KEY_ERROR                 (mrb_exc_get(mrb, "KeyError"))

MRB_API mrb_value mrb_yield(mrb_state *mrb, mrb_value b, mrb_value arg);
MRB_API mrb_value mrb_yield_argv(mrb_state *mrb, mrb_value b, mrb_int argc, const mrb_value *argv);
MRB_API mrb_value mrb_yield_with_class(mrb_state *mrb, mrb_value b, mrb_int argc, const mrb_value *argv, mrb_value self, struct RClass *c);

/* continue execution to the proc */
/* this function should always be called as the last function of a method */
/* e.g. return mrb_yield_cont(mrb, proc, self, argc, argv); */
mrb_value mrb_yield_cont(mrb_state *mrb, mrb_value b, mrb_value self, mrb_int argc, const mrb_value *argv);

/* mrb_gc_protect() leaves the object in the arena */
MRB_API void mrb_gc_protect(mrb_state *mrb, mrb_value obj);
/* mrb_gc_register() keeps the object from GC. */
MRB_API void mrb_gc_register(mrb_state *mrb, mrb_value obj);
/* mrb_gc_unregister() removes the object from GC root. */
MRB_API void mrb_gc_unregister(mrb_state *mrb, mrb_value obj);

MRB_API mrb_value mrb_to_int(mrb_state *mrb, mrb_value val);
#define mrb_int(mrb, val) mrb_fixnum(mrb_to_int(mrb, val))
/* string type checking (contrary to the name, it doesn't convert) */
MRB_API mrb_value mrb_to_str(mrb_state *mrb, mrb_value val);
MRB_API void mrb_check_type(mrb_state *mrb, mrb_value x, enum mrb_vtype t);

MRB_INLINE void mrb_check_frozen(mrb_state *mrb, void *o)
{
  if (mrb_frozen_p((struct RBasic*)o)) mrb_frozen_error(mrb, o);
}

typedef enum call_type {
  CALL_PUBLIC,
  CALL_FCALL,
  CALL_VCALL,
  CALL_TYPE_MAX
} call_type;

MRB_API void mrb_define_alias(mrb_state *mrb, struct RClass *c, const char *a, const char *b);
MRB_API const char *mrb_class_name(mrb_state *mrb, struct RClass* klass);
MRB_API void mrb_define_global_const(mrb_state *mrb, const char *name, mrb_value val);

MRB_API mrb_value mrb_attr_get(mrb_state *mrb, mrb_value obj, mrb_sym id);

MRB_API mrb_bool mrb_respond_to(mrb_state *mrb, mrb_value obj, mrb_sym mid);
MRB_API mrb_bool mrb_obj_is_instance_of(mrb_state *mrb, mrb_value obj, struct RClass* c);
MRB_API mrb_bool mrb_func_basic_p(mrb_state *mrb, mrb_value obj, mrb_sym mid, mrb_func_t func);


/**
 * Resume a Fiber
 *
 * Implemented in mruby-fiber
 */
MRB_API mrb_value mrb_fiber_resume(mrb_state *mrb, mrb_value fib, mrb_int argc, const mrb_value *argv);

/**
 * Yield a Fiber
 *
 * Implemented in mruby-fiber
 */
MRB_API mrb_value mrb_fiber_yield(mrb_state *mrb, mrb_int argc, const mrb_value *argv);

/**
 * Check if a Fiber is alive
 *
 * Implemented in mruby-fiber
 */
MRB_API mrb_value mrb_fiber_alive_p(mrb_state *mrb, mrb_value fib);

/**
 * FiberError reference
 *
 * Implemented in mruby-fiber
 */
#define E_FIBER_ERROR (mrb_exc_get(mrb, "FiberError"))
MRB_API void mrb_stack_extend(mrb_state*, mrb_int);

/* memory pool implementation */
typedef struct mrb_pool mrb_pool;
MRB_API struct mrb_pool* mrb_pool_open(mrb_state*);
MRB_API void mrb_pool_close(struct mrb_pool*);
MRB_API void* mrb_pool_alloc(struct mrb_pool*, size_t);
MRB_API void* mrb_pool_realloc(struct mrb_pool*, void*, size_t oldlen, size_t newlen);
MRB_API mrb_bool mrb_pool_can_realloc(struct mrb_pool*, void*, size_t);
/* temporary memory allocation, only effective while GC arena is kept */
MRB_API void* mrb_alloca(mrb_state *mrb, size_t);

MRB_API void mrb_state_atexit(mrb_state *mrb, mrb_atexit_func func);

MRB_API void mrb_show_version(mrb_state *mrb);
MRB_API void mrb_show_copyright(mrb_state *mrb);

MRB_API mrb_value mrb_format(mrb_state *mrb, const char *format, ...);

#if 0
/* memcpy and memset does not work with gdb reverse-next on my box */
/* use naive memcpy and memset instead */
#undef memcpy
#undef memset
static void*
mrbmemcpy(void *dst, const void *src, size_t n)
{
  char *d = (char*)dst;
  const char *s = (const char*)src;
  while (n--)
    *d++ = *s++;
  return d;
}
#define memcpy(a,b,c) mrbmemcpy(a,b,c)

static void*
mrbmemset(void *s, int c, size_t n)
{
  char *t = (char*)s;
  while (n--)
    *t++ = c;
  return s;
}
#define memset(a,b,c) mrbmemset(a,b,c)
#endif

MRB_END_DECL

#endif  /* MRUBY_H */
