/*
** mruby - An embeddable Ruby implementation
**
** Copyright (c) mruby developers 2010-2021
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
** [ MIT license: https://www.opensource.org/licenses/mit-license.php ]
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
#ifndef UINTPTR_MAX
#error Must be placed `#include <mruby.h>` before `#include <stdint.h>`
#endif
#ifndef SIZE_MAX
#ifdef __SIZE_MAX__
#define SIZE_MAX __SIZE_MAX__
#else
#define SIZE_MAX std::numeric_limits<size_t>::max()
#endif
#endif
#endif

#ifdef _MSC_VER
# define __func__ __FUNCTION__
#endif

#ifdef MRB_DEBUG
#include <assert.h>
#define mrb_assert(p) assert(p)
#define mrb_assert_int_fit(t1,n,t2,max) assert((n)>=0 && ((sizeof(n)<=sizeof(t2))||(n<=(t1)(max))))
#else
#define mrb_assert(p) ((void)0)
#define mrb_assert_int_fit(t1,n,t2,max) ((void)0)
#endif

#if (defined __cplusplus && __cplusplus >= 201703L)
# define mrb_static_assert(...) static_assert(__VA_ARGS__)
# define mrb_static_assert1(exp) static_assert(exp)
# define mrb_static_assert2(exp, str) static_assert(exp, str)
#elif (defined __cplusplus && __cplusplus >= 201103L) || \
    (defined _MSC_VER) || \
    (defined __GXX_EXPERIMENTAL_CXX0X__)  /* for old G++/Clang++ */
# define mrb_static_assert2(exp, str) static_assert(exp, str)
#elif defined __STDC_VERSION__ && \
        ((__STDC_VERSION__ >= 201112L) || \
         (defined __GNUC__ && __GNUC__ * 100 + __GNUC_MINOR__ >= 406))
# define mrb_static_assert2(exp, str) _Static_assert(exp, str)
#else
# /* alternative implementation of static_assert() */
# define _mrb_static_assert_cat0(a, b) a##b
# define _mrb_static_assert_cat(a, b) _mrb_static_assert_cat0(a, b)
# ifdef __COUNTER__
#  define _mrb_static_assert_id(prefix) _mrb_static_assert_cat(prefix, __COUNTER__)
# else
#  define _mrb_static_assert_id(prefix) _mrb_static_assert_cat(prefix, __LINE__)
# endif
# define mrb_static_assert2(exp, str) \
   struct _mrb_static_assert_id(_mrb_static_assert_) { char x[(exp) ? 1 : -1]; }
#endif

#ifndef mrb_static_assert
# define mrb_static_assert1(exp) mrb_static_assert2(exp, #exp)
# define mrb_static_assert_expand(...) __VA_ARGS__ /* for MSVC behaviour - https://stackoverflow.com/q/5530505 */
# define mrb_static_assert_selector(a, b, name, ...) name
/**
 * The `mrb_static_assert()` macro function takes one or two arguments.
 *
 *      !!!c
 *      mrb_static_assert(expect_condition);
 *      mrb_static_assert(expect_condition, error_message);
 */
# define mrb_static_assert(...) \
    mrb_static_assert_expand(mrb_static_assert_selector(__VA_ARGS__, mrb_static_assert2, mrb_static_assert1, _)(__VA_ARGS__))
#endif

#define mrb_static_assert_powerof2(num) mrb_static_assert((num) > 0 && (num) == ((num) & -(num)), "need power of 2 for " #num)

#include "mrbconf.h"

#include <mruby/common.h>
#include <mruby/value.h>
#include <mruby/gc.h>
#include <mruby/version.h>

#ifndef MRB_NO_FLOAT
#include <math.h>
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

#ifdef MRB_USE_FLOAT32
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
  uint8_t n:4;                  /* (15=*) c=n|nk<<4 */
  uint8_t nk:4;                 /* (15=*) */
  uint8_t cci;                  /* called from C function */
  mrb_sym mid;
  const struct RProc *proc;
  mrb_value *stack;
  const mrb_code *pc;           /* current address on iseq of this proc */
  union {
    struct REnv *env;
    struct RClass *target_class;
  } u;
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

  mrb_value *stbase, *stend;              /* stack of virtual machine */

  mrb_callinfo *ci;
  mrb_callinfo *cibase, *ciend;

  enum mrb_fiber_state status : 4;
  mrb_bool vmexec : 1;
  struct RFiber *fib;
};

#ifdef MRB_METHOD_CACHE_SIZE
# undef MRB_NO_METHOD_CACHE
mrb_static_assert_powerof2(MRB_METHOD_CACHE_SIZE);
#else
/* default method cache size: 256 */
/* cache size needs to be power of 2 */
# define MRB_METHOD_CACHE_SIZE (1<<8)
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

#ifndef MRB_USE_METHOD_T_STRUCT
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

#ifndef MRB_NO_METHOD_CACHE
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

#ifndef MRB_NO_FLOAT
  struct RClass *float_class;
#endif
  struct RClass *integer_class;
  struct RClass *true_class;
  struct RClass *false_class;
  struct RClass *nil_class;
  struct RClass *symbol_class;
  struct RClass *kernel_module;

  mrb_gc gc;

#ifndef MRB_NO_METHOD_CACHE
  struct mrb_cache_entry cache[MRB_METHOD_CACHE_SIZE];
#endif

  mrb_sym symidx;
  const char **symtbl;
  uint8_t *symlink;
  uint8_t *symflags;
  mrb_sym symhash[256];
  size_t symcapa;
#ifndef MRB_USE_ALL_SYMBOLS
  char symbuf[8];               /* buffer for small symbol names */
#endif

#ifdef MRB_USE_DEBUG_HOOK
  void (*code_fetch_hook)(struct mrb_state* mrb, const struct mrb_irep *irep, const mrb_code *pc, mrb_value *regs);
  void (*debug_op_hook)(struct mrb_state* mrb, const struct mrb_irep *irep, const mrb_code *pc, mrb_value *regs);
#endif

#ifdef MRB_BYTECODE_DECODE_OPTION
  mrb_code (*bytecode_decoder)(struct mrb_state* mrb, mrb_code code);
#endif

  struct RClass *eException_class;
  struct RClass *eStandardError_class;
  struct RObject *nomem_err;              /* pre-allocated NoMemoryError */
  struct RObject *stack_err;              /* pre-allocated SysStackError */
#ifdef MRB_GC_FIXED_ARENA
  struct RObject *arena_err;              /* pre-allocated arena overflow error */
#endif

  void *ud; /* auxiliary data */

#ifdef MRB_FIXED_STATE_ATEXIT_STACK
  mrb_atexit_func atexit_stack[MRB_FIXED_STATE_ATEXIT_STACK_SIZE];
#else
  mrb_atexit_func *atexit_stack;
#endif
  uint16_t atexit_stack_len;
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
MRB_API struct RClass *mrb_define_class_id(mrb_state *mrb, mrb_sym name, struct RClass *super);

/**
 * Defines a new module.
 *
 * @param mrb The current mruby state.
 * @param name The name of the module.
 * @return [struct RClass *] Reference to the newly defined module.
 */
MRB_API struct RClass *mrb_define_module(mrb_state *mrb, const char *name);
MRB_API struct RClass *mrb_define_module_id(mrb_state *mrb, mrb_sym name);

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
MRB_API void mrb_define_method_id(mrb_state *mrb, struct RClass *c, mrb_sym mid, mrb_func_t func, mrb_aspec aspec);

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
MRB_API void mrb_define_class_method_id(mrb_state *mrb, struct RClass *cla, mrb_sym name, mrb_func_t fun, mrb_aspec aspec);

/**
 * Defines a singleton method
 *
 * @see mrb_define_class_method
 */
MRB_API void mrb_define_singleton_method(mrb_state *mrb, struct RObject *cla, const char *name, mrb_func_t fun, mrb_aspec aspec);
MRB_API void mrb_define_singleton_method_id(mrb_state *mrb, struct RObject *cla, mrb_sym name, mrb_func_t fun, mrb_aspec aspec);

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
MRB_API void mrb_define_module_function_id(mrb_state *mrb, struct RClass *cla, mrb_sym name, mrb_func_t fun, mrb_aspec aspec);

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
MRB_API void mrb_define_const_id(mrb_state* mrb, struct RClass* cla, mrb_sym name, mrb_value val);

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
MRB_API void mrb_undef_class_method_id(mrb_state *mrb, struct RClass *cls, mrb_sym name);

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
MRB_API mrb_bool mrb_class_defined_id(mrb_state *mrb, mrb_sym name);

/**
 * Gets a class.
 * @param mrb The current mruby state.
 * @param name The name of the class.
 * @return [struct RClass *] A reference to the class.
*/
MRB_API struct RClass* mrb_class_get(mrb_state *mrb, const char *name);
MRB_API struct RClass* mrb_class_get_id(mrb_state *mrb, mrb_sym name);

/**
 * Gets a exception class.
 * @param mrb The current mruby state.
 * @param name The name of the class.
 * @return [struct RClass *] A reference to the class.
*/
MRB_API struct RClass* mrb_exc_get_id(mrb_state *mrb, mrb_sym name);
#define mrb_exc_get(mrb, name) mrb_exc_get_id(mrb, mrb_intern_cstr(mrb, name))

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
MRB_API mrb_bool mrb_class_defined_under_id(mrb_state *mrb, struct RClass *outer, mrb_sym name);

/**
 * Gets a child class.
 * @param mrb The current mruby state.
 * @param outer The name of the parent class.
 * @param name The name of the class.
 * @return [struct RClass *] A reference to the class.
*/
MRB_API struct RClass * mrb_class_get_under(mrb_state *mrb, struct RClass *outer, const char *name);
MRB_API struct RClass * mrb_class_get_under_id(mrb_state *mrb, struct RClass *outer, mrb_sym name);

/**
 * Gets a module.
 * @param mrb The current mruby state.
 * @param name The name of the module.
 * @return [struct RClass *] A reference to the module.
*/
MRB_API struct RClass * mrb_module_get(mrb_state *mrb, const char *name);
MRB_API struct RClass * mrb_module_get_id(mrb_state *mrb, mrb_sym name);

/**
 * Gets a module defined under another module.
 * @param mrb The current mruby state.
 * @param outer The name of the outer module.
 * @param name The name of the module.
 * @return [struct RClass *] A reference to the module.
*/
MRB_API struct RClass * mrb_module_get_under(mrb_state *mrb, struct RClass *outer, const char *name);
MRB_API struct RClass * mrb_module_get_under_id(mrb_state *mrb, struct RClass *outer, mrb_sym name);

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
MRB_API struct RClass* mrb_define_class_under(mrb_state *mrb, struct RClass *outer, const char *name, struct RClass *super);
MRB_API struct RClass* mrb_define_class_under_id(mrb_state *mrb, struct RClass *outer, mrb_sym name, struct RClass *super);

MRB_API struct RClass* mrb_define_module_under(mrb_state *mrb, struct RClass *outer, const char *name);
MRB_API struct RClass* mrb_define_module_under_id(mrb_state *mrb, struct RClass *outer, mrb_sym name);

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
 * | `C`  | {Class}/{Module} | {mrb_value}     | when `!` follows, the value may be `nil`           |
 * | `S`  | {String}       | {mrb_value}       | when `!` follows, the value may be `nil`           |
 * | `A`  | {Array}        | {mrb_value}       | when `!` follows, the value may be `nil`           |
 * | `H`  | {Hash}         | {mrb_value}       | when `!` follows, the value may be `nil`           |
 * | `s`  | {String}       | const char *, {mrb_int} | Receive two arguments; `s!` gives (`NULL`,`0`) for `nil` |
 * | `z`  | {String}       | const char *      | `NULL` terminated string; `z!` gives `NULL` for `nil` |
 * | `a`  | {Array}        | const {mrb_value} *, {mrb_int} | Receive two arguments; `a!` gives (`NULL`,`0`) for `nil` |
 * | `c`  | {Class}/{Module} | strcut RClass * | `c!` gives `NULL` for `nil`                        |
 * | `f`  | {Integer}/{Float} | {mrb_float}    |                                                    |
 * | `i`  | {Integer}/{Float} | {mrb_int}      |                                                    |
 * | `b`  | boolean        | {mrb_bool}        |                                                    |
 * | `n`  | {String}/{Symbol} | {mrb_sym}         |                                                    |
 * | `d`  | data           | void *, {mrb_data_type} const | 2nd argument will be used to check data type so it won't be modified; when `!` follows, the value may be `nil` |
 * | `I`  | inline struct  | void *, struct RClass | `I!` gives `NULL` for `nil`                    |
 * | `&`  | block          | {mrb_value}       | &! raises exception if no block given.             |
 * | `*`  | rest arguments | const {mrb_value} *, {mrb_int} | Receive the rest of arguments as an array; `*!` avoid copy of the stack.  |
 * | <code>\|</code> | optional     |                   | After this spec following specs would be optional. |
 * | `?`  | optional given | {mrb_bool}        | `TRUE` if preceding argument is given. Used to check optional argument is given. |
 * | `:`  | keyword args   | {mrb_kwargs} const | Get keyword arguments. @see mrb_kwargs |
 *
 * @see mrb_get_args
 *
 * Immediately after format specifiers it can add format modifiers:
 *
 * | char | Notes                                                                                   |
 * |:----:|-----------------------------------------------------------------------------------------|
 * | `!`  | Switch to the alternate mode; The behaviour changes depending on the format specifier   |
 * | `+`  | Request a not frozen object; However, except nil value                                  |
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
 *      const mrb_kwargs kwargs = { kw_num, kw_required, kw_names, kw_values, NULL };
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
 *      const mrb_sym kw_names[kw_num] = { MRB_SYM(x), MRB_SYM(y), MRB_SYM(z) };
 *      uint32_t kw_required = 1;
 *      mrb_value kw_values[kw_num];
 *      const mrb_kwargs kwargs = { kw_num, kw_required, kw_names, kw_values, &kw_rest };
 *
 *      mrb_get_args(mrb, "S:", &str, &kwargs);
 *      // or: mrb_get_args(mrb, ":S", &kwargs, &str);
 *      if (mrb_undef_p(kw_values[1])) { kw_values[1] = mrb_fixnum_value(2); }
 *      if (mrb_undef_p(kw_values[2])) { kw_values[2] = mrb_str_new_cstr(mrb, "default string"); }
 */
typedef struct mrb_kwargs mrb_kwargs;

struct mrb_kwargs
{
  uint32_t num;                 /* number of keyword arguments */
  uint32_t required;            /* number of required keyword arguments */
  const mrb_sym *table;         /* C array of symbols for keyword names */
  mrb_value *values;            /* keyword argument values */
  mrb_value *rest;              /* keyword rest (dict) */
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
MRB_API const mrb_value *mrb_get_argv(mrb_state *mrb);

/**
 * Retrieve the first and only argument from mrb_state.
 * Raises ArgumentError unless the number of arguments is exactly one.
 *
 * Correctly handles *splat arguments.
 */
MRB_API mrb_value mrb_get_arg1(mrb_state *mrb);

/**
 * Check if a block argument is given from mrb_state.
 */
MRB_API mrb_bool mrb_block_given_p(mrb_state *mrb);

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
 *        mrb_funcall_id(mrb, obj, MRB_SYM(method_name), 1, mrb_fixnum_value(i));
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
MRB_API mrb_value mrb_funcall_id(mrb_state *mrb, mrb_value val, mrb_sym mid, mrb_int argc, ...);
/**
 * Call existing ruby functions. This is basically the type safe version of mrb_funcall.
 *
 *      #include <stdio.h>
 *      #include <mruby.h>
 *      #include "mruby/compile.h"
 *      int
 *      main()
 *      {
 *        mrb_state *mrb = mrb_open();
 *        mrb_value obj = mrb_fixnum_value(1);
 *
 *        if (!mrb) { }
 *
 *        FILE *fp = fopen("test.rb","r");
 *        mrb_value obj = mrb_load_file(mrb,fp);
 *        mrb_funcall_argv(mrb, obj, MRB_SYM(method_name), 1, &obj); // Calling ruby function from test.rb.
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
 * Create a symbol from C string. But usually it's better to use MRB_SYM,
 * MRB_OPSYM, MRB_CVSYM, MRB_IVSYM, MRB_SYM_B, MRB_SYM_Q, MRB_SYM_E macros.
 *
 * Example:
 *
 *     # Ruby style:
 *     :pizza # => :pizza
 *
 *     // C style:
 *     mrb_sym sym1 = mrb_intern_lit(mrb, "pizza"); //  => :pizza
 *     mrb_sym sym2 = MRB_SYM(pizza);               //  => :pizza
 *     mrb_sym sym3 = MRB_SYM_Q(pizza);             //  => :pizza?
 *
 * @param mrb The current mruby state.
 * @param str The string to be symbolized
 * @return [mrb_sym] mrb_sym A symbol.
 */
MRB_API mrb_sym mrb_intern_cstr(mrb_state *mrb, const char* str);
MRB_API mrb_sym mrb_intern(mrb_state*,const char*,size_t);
MRB_API mrb_sym mrb_intern_static(mrb_state*,const char*,size_t);
#define mrb_intern_lit(mrb, lit) mrb_intern_static(mrb, (lit ""), mrb_strlen_lit(lit))
MRB_API mrb_sym mrb_intern_str(mrb_state*,mrb_value);
/* mrb_intern_check series functions returns 0 if the symbol is not defined */
MRB_API mrb_sym mrb_intern_check_cstr(mrb_state*,const char*);
MRB_API mrb_sym mrb_intern_check(mrb_state*,const char*,size_t);
MRB_API mrb_sym mrb_intern_check_str(mrb_state*,mrb_value);
/* mrb_check_intern series functions returns nil if the symbol is not defined */
/* otherwise returns mrb_value */
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

/**
 * Allocates a Ruby object that matches the constant literal defined in
 * `enum mrb_vtype` and returns a pointer to the corresponding C type.
 *
 * @param mrb   The current mruby state
 * @param tt    The constant literal of `enum mrb_vtype`
 * @param klass A Class object
 * @return      Reference to the newly created object
 */
#define MRB_OBJ_ALLOC(mrb, tt, klass) ((MRB_VTYPE_TYPEOF(tt)*)mrb_obj_alloc(mrb, tt, klass))

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
MRB_API mrb_value mrb_top_run(mrb_state *mrb, const struct RProc *proc, mrb_value self, mrb_int stack_keep);
MRB_API mrb_value mrb_vm_run(mrb_state *mrb, const struct RProc *proc, mrb_value self, mrb_int stack_keep);
MRB_API mrb_value mrb_vm_exec(mrb_state *mrb, const struct RProc *proc, const mrb_code *iseq);
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
#ifndef MRB_NO_FLOAT
MRB_API mrb_value mrb_ensure_float_type(mrb_state *mrb, mrb_value val);
#define mrb_as_float(mrb, x) mrb_float(mrb_ensure_float_type(mrb, x))
/* obsolete: use mrb_ensure_float_type() instead */
#define mrb_to_float(mrb, val) mrb_ensure_float_type(mrb, val)
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

MRB_API mrb_value mrb_type_convert(mrb_state *mrb, mrb_value val, enum mrb_vtype type, mrb_sym method);
#define mrb_convert_type(mrb, val, type, tname, method) mrb_type_convert(mrb, val, type, mrb_intern_lit(mrb, method))
MRB_API mrb_value mrb_type_convert_check(mrb_state *mrb, mrb_value val, enum mrb_vtype type, mrb_sym method);
#define mrb_check_convert_type(mrb, val, type, tname, method) mrb_type_convert_check(mrb, val, type, mrb_intern_lit(mrb, method))

MRB_API mrb_value mrb_any_to_s(mrb_state *mrb, mrb_value obj);
MRB_API const char * mrb_obj_classname(mrb_state *mrb, mrb_value obj);
MRB_API struct RClass* mrb_obj_class(mrb_state *mrb, mrb_value obj);
MRB_API mrb_value mrb_class_path(mrb_state *mrb, struct RClass *c);
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
#define MRB_ERROR_SYM(sym) mrb_intern_lit(mrb, #sym)
#define E_RUNTIME_ERROR      mrb_exc_get_id(mrb, MRB_ERROR_SYM(RuntimeError))
#define E_TYPE_ERROR         mrb_exc_get_id(mrb, MRB_ERROR_SYM(TypeError))
#define E_ZERODIV_ERROR      mrb_exc_get_id(mrb, MRB_ERROR_SYM(ZeroDivisionError))
#define E_ARGUMENT_ERROR     mrb_exc_get_id(mrb, MRB_ERROR_SYM(ArgumentError))
#define E_INDEX_ERROR        mrb_exc_get_id(mrb, MRB_ERROR_SYM(IndexError))
#define E_RANGE_ERROR        mrb_exc_get_id(mrb, MRB_ERROR_SYM(RangeError))
#define E_NAME_ERROR         mrb_exc_get_id(mrb, MRB_ERROR_SYM(NameError))
#define E_NOMETHOD_ERROR     mrb_exc_get_id(mrb, MRB_ERROR_SYM(NoMethodError))
#define E_SCRIPT_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(ScriptError))
#define E_SYNTAX_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(SyntaxError))
#define E_LOCALJUMP_ERROR    mrb_exc_get_id(mrb, MRB_ERROR_SYM(LocalJumpError))
#define E_REGEXP_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(RegexpError))
#define E_FROZEN_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(FrozenError))
#define E_NOTIMP_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(NotImplementedError))
#define E_KEY_ERROR          mrb_exc_get_id(mrb, MRB_ERROR_SYM(KeyError))
#ifndef MRB_NO_FLOAT
# define E_FLOATDOMAIN_ERROR mrb_exc_get_id(mrb, MRB_ERROR_SYM(FloatDomainError))
#endif

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

/* type conversion/check functions */
MRB_API mrb_value mrb_ensure_array_type(mrb_state *mrb, mrb_value self);
MRB_API mrb_value mrb_check_array_type(mrb_state *mrb, mrb_value self);
MRB_API mrb_value mrb_ensure_hash_type(mrb_state *mrb, mrb_value hash);
MRB_API mrb_value mrb_check_hash_type(mrb_state *mrb, mrb_value hash);
MRB_API mrb_value mrb_ensure_string_type(mrb_state *mrb, mrb_value str);
MRB_API mrb_value mrb_check_string_type(mrb_state *mrb, mrb_value str);
/* obsolete: use mrb_ensure_string_type() instead */
#define mrb_string_type(mrb, str) mrb_ensure_string_type(mrb,str)
#define mrb_to_str(mrb, str) mrb_ensure_string_type(mrb,str)
/* obsolete: use mrb_obj_as_string() instead */
#define mrb_str_to_str(mrb, str) mrb_obj_as_string(mrb, str)
MRB_API mrb_value mrb_ensure_int_type(mrb_state *mrb, mrb_value val);
#define mrb_as_int(mrb, val) mrb_integer(mrb_ensure_int_type(mrb, val))
/* obsolete: use mrb_ensure_int_type() instead */
#define mrb_to_integer(mrb, val) mrb_ensure_int_type(mrb, val)
#define mrb_to_int(mrb, val) mrb_ensure_int_type(mrb, val)

/* string type checking (contrary to the name, it doesn't convert) */
MRB_API void mrb_check_type(mrb_state *mrb, mrb_value x, enum mrb_vtype t);

MRB_INLINE void mrb_check_frozen(mrb_state *mrb, void *o)
{
  if (mrb_frozen_p((struct RBasic*)o)) mrb_frozen_error(mrb, o);
}

MRB_API void mrb_define_alias(mrb_state *mrb, struct RClass *c, const char *a, const char *b);
MRB_API void mrb_define_alias_id(mrb_state *mrb, struct RClass *c, mrb_sym a, mrb_sym b);
MRB_API const char *mrb_class_name(mrb_state *mrb, struct RClass* klass);
MRB_API void mrb_define_global_const(mrb_state *mrb, const char *name, mrb_value val);

MRB_API mrb_value mrb_attr_get(mrb_state *mrb, mrb_value obj, mrb_sym id);

MRB_API mrb_bool mrb_respond_to(mrb_state *mrb, mrb_value obj, mrb_sym mid);
MRB_API mrb_bool mrb_obj_is_instance_of(mrb_state *mrb, mrb_value obj, struct RClass* c);
MRB_API mrb_bool mrb_func_basic_p(mrb_state *mrb, mrb_value obj, mrb_sym mid, mrb_func_t func);

/* obsolete function(s); will be removed */
#define mrb_int(mrb, val) mrb_as_int(mrb, val)

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
#define E_FIBER_ERROR mrb_exc_get_id(mrb, MRB_ERROR_SYM(FiberError))
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

#ifdef MRB_PRESYM_SCANNING
# include <mruby/presym/scanning.h>
#endif

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
