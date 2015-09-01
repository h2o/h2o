# mruby.h

Basic header of mruby.
It includes **mrbconf.h**, **mruby/value.h**, **mruby/version.h** internally.

## `mrb_state` management

### mrb_open
```C
mrb_state* mrb_open();
```
Creates new `mrb_state`.

### mrb_allocf
```C
typedef void* (*mrb_allocf) (struct mrb_state *mrb, void *ptr, size_t s, void *ud);
```
Function pointer type of custom allocator used in `mrb_open_allocf`.

The function pointing it must behave similarly as `realloc` except:
* If `ptr` is `NULL` it must allocate new space.
* If `s` is `NULL`, `ptr` must be freed.

### mrb_open_allocf
```C
mrb_state* mrb_open_allocf(mrb_allocf f, void *ud);
```
Create new `mrb_state` with custom allocator.
`ud` will be passed to custom allocator `f`.
If user data isn't required just pass `NULL`.
Function pointer `f` must satisfy requirements of its type.

### mrb_close
```C
void mrb_close(mrb_state *mrb);
```
Deletes `mrb_state`.

## Method

### mrb_get_args
```C
int mrb_get_args(mrb_state *mrb, const char *format, ...);
```
Retrieve arguments from `mrb_state`.
When applicable, implicit conversions (such as `to_str`,
`to_ary`, `to_hash`) are applied to received arguments.
Use it inside a function pointed by `mrb_func_t`.
It returns the number of arguments retrieved.
`format` is a list of following format specifiers:

char|mruby type|retrieve types|note
:---:|----------|--------------|---
`o`|`Object`|`mrb_value`|Could be used to retrieve any type of argument
`C`|`Class`/`Module`|`mrb_value`|
`S`|`String`|`mrb_value`|when ! follows, the value may be nil
`A`|`Array`|`mrb_value`|when ! follows, the value may be nil
`H`|`Hash`|`mrb_value`|when ! follows, the value may be nil
`s`|`String`|`char*`, `mrb_int`|Receive two arguments; s! gives (NULL,0) for nil
`z`|`String`|`char*`|NUL terminated string; z! gives NULL for nil
`a`|`Array`|`mrb_value*`, `mrb_int`|Receive two arguments; a! gives (NULL,0) for nil
`f`|`Float`|`mrb_float`|
`i`|`Integer`|`mrb_int`|
`b`|boolean|`mrb_bool`|
`n`|`Symbol`|`mrb_sym`|
`&`|block|`mrb_value`|
`*`|rest arguments|`mrb_value*`, `mrb_int`|Receive the rest of arguments as an array.
<code>&#124;</code>|optional||After this spec following specs would be optional.
`?`|optional given|`mrb_bool`|True if preceding argument is given. Used to check optional argument is given.

The passing variadic arguments must be a pointer of retrieving type.

### mrb_define_class
```C
MRB_API struct RClass *mrb_define_class(mrb_state *, const char*, struct RClass*);
```
Defines a new class. If you're creating a gem it may look something like this:

```C
void mrb_example_gem_init(mrb_state* mrb) {
    struct RClass *example_class;
    example_class = mrb_define_class(mrb, "Example_Class", mrb->object_class);
}

void mrb_example_gem_final(mrb_state* mrb) {
  //free(TheAnimals);
}
```
### mrb_define_method

```C
MRB_API void mrb_define_method(mrb_state*, struct RClass*, const char*, mrb_func_t, mrb_aspec);
```

Defines a global function in ruby. If you're creating a gem it may look something like this:

```C
mrb_value example_method(mrb_state* mrb, mrb_value self){
	puts("Executing example command!");
	return self;
}

void mrb_example_gem_init(mrb_state* mrb) {
  mrb_define_method(mrb, mrb->kernel_module, "example_method", example_method, MRB_ARGS_NONE());  
}

void mrb_example_gem_final(mrb_state* mrb) {
  //free(TheAnimals);
}
```

Or maybe you want to create a class method for a class? It might look something like this:

```C
mrb_value example_method(mrb_state* mrb, mrb_value self){
	puts("Examples are like pizza...");
	return self;
}

void mrb_example_gem_init(mrb_state* mrb) {
    struct RClass *example_class;
    example_class = mrb_define_class(mrb, "Example_Class", mrb->object_class);
    mrb_define_method(mrb, example_class, "example_method", example_method, MRB_ARGS_NONE());
}

void mrb_example_gem_final(mrb_state* mrb) {
  //free(TheAnimals);
}
```
### mrb_define_module

```C
MRB_API struct RClass *mrb_define_module(mrb_state *, const char*);
```

Defines a module. If you're creating a gem it may look something like this:

```C
mrb_value example_method(mrb_state* mrb, mrb_value self){
	puts("Examples are like tacos...");
	return self;
}

void mrb_example_gem_init(mrb_state* mrb) {
    struct RClass *example_module;
    example_module = mrb_define_module(mrb, "Example_Module");
}

void mrb_example_gem_final(mrb_state* mrb) {
  //free(TheAnimals);
}
```

### mrb_define_module_function

```C
MRB_API void mrb_define_module_function(mrb_state*, struct RClass*, const char*, mrb_func_t, mrb_aspec);
```

Defines a module function. If you're creating a gem it may look something like this:


```C
mrb_value example_method(mrb_state* mrb, mrb_value self){
	puts("Examples are like hot wings...");
	return self;
}

void mrb_example_gem_init(mrb_state* mrb) {
    struct RClass *example_module;
    example_module = mrb_define_module(mrb, "Example_Module");
    mrb_define_module_function(mrb, example_module, "example_method", example_method, MRB_ARGS_NONE());
}

void mrb_example_gem_final(mrb_state* mrb) {
  //free(TheAnimals);
}
```

### mrb_define_const

```C
MRB_API void mrb_define_const(mrb_state*, struct RClass*, const char *name, mrb_value);
```

Defines a constant. If you're creating a gem it may look something like this:

```C
mrb_value example_method(mrb_state* mrb, mrb_value self){
	puts("Examples are like hot wings...");
	return self;
}

void mrb_example_gem_init(mrb_state* mrb) {
    mrb_define_const(mrb, mrb->kernel_module, "EXAPMLE_CONSTANT", mrb_fixnum_value(0x00000001));
}

void mrb_example_gem_final(mrb_state* mrb) {
  //free(TheAnimals);
}
```

### mrb_str_new_cstr

```C
MRB_API mrb_value mrb_str_new_cstr(mrb_state*, const char*);
```

Turns a C string into a Ruby string value.


### mrb_value mrb_funcall

```C
MRB_API mrb_value mrb_funcall(mrb_state*, mrb_value, const char*, mrb_int,...);
```
Call existing ruby functions.
