### mrb_str_plus
```C
   mrb_value mrb_str_plus(mrb_state*, mrb_value, mrb_value);
```
Adds to strings together.
### mrb_ptr_to_str
```C
   mrb_value mrb_ptr_to_str(mrb_state *, void*);
```
Converts pointer into a Ruby string.
### mrb_obj_as_string
```C
   mrb_value mrb_obj_as_string(mrb_state *mrb, mrb_value obj);
```
Returns an object as a Ruby string.
### mrb_str_resize
```C
   mrb_value mrb_str_resize(mrb_state *mrb, mrb_value str, mrb_int len);
```
Resizes the string's length.
### mrb_str_substr
```C
   mrb_value mrb_str_substr(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len);
```
Returns a sub string.
### mrb_string_type
```C
   mrb_value mrb_string_type(mrb_state *mrb, mrb_value str);
```
Returns a Ruby string type.
### mrb_str_new_cstr
```C
   const char *mrb_string_value_cstr(mrb_state *mrb, mrb_value *ptr);
```
Returns a Ruby string as a C string.
### mrb_str_dup
```C
   mrb_value mrb_str_dup(mrb_state *mrb, mrb_value str);
```
Duplicates a string object.
### mrb_str_intern
```C
   mrb_value mrb_str_intern(mrb_state *mrb, mrb_value self);
```
Returns a symbol from a passed in string.
