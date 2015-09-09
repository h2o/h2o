## Macros
### mrb_str_ptr(s)
Returns a pointer from a Ruby string.
## Functions
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
### mrb_str_to_str
```C
   mrb_value mrb_str_to_str(mrb_state *mrb, mrb_value str);
```
Returns a converted string type.
### mrb_str_equal
```C
   mrb_bool mrb_str_equal(mrb_state *mrb, mrb_value str1, mrb_value str2);
```
Returns true if the strings match and false if the strings don't match.
### mrb_str_cat
```C
   mrb_value mrb_str_cat(mrb_state *mrb, mrb_value str, const char *ptr, size_t len);
```
Returns a concated string comprised of a Ruby string and a C string.
### mrb_str_cat_cstr
```C
   mrb_value mrb_str_cat_str(mrb_state *mrb, mrb_value str, mrb_value str2);
```
Returns a concated string comprised of a Ruby string and a C string(A shorter alternative to mrb_str_cat).
### mrb_str_append
```C
   mrb_value mrb_str_append(mrb_state *mrb, mrb_value str1, mrb_value str2);
```
Adds str2 to the end of str1.
### mrb_str_cmp
```C
   int mrb_str_cmp(mrb_state *mrb, mrb_value str1, mrb_value str2);
```
Returns 0 if both Ruby strings are equal.
Returns a value < 0 if Ruby str1 is less than Ruby str2.
Returns a value > 0 if Ruby str2 is greater than Ruby str1.
### mrb_str_to_cstr
```C
   char *mrb_str_to_cstr(mrb_state *mrb, mrb_value str);
```
Returns a C string from a Ruby string.
### mrb_str_inspect
```C
   mrb_str_inspect(mrb_state *mrb, mrb_value str);
```
Returns a printable version of str, surrounded by quote marks, with special characters escaped.
