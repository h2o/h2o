### mrb_ary_new

```C
mrb_value mrb_ary_new(mrb_state *mrb);
```
Initializes an array.
#### Example
In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument and what class the passed in value is. In this case we are declaring a variable new_ary of data type mrb_value. Then we are initializing it with the mrb_ary_new function which only takes an mruby state as an argument.
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/array.h" // Needs the array header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_value new_ary; // Declare variable.
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  new_ary = mrb_ary_new(mrb);
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, new_ary);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```
test.rb
```Ruby
class Example_Class
  def method_name(a)
    puts a
    puts a.class
  end
end
Example_Class.new
```

### mrb_ary_push
```C
void mrb_ary_push(mrb_state*, mrb_value, mrb_value);
```
Pushes given value into an array.
#### Example
In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument and what class the passed in value is. In this case after initializing our array. We are declaring two variables with the mrb_int data type random_value1 & random_value2 and we initialize them 70 and 60 respectively. Then we use the mrb_ary_push function to push values those values into the array. 
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/array.h" // Needs the array header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_value new_ary; // Declare variable.
  mrb_int random_value1 = 70; // Initialize variable
  mrb_int random_value2 = 60; // Initialize variable
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  new_ary = mrb_ary_new(mrb); // Initialize ruby array.
  /* Pushes the fixnum value from random_value1 to the new_ary instance. */
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value1)); 
  /* Pushes the fixnum value from random_value2 to the new_ary instance. */
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value2));
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, new_ary);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```
test.rb
```Ruby
class Example_Class
  def method_name(a)
    puts a
    puts a.class
  end
end
Example_Class.new
```
#### Result
After compiling you should get these results.
```Ruby
[70, 60]
Array
```

## mrb_ary_pop
```C
mrb_value mrb_ary_pop(mrb_state *mrb, mrb_value ary);
```
Pops the last element from the array.
#### Example
In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument and what class the passed in value is. In this case after initializing our array. We are declaring two variables with the mrb_int data type random_value1 & random_value2 and we initialize them 70 and 60 respectively. Then we use the mrb_ary_push function to push values those values into the array. Now here in the Ruby files we add another method
called pop_ary that will return the array alone(just to be clean) and you should see the last element gone.
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/array.h" // Needs the array header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_value new_ary; // Declare variable.
  mrb_int random_value1 = 70; // Initialize variable
  mrb_int random_value2 = 60; // Initialize variable
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  new_ary = mrb_ary_new(mrb); // Initialize ruby array.
  /* Pushes the fixnum value from random_value1 to the new_ary instance. */
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value1)); 
  /* Pushes the fixnum value from random_value2 to the new_ary instance. */
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value2));
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, new_ary);
  mrb_ary_pop(mrb, new_ary); // Pops the last element of the array. In this case 60.
  mrb_funcall(mrb, obj, "pop_ary", 1, new_ary); // Calls the method again to show the results.
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```
test.rb
```Ruby
class Example_Class
  def method_name(a)
    puts a
    puts a.class
  end
  def pop_ary(a)
    puts a
  end
end
Example_Class.new
```
#### Result
After compiling you should get these results.
```Ruby
[70, 60]
Array
[70]
```
## mrb_ary_ref
```C
mrb_value mrb_ary_ref(mrb_state *mrb, mrb_value ary, mrb_int n);
```
Returns a reference to an element of the array. Specified by the value given to mrb_int n.
#### Example
In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument and what class the passed in value is. In this case we're declaring a variable ary_ref with the data type of mrb_value. Then we assign mrb_ary_ref to it getting new_ary's value at index 1.
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/array.h" // Needs the array header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_value ary_ref; // Declare variable.
  mrb_value new_ary; // Declare variable.
  mrb_int random_value1 = 70; // Initialize variable
  mrb_int random_value2 = 60; // Initialize variable
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  new_ary = mrb_ary_new(mrb); // Initialize ruby array.
  /* Pushes the fixnum value from random_value1 to the new_ary instance. */
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value1)); 
  /* Pushes the fixnum value from random_value2 to the new_ary instance. */
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value2));
  ary_ref = mrb_ary_ref(mrb, new_ary, 1); // Gets the value of new_ary's second element at index 1. 
  mrb_value obj = mrb_load_file(mrb,fp);
  /* Passing the value from ary_ref to the method method_name.*/
  mrb_funcall(mrb, obj, "method_name", 1, ary_ref);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```
test.rb
```Ruby
class Example_Class
  def method_name(a)
    puts a
    puts a.class
  end
end
Example_Class.new
```
#### Result
After compiling you should get these results.
```Ruby
60
Fixnum
```

### mrb_ary_set
```C
void mrb_ary_set(mrb_state *mrb, mrb_value ary, mrb_int n, mrb_value val);
```
Sets a value to an index.
#### Example
In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument and what class the passed in value is. In this case we're declaring a variable ary_ref with the data type of mrb_value. Then we assign mrb_ary_ref to it getting new_ary's value at index 1.
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/array.h" // Needs the array header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_value new_ary;
  mrb_value ary_obj;
  mrb_int random_value1 = 70;
  mrb_int random_value2 = 60;
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  new_ary = mrb_ary_new(mrb);
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value1));
  mrb_ary_push(mrb, new_ary, mrb_fixnum_value(random_value2));
  /* Sets the fixnum value of 7 to the second index of the array.*/
  mrb_ary_set(mrb, new_ary, 2, mrb_fixnum_value(7));
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "before_after", 1, new_ary);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```
test.rb
```Ruby
class Example_Class
  def method_name(a)
    puts a
    puts a.class
  end
  def before_after(a)
    puts a
  end
end
Example_Class.new
```
#### Result
After compiling you should get these results.
```Ruby
[70, 60, 7]
```
