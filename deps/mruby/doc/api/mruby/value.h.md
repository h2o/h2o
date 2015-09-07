### mrb_float_value
```C
static inline mrb_value mrb_float_value(struct mrb_state *mrb, mrb_float f)
```

Returns a float in Ruby.

##### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument 
and what class the passed in value is. In this case we are passing in mrb_float f = 0.09. Alternatively 
double i = 0.09 could also be used.


example.c
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/compile.h"
#include "mruby/string.h"

int
main(void)
{
  mrb_float f = 0.09;// or double i = 0.09;
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, mrb_float_value(mrb, f));
  fclose(fp);
  mrb_close(mrb);
  return 0;
}

```

test.rb
```Ruby
class My_Class
  def method_name(s)
    puts s
    puts s.class
  end
end
a = My_Class.new
```

### mrb_fixnum_value

```C
static inline mrb_value mrb_fixnum_value(mrb_int i)
```

Returns a fixnum in Ruby.

##### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument 
and what class the passed in value is. In this case we are passing in mrb_int i = 99. Alternativly int i = 99
could also be used.


example.c
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/compile.h"

int
main(void)
{
  mrb_int i = 99; // or int i = 99;
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, mrb_fixnum_value(i));
  fclose(fp);
  mrb_close(mrb);
  return 0;
}

```

test.rb
```Ruby
class My_Class
  def method_name(s)
    puts s
    puts s.class
  end
end
a = My_Class.new
```



### mrb_nil_value

```C
static inline mrb_value mrb_nil_value(void)
```

Returns nil in Ruby.

##### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument 
and what class the passed in value is. In this case we are passing in nothing and we will get NillClass.


example.c
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/compile.h"

int
main(void)
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, mrb_nil_value());
  fclose(fp);
  mrb_close(mrb);
  return 0;
}

```

test.rb
```Ruby
class My_Class
  def method_name(s)
    puts s
    puts s.class
  end
end
a = My_Class.new
```


### mrb_false_value

```C
static inline mrb_value mrb_false_value(void)
```

Returns false in Ruby.

##### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument 
and what class the passed in value is. In this case we are passing in nothing and we will get FalseClass.


example.c
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/compile.h"

int
main(void)
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, mrb_false_value());
  fclose(fp);
  mrb_close(mrb);
  return 0;
}

```

test.rb
```Ruby
class My_Class
  def method_name(s)
    puts s
    puts s.class
  end
end
a = My_Class.new
```



### mrb_true_value

```C
static inline mrb_value mrb_true_value(void)
```

Returns true in Ruby.

##### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument 
and what class the passed in value is. In this case we are passing in nothing and we will get TrueClass.


example.c
```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/compile.h"

int
main(void)
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  FILE *fp = fopen("test.rb","r");
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, mrb_true_value());
  fclose(fp);
  mrb_close(mrb);
  return 0;
}

```

test.rb
```Ruby
class My_Class
  def method_name(s)
    puts s
    puts s.class
  end
end
a = My_Class.new
```
