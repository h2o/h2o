#### mrb_range_new
```C
  mrb_value mrb_range_new(mrb_state*, mrb_value, mrb_value, mrb_bool);
```
Initializes a Range. The first mrb_value being the beginning value and second being the ending value.
The third parameter is an mrb_bool value that represents the inclusion or exclusion of the last value.
If the third parameter is 0 then it includes the last value in the range. If the third parameter is 1 
then it excludes the last value in the range.
C code
```C
  #include <stdio.h>
  #include <mruby.h>
  #include "mruby/range.h" // Needs the range header.
  #include "mruby/compile.h"

  int main(int argc, char *argv[])
    {
      mrb_int beg = 0;
      mrb_int end = 2;
      mrb_bool exclude = 1;
      mrb_value range_obj;
      mrb_state *mrb = mrb_open();
      if (!mrb) { /* handle error */ }
      FILE *fp = fopen("test.rb","r");
      range_obj = mrb_range_new(mrb, mrb_fixnum_value(beg), mrb_fixnum_value(end), exclude);
      mrb_value obj = mrb_load_file(mrb,fp);
      mrb_funcall(mrb, obj, "method_name", 1, range_obj);
      fclose(fp);
      mrb_close(mrb);
      return 0;
    }
```
Ruby code
```Ruby
  class Example_Class
    def method_name(a)
      puts a
      puts a.class
    end
  end
  Example_Class.new
```
This returns the following:
```Ruby
  0...2
  Range
```
