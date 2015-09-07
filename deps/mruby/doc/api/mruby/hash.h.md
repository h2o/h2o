### mrb_hash_new

```C
mrb_value mrb_hash_new(mrb_state *mrb);
```

Initializes a hash.
#### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument
and what class the passed in value is. This example initializes a hash. In pure Ruby doing this is equivalent
to Hash.new.

```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/hash.h" // Needs the hash header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  mrb_value new_hash; // Declare variable.
  FILE *fp = fopen("test_ext.rb","r");
  new_hash = mrb_hash_new(mrb);  // Initialize hash.
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_funcall(mrb, obj, "method_name", 1, new_hash);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```

#### test_ext.rb

``` Ruby
class Example_Class
  def method_name(a)
    puts a
    puts a.class
  end
end
Example_Class.new
```

### mrb_hash_set

```C
void mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val);
```

Sets a keys and values to hashes.
#### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument
and what class the passed in value is. This example sets a key and value pair to a hash. In pure Ruby doing this is equivalent to:

```Ruby
a = {:da_key => 80}
```

```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/hash.h" // Needs the hash header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  mrb_value new_hash; // Declare variable.
  mrb_sym hash_key = mrb_intern_cstr(mrb, "da_key"); // Declare a symbol.
  mrb_int hash_value = 80; // Declare a fixnum value.
  FILE *fp = fopen("test_ext.rb","r");
  new_hash = mrb_hash_new(mrb);  // Initialize hash.
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key), mrb_fixnum_value(hash_value)); // Set values to hash.
  mrb_funcall(mrb, obj, "method_name", 1, new_hash);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```

#### test_ext.rb

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
{:da_key=>80}
Hash
```

### mrb_hash_get

```C
mrb_value mrb_hash_get(mrb_state *mrb, mrb_value hash, mrb_value key);
```

Gets a value from a key.
#### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument
and what class the passed in value is. This example gets a value from a key. In pure Ruby doing this is equivalent to:

```Ruby
a = {:da_key => 80} 
a[:da_key]
```

```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/hash.h" // Needs the hash header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  mrb_value new_hash; // Declare variable for new hash object.
  mrb_value get_hash_value; // Declare variable for getting a value from a hash.
  mrb_sym hash_key_a = mrb_intern_cstr(mrb, "da_key1"); // Declare a symbol.
  mrb_sym hash_key_b = mrb_intern_cstr(mrb, "da_key2"); // Declare a symbol.
  mrb_int hash_value_a = 80; // Declare a fixnum value.
  mrb_int hash_value_b = 90; // Declare a fixnum value.
  FILE *fp = fopen("test_ext.rb","r");
  new_hash = mrb_hash_new(mrb);  // Initialize hash.
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_a), mrb_fixnum_value(hash_value_a)); // Set values to hash.
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_b), mrb_fixnum_value(hash_value_b)); // Set values to hash.
  get_hash_value = mrb_hash_get(mrb, new_hash, mrb_symbol_value(hash_key_b)); // Get value from hash.
  mrb_funcall(mrb, obj, "method_name", 1, get_hash_value);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```

#### test_ext.rb

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
90
Fixnum
```

### mrb_hash_delete_key

```C
mrb_value mrb_hash_delete_key(mrb_state *mrb, mrb_value hash, mrb_value key);
```

Deletes hash key and value pair.
#### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument
and what class the passed in value is. This example deletes hash key and value pair. In pure Ruby doing this is equivalent to:

```Ruby
a = {:da_key1 => 80,:da_key2 => 90} 
a.delete(:da_key2)
```

```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/hash.h" // Needs the hash header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  mrb_value new_hash; // Declare variable for new hash object.
  mrb_value get_hash_value; // Declare variable for getting a value from a hash.
  mrb_sym hash_key_a = mrb_intern_cstr(mrb, "da_key1"); // Declare a symbol.   
  mrb_sym hash_key_b = mrb_intern_cstr(mrb, "da_key2"); // Declare a symbol.
  mrb_sym hash_key_b = mrb_intern_cstr(mrb, "da_key2"); // Declare a symbol.
  mrb_int hash_value_a = 80; // Declare a fixnum value.
  mrb_int hash_value_b = 90; // Declare a fixnum value.
  FILE *fp = fopen("test_ext.rb","r");
  new_hash = mrb_hash_new(mrb);  // Initialize hash.
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_a), mrb_fixnum_value(hash_value_a)); // Set values to hash.
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_b), mrb_fixnum_value(hash_value_b)); // Set values to hash.
  mrb_funcall(mrb, obj, "method_name", 1, new_hash);
  mrb_hash_delete_key(mrb, new_hash, mrb_symbol_value(hash_key_b));
  mrb_funcall(mrb, obj, "another_method_name", 1, new_hash);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```

#### test_ext.rb

```Ruby
class Example_Class
  def method_name(a)
    puts "Hash pre deletion #{a}"
    #puts a.class
  end
  # Show deleted key and value pair.
  def another_method_name(a)
    puts "Hash post deletion #{a}"
  end
end
Example_Class.new
```

#### Result

After compiling you should get these results.

```Ruby
Hash pre deletion {:da_key1 => 80, :da_key2 => 90}
Hash post deletion {:da_key1 => 80}
```

### mrb_hash_keys

```C
mrb_value mrb_hash_keys(mrb_state *mrb, mrb_value hash);
```

Gets an array of keys.
#### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument
and what class the passed in value is. This example gets an array of keys from a hash.

```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/hash.h" // Needs the hash header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  mrb_value new_hash; // Declare variable for new hash object.
  mrb_value get_hash_keys; // Declare variable for getting an array of keys.
  mrb_sym hash_key_a = mrb_intern_cstr(mrb, "da_key1"); // Declare a symbol.
  mrb_sym hash_key_b = mrb_intern_cstr(mrb, "da_key2"); // Declare a symbol.
  mrb_int hash_value_a = 80; // Declare a fixnum value.
  mrb_int hash_value_b = 90; // Declare a fixnum value.
  FILE *fp = fopen("test_ext.rb","r");
  new_hash = mrb_hash_new(mrb);  // Initialize hash.
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_a), mrb_fixnum_value(hash_value_a)); // Set values to hash.
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_b), mrb_fixnum_value(hash_value_b)); // Set values to hash.
  get_hash_keys = mrb_hash_keys(mrb, new_hash); // get an array of keys.
  mrb_funcall(mrb, obj, "method_name", 1, get_hash_keys);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```

#### test_ext.rb

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
[:da_key1, :da_key2]
Array
```

### mrb_hash_clear

```C
mrb_value mrb_hash_clear(mrb_state *mrb, mrb_value hash);
```

Clears the hash.
#### Example

In this example we read from a Ruby file inside C. The Ruby code will print what you pass as an argument
and what class the passed in value is. This example clears the hash. In pure Ruby doing this is equivalent to:

```Ruby
a = {:da_key1 => 80,:da_key2 => 90}
a.clear
```

```C
#include <stdio.h>
#include <mruby.h>
#include "mruby/hash.h" // Needs the hash header.
#include "mruby/compile.h"

int main(int argc, char *argv[])
{
  mrb_state *mrb = mrb_open();
  if (!mrb) { /* handle error */ }
  mrb_value new_hash; // Declare variable for new hash object.
  mrb_value get_hash; // Declare variable for getting a hash.
  mrb_sym hash_key_a = mrb_intern_cstr(mrb, "da_key1"); // Declare a symbol.
  mrb_sym hash_key_b = mrb_intern_cstr(mrb, "da_key2"); // Declare a symbol.
  mrb_int hash_value_a = 80; // Declare a fixnum value.
  mrb_int hash_value_b = 90; // Declare a fixnum value.
  FILE *fp = fopen("test_ext.rb","r");
  new_hash = mrb_hash_new(mrb);  // Initialize hash.
  mrb_value obj = mrb_load_file(mrb,fp);
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_a), mrb_fixnum_value(hash_value_a)); // Set values to hash.
  mrb_hash_set(mrb, new_hash, mrb_symbol_value(hash_key_b), mrb_fixnum_value(hash_value_b)); // Set values to hash.
  mrb_funcall(mrb, obj, "method_name", 1, new_hash);
  get_hash = mrb_hash_clear(mrb, new_hash);
  mrb_funcall(mrb, obj, "another_method_name", 1, get_hash);
  fclose(fp);
  mrb_close(mrb);
  return 0;
}
```

#### test_ext.rb

```Ruby
class Example_Class
  def method_name(a)
    puts "Hash pre clear #{a}"
    #puts a.class
  end
  # Show clear hash.
  def another_method_name(a)
    puts "Hash post clear #{a}"
  end
end
Example_Class.new
```

#### Result

After compiling you should get these results.

```Ruby
Hash pre clear {:da_key1 => 80, :da_key2 => 90}
Hash post clear {}
```
