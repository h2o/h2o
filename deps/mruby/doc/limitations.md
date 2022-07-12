# Limitations and Differences

The philosophy of mruby is to be a lightweight implementation of
the Ruby ISO standard. These two objectives are partially contradicting.
Ruby is an expressive language with complex implementation details which
are difficult to implement in a lightweight manner. To cope with this,
limitations to the "Ruby Compatibility" are defined.

This document is collecting these limitations.

## Integrity

This document does not contain a complete list of limitations.
Please help to improve it by submitting your findings.

## `Kernel.raise` in rescue clause

`Kernel.raise` without arguments does not raise the current exception within
a rescue clause.

```ruby
begin
  1 / 0
rescue
  raise
end
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

`ZeroDivisionError` is raised.

#### mruby [3.1.0 (2022-05-12)]

`RuntimeError` is raised instead of `ZeroDivisionError`. To re-raise the exception, you have to do:

```ruby
begin
  1 / 0
rescue => e
  raise e
end
```

## Fiber execution can't cross C function boundary

mruby's `Fiber` is implemented similarly to Lua's co-routine. This
results in the consequence that you can't switch context within C functions.
Only exception is `mrb_fiber_yield` at return.

## `Array` does not support instance variables

To reduce memory consumption `Array` does not support instance variables.

```ruby
class Liste < Array
  def initialize(str = nil)
    @field = str
  end
end

p Liste.new "foobar"
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

` [] `

#### mruby [3.1.0 (2022-05-12)]

`ArgumentError` is raised.

## Method visibility

For simplicity reasons no method visibility (public/private/protected) is
supported. Those methods are defined, but they are dummy methods.

```ruby
class VisibleTest

  def public_method; end

  private
  def private_method; end

end

p VisibleTest.new.respond_to?(:private_method, false)
p VisibleTest.new.respond_to?(:private_method, true)
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

```
false
true
```

#### mruby [3.1.0 (2022-05-12)]

```
true
true
```

### Visibility Declaration

The declaration form of following visibility methods are not implemented.

* `public`
* `private`
* `protected`
* `module_function`

Especially, `module_function` method is not dummy, but no declaration form.

```
module TestModule
  module_function
  def test_func
    p 'test_func called'
  end

  test_func
end

p 'ok'
```

#### Ruby [ruby 2.5.5p157 (2019-03-15 revision 67260)]

```
ok
```

#### mruby [3.1.0 (2022-05-12)]

```
test.rb:8: undefined method 'test_func' (NoMethodError)
```

## `defined?`

The `defined?` keyword is considered too complex to be fully
implemented. It is recommended to use `const_defined?` and
other reflection methods instead.

```ruby
defined?(Foo)
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

```
nil
```

#### mruby [3.1.0 (2022-05-12)]

`NameError` is raised.

## `alias` on global variables

Aliasing a global variable works in CRuby but is not part
of the ISO standard.

```ruby
alias $a $__a__
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

` nil `

#### mruby [3.1.0 (2022-05-12)]

Syntax error

## Operator modification

An operator can't be overwritten by the user.

```ruby
class String
  def +
  end
end

'a' + 'b'
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

`ArgumentError` is raised.
The re-defined `+` operator does not accept any arguments.

#### mruby [3.1.0 (2022-05-12)]

` 'ab' `
Behavior of the operator wasn't changed.

## `Kernel#binding` is not supported

`Kernel#binding` method is not supported.

#### Ruby [ruby 2.5.1p57 (2018-03-29 revision 63029)]

```
$ ruby -e 'puts Proc.new {}.binding'
#<Binding:0x00000e9deabb9950>
```

#### mruby [3.1.0 (2022-05-12)]

```
$ ./bin/mruby -e 'puts Proc.new {}.binding'
trace (most recent call last):
        [0] -e:1
-e:1: undefined method 'binding' (NoMethodError)
```

## `nil?` redefinition in conditional expressions

Redefinition of `nil?` is ignored in conditional expressions.

```ruby
a = "a"
def a.nil?
  true
end
puts(a.nil? ? "truthy" : "falsy")
```

Ruby outputs `falsy`. mruby outputs `truthy`.

## Argument Destructuring

```ruby
def m(a,(b,c),d); p [a,b,c,d]; end
m(1,[2,3],4)  # => [1,2,3,4]
```

Destructured arguments (`b` and `c` in above example) cannot be accessed
from the default expression of optional arguments and keyword arguments,
since actual assignment is done after the evaluation of those default
expressions. Thus:

```ruby
def f(a,(b,c),d=b)
  p [a,b,c,d]
end
f(1,[2,3])
```

CRuby gives `[1,2,3,nil]`. mruby raises `NoMethodError` for `b`.
