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


## ```1/2``` gives ```0.5```

Since mruby does not have ```Bignum```, bigger integers are represented
by ```Float``` numbers. To enhance interoperability between ```Fixnum```
and ```Float```, mruby provides ```Float#upto``` and other iterating
methods for the ```Float``` class.  As a side effect, ```1/2``` gives ```0.5```
not ```0```.

## ```Array``` passed to ```puts```

Passing an Array to ```puts``` results in different output.

```ruby
puts [1,2,3]
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

```
1
2
3
```

#### mruby [1.4.1 (2018-4-27)]

```
[1, 2, 3]
```

## ```Kernel.raise``` in rescue clause

```Kernel.raise``` without arguments does not raise the current exception within
a rescue clause.

```ruby
begin
  1 / 0
rescue
  raise
end
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

```ZeroDivisionError``` is raised.

#### mruby [1.4.1 (2018-4-27)]

No exception is raised.

## Fiber execution can't cross C function boundary

mruby's ```Fiber``` is implemented in a similar way to Lua's co-routine. This
results in the consequence that you can't switch context within C functions.
Only exception is ```mrb_fiber_yield``` at return.

## ```Array``` does not support instance variables

To reduce memory consumption ```Array``` does not support instance variables.

```ruby
class Liste < Array
  def initialize(str = nil)
    @feld = str
  end
end

p Liste.new "foobar"
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

``` [] ```

#### mruby [1.4.1 (2018-4-27)]

```ArgumentError``` is raised.

## Method visibility

For simplicity reasons no method visibility (public/private/protected) is
supported.

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

#### mruby [1.4.1 (2018-4-27)]

```
true
true
```

## defined?

The ```defined?``` keyword is considered too complex to be fully
implemented. It is recommended to use ```const_defined?``` and
other reflection methods instead.

```ruby
defined?(Foo)
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

```
nil
```

#### mruby [1.4.1 (2018-4-27)]

```NameError``` is raised.

## ```alias``` on global variables

Aliasing a global variable works in CRuby but is not part
of the ISO standard.

```ruby
alias $a $__a__
```

#### Ruby [ruby 2.0.0p645 (2015-04-13 revision 50299)]

``` nil ```

#### mruby [1.4.1 (2018-4-27)]

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

```ArgumentError``` is raised.
The re-defined ```+``` operator does not accept any arguments.

#### mruby [1.4.1 (2018-4-27)]

``` 'ab' ```
Behavior of the operator wasn't changed.

## Kernel#binding is not supported

`Kernel#binding` method is not supported.

#### Ruby [ruby 2.5.1p57 (2018-03-29 revision 63029)]

```
$ ruby -e 'puts Proc.new {}.binding'
#<Binding:0x00000e9deabb9950>
```

#### mruby [1.4.1 (2018-4-27)]

```
$ ./bin/mruby -e 'puts Proc.new {}.binding'
trace (most recent call last):
        [0] -e:1
-e:1: undefined method 'binding' (NoMethodError)
```
