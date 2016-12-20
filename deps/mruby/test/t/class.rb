##
# Class ISO Test

assert('Class', '15.2.3') do
  assert_equal(Class, Class.class)
end

assert('Class#initialize', '15.2.3.3.1') do
  c = Class.new do
    def test
      :test
    end
  end.new

  assert_equal(c.test, :test)
end

assert('Class#initialize_copy', '15.2.3.3.2') do
  class TestClass
    attr_accessor :n
    def initialize(n)
      @n = n
    end
    def initialize_copy(obj)
      @n = n
    end
  end

  c1 = TestClass.new('Foo')
  c2 = c1.dup
  c3 = TestClass.new('Bar')

  assert_equal(c1.n, c2.n)
  assert_not_equal(c1.n, c3.n)
end

assert('Class#new', '15.2.3.3.3') do
  assert_raise(TypeError, 'Singleton should raise TypeError') do
    "a".singleton_class.new
  end

  class TestClass
    def initialize args, &block
      @result = if not args.nil? and block.nil?
        # only arguments
        :only_args
      elsif not args.nil? and not block.nil?
        # args and block is given
        :args_and_block
      else
        # this should never happen
        :broken
      end
    end

    def result; @result; end
  end

  assert_equal(:only_args, TestClass.new(:arg).result)
  # with block doesn't work yet
end

assert('Class#superclass', '15.2.3.3.4') do
  class SubClass < String; end
  assert_equal(String, SubClass.superclass)
end

# Not ISO specified

assert('Class 1') do
  class C1; end
  assert_equal(Class, C1.class)
end

assert('Class 2') do
  class C2; end
  assert_equal(C2, C2.new.class)
end

assert('Class 3') do
  class C3; end
  assert_equal(Class, C3.new.class.class)
end

assert('Class 4') do
  class C4_A; end
  class C4 < C4_A; end
  assert_equal(Class, C4.class)
end

assert('Class 5') do
  class C5_A; end
  class C5 < C5_A; end
  assert_equal(C5, C5.new.class)
end

assert('Class 6') do
  class C6_A; end
  class C6 < C6_A; end
  assert_equal(Class, C6.new.class.class)
end

assert('Class 7') do
  class C7_A; end
  class C7_B; end

  class C7 < C7_A; end

  assert_raise(TypeError) do
    # Different superclass.
    class C7 < C7_B; end
  end
end

assert('Class 8') do
  class C8_A; end

  class C8; end  # superclass is Object

  assert_raise(TypeError) do
    # Different superclass.
    class C8 < C8_A; end
  end
end

assert('Class 9') do
  Class9Const = "a"

  assert_raise(TypeError) do
    class Class9Const; end
  end
end

assert('Class Module 1') do
  module M; end
  assert_equal(Module, M.class)
end

assert('Class Module 2') do
  module M; end
  class C; include M; end
  assert_equal(C, C.new.class)
end

# nested class
assert('Class Nested 1') do
  class A; end
  class A::B; end
  assert_equal(A::B, A::B)
end

assert('Class Nested 2') do
  class A; end
  class A::B; end
  assert_equal(A::B, A::B.new.class)
end

assert('Class Nested 3') do
  class A; end
  class A::B; end
  assert_equal(Class, A::B.new.class.class)
end

assert('Class Nested 4') do
  class A; end
  class A::B; end
  class A::B::C; end
  assert_equal(A::B::C, A::B::C)
end

assert('Class Nested 5') do
  class A; end
  class A::B; end
  class A::B::C; end
  assert_equal(Class, A::B::C.class)
end

assert('Class Nested 6') do
  class A; end
  class A::B; end
  class A::B::C; end
  assert_equal(A::B::C, A::B::C.new.class)
end

assert('Class Nested 7') do
  class A; end
  class A::B; end
  class A::B2 < A::B; end
  assert_equal(A::B2, A::B2)
end

assert('Class Nested 8') do
  class A; end
  class A::B; end
  class A::B2 < A::B; end
  assert_equal(Class, A::B2.class)
end

assert('Class Colon 1') do
  class A; end
  A::C = 1
  assert_equal(1, A::C)
end

assert('Class Colon 2') do
  class A; class ::C; end end
  assert_equal(C, C)
end

assert('Class Colon 3') do
  class A; class ::C; end end
  assert_equal(Class, C.class)
end

assert('Class Dup 1') do
  class C; end
  assert_equal(Class, C.dup.class)
end

assert('Class Dup 2') do
  module M; end
  assert_equal(Module, M.dup.class)
end

assert('Class.new') do
  assert_equal(Class, Class.new.class)
  a = []
  klass = Class.new do |c|
    a << c
  end
  assert_equal([klass], a)
end

assert('class to return the last value') do
  m = class C; :m end
  assert_equal(m, :m)
end

assert('raise when superclass is not a class') do
  module FirstModule; end
  assert_raise(TypeError, 'should raise TypeError') do
    class FirstClass < FirstModule; end
  end

  class SecondClass; end
  assert_raise(TypeError, 'should raise TypeError') do
    class SecondClass < false; end
  end

  class ThirdClass; end
  assert_raise(TypeError, 'should raise TypeError') do
    class ThirdClass < ThirdClass; end
  end
end

assert('Class#inherited') do
  class Foo
    @@subclass_name = nil
    def self.inherited(subclass)
      @@subclass_name = subclass
    end
    def self.subclass_name
      @@subclass_name
    end
  end

  assert_equal(nil, Foo.subclass_name)

  class Bar < Foo
  end

  assert_equal(Bar, Foo.subclass_name)

  class Baz < Bar
  end

  assert_equal(Baz, Foo.subclass_name)
end

assert('singleton tests') do
  module FooMod
    def run_foo_mod
      100
    end
  end

  bar = String.new

  baz = class << bar
    extend FooMod
    def self.run_baz
      200
    end
  end

  assert_false baz.singleton_methods.include? :run_foo_mod
  assert_false baz.singleton_methods.include? :run_baz

  assert_raise(NoMethodError, 'should raise NoMethodError') do
    baz.run_foo_mod
  end
  assert_raise(NoMethodError, 'should raise NoMethodError') do
    baz.run_baz
  end

  assert_raise(NoMethodError, 'should raise NoMethodError') do
    bar.run_foo_mod
  end
  assert_raise(NoMethodError, 'should raise NoMethodError') do
    bar.run_baz
  end

  baz = class << bar
    extend FooMod
    def self.run_baz
      300
    end
    self
  end

  assert_true baz.singleton_methods.include? :run_baz
  assert_true baz.singleton_methods.include? :run_foo_mod
  assert_equal 100, baz.run_foo_mod
  assert_equal 300, baz.run_baz

  assert_raise(NoMethodError, 'should raise NoMethodError') do
    bar.run_foo_mod
  end
  assert_raise(NoMethodError, 'should raise NoMethodError') do
    bar.run_baz
  end

  fv = false
  class << fv
    def self.run_false
      5
    end
  end

  nv = nil
  class << nv
    def self.run_nil
      6
    end
  end

  tv = true
  class << tv
    def self.run_nil
      7
    end
  end

  assert_raise(TypeError, 'should raise TypeError') do
    num = 1.0
    class << num
      def self.run_nil
        7
      end
    end
  end
end

assert('clone Class') do
  class Foo
    def func
      true
    end
  end

  Foo.clone.new.func
end

assert('class variable and class << self style class method') do
  class ClassVariableTest
    @@class_variable = "value"
    class << self
      def class_variable
        @@class_variable
      end
    end
  end

  assert_equal("value", ClassVariableTest.class_variable)
end

assert('class variable in module and class << self style class method') do
  module ClassVariableInModuleTest
    @@class_variable = "value"
    class << self
      def class_variable
        @@class_variable
      end
    end
  end

  assert_equal("value", ClassVariableInModuleTest.class_variable)
end

assert('overriding class variable with a module (#3235)') do
  module ModuleWithCVar
    @@class_variable = 1
  end
  class CVarOverrideTest
    @@class_variable = 2
    include ModuleWithCVar

    assert_equal(1, @@class_variable)
  end
end

assert('class with non-class/module outer raises TypeError') do
  assert_raise(TypeError) { class 0::C1; end }
  assert_raise(TypeError) { class []::C2; end }
end

assert("remove_method doesn't segfault if the passed in argument isn't a symbol") do
  klass = Class.new
  assert_raise(TypeError) { klass.remove_method nil }
  assert_raise(TypeError) { klass.remove_method 123 }
  assert_raise(TypeError) { klass.remove_method 1.23 }
  assert_raise(NameError) { klass.remove_method "hello" }
  assert_raise(TypeError) { klass.remove_method Class.new }
end
