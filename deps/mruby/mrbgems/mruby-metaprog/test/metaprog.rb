assert('Kernel#send', '15.3.1.3.44') do
  # test with block
  l = send(:lambda) do
    true
  end

  assert_true l.call
  assert_equal l.class, Proc
  # test with argument
  assert_true send(:respond_to?, :nil?)
  # test without argument and without block
  assert_equal send(:to_s).class, String
end

assert('Kernel#instance_variable_defined?', '15.3.1.3.20') do
  o = Object.new
  o.instance_variable_set(:@a, 1)

  assert_true o.instance_variable_defined?("@a")
  assert_false o.instance_variable_defined?("@b")
  assert_true o.instance_variable_defined?("@a"[0,2])
  assert_true o.instance_variable_defined?("@abc"[0,2])
  assert_raise(NameError) { o.instance_variable_defined?("@0") }
end

assert('Kernel#instance_variable_get', '15.3.1.3.21') do
  o = Class.new { attr_accessor :foo, :bar }.new
  o.foo = "one"
  o.bar = 2
  assert_equal("one", o.instance_variable_get(:@foo))
  assert_equal(2, o.instance_variable_get("@bar"))
  assert_equal(nil, o.instance_variable_get(:@baz))
  %w[foo @1].each do |n|
    assert_raise(NameError) { o.instance_variable_get(n) }
  end
end

assert('Kernel#instance_variable_set', '15.3.1.3.22') do
  o = Class.new { attr_reader :foo, :_bar }.new
  assert_equal("one", o.instance_variable_set(:@foo, "one"))
  assert_equal("one", o.foo)
  assert_equal(2, o.instance_variable_set("@_bar", 2))
  assert_equal(2, o._bar)
  %w[@6 @% @@a @ a].each do |n|
    assert_raise(NameError) { o.instance_variable_set(n, 1) }
  end
  assert_raise(FrozenError) { o.freeze.instance_variable_set(:@a, 2) }
  assert_raise(FrozenError, ArgumentError) { nil.instance_variable_set(:@a, 2) }
end

assert('Kernel#instance_variables', '15.3.1.3.23') do
  o = Object.new
  o.instance_eval do
    @a = 11
    @b = 12
  end
  ivars = o.instance_variables

  assert_equal Array, ivars.class,
  assert_equal(2, ivars.size)
  assert_true ivars.include?(:@a)
  assert_true ivars.include?(:@b)
end

assert('Kernel#methods', '15.3.1.3.31') do
  assert_equal Array, methods.class
  assert_equal [:foo], Class.new{def self.foo; end}.methods(false)
  assert_equal [], Class.new{}.methods(false)
end

assert('Kernel#private_methods', '15.3.1.3.36') do
  assert_equal Array, private_methods.class
end

assert('Kernel#protected_methods', '15.3.1.3.37') do
  assert_equal Array, protected_methods.class
end

assert('Kernel#public_methods', '15.3.1.3.38') do
  assert_equal Array, public_methods.class
  class Foo
    def foo
    end
  end
  assert_equal [:foo], Foo.new.public_methods(false)
end

assert('Kernel#singleton_methods', '15.3.1.3.45') do
  assert_equal singleton_methods.class, Array
end

assert('Kernel.global_variables', '15.3.1.2.4') do
  assert_equal Array, Kernel.global_variables.class
end

assert('Kernel#global_variables', '15.3.1.3.14') do
  variables1 = global_variables
  assert_equal Array, variables1.class
  assert_not_include(variables1, :$kernel_global_variables_test)

  $kernel_global_variables_test = nil
  variables2 = global_variables
  assert_include(variables2, :$kernel_global_variables_test)
  assert_equal(1, variables2.size - variables1.size)
end

assert('Kernel#local_variables', '15.3.1.3.28') do
  assert_equal Array, local_variables.class

  def local_var_list
    a = "hello"
    local_variables
  end

  assert_equal [:a], local_var_list
end

assert('Kernel.local_variables', '15.3.1.2.7') do
  a, b = 0, 1
  a += b

  vars = Kernel.local_variables.sort
  assert_equal [:a, :b, :vars], vars

  assert_equal [:a, :b, :c, :vars], Proc.new { |a, b|
    c = 2
    # Kernel#local_variables: 15.3.1.3.28
    local_variables.sort
  }.call(-1, -2)

  a = Object.new
  def a.hoge(vars, *, **)
    Proc.new {
      x, y = 1, 2
      local_variables.sort
    }
  end
  assert_equal([:vars, :x, :y]) { a.hoge(0).call }
end

assert('Kernel#define_singleton_method') do
  o = Object.new
  ret = o.define_singleton_method(:test_method) do
    :singleton_method_ok
  end
  assert_equal :test_method, ret
  assert_equal :singleton_method_ok, o.test_method
  assert_raise(TypeError) { 2.define_singleton_method(:f){} }
  assert_raise(FrozenError) { [].freeze.define_singleton_method(:f){} }
end

assert('Kernel#singleton_class') do
  o1 = Object.new
  assert_same(o1.singleton_class, class << o1; self end)

  o2 = Object.new
  sc2 = class << o2; self end
  assert_same(o2.singleton_class, sc2)

  o3 = Object.new
  sc3 = o3.singleton_class
  o3.freeze
  assert_predicate(sc3, :frozen?)

  assert_predicate(Object.new.freeze.singleton_class, :frozen?)
end

def labeled_module(name, &block)
  Module.new do
    (class <<self; self end).class_eval do
      define_method(:to_s) { name }
      alias_method :inspect, :to_s
    end
    class_eval(&block) if block
  end
end

def labeled_class(name, supklass = Object, &block)
  Class.new(supklass) do
    (class <<self; self end).class_eval do
      define_method(:to_s) { name }
      alias_method :inspect, :to_s
    end
    class_eval(&block) if block
  end
end

assert('Module#class_variable_defined?', '15.2.2.4.16') do
  class Test4ClassVariableDefined
    @@cv = 99
  end

  assert_true Test4ClassVariableDefined.class_variable_defined?(:@@cv)
  assert_false Test4ClassVariableDefined.class_variable_defined?(:@@noexisting)
  assert_raise(NameError) { Test4ClassVariableDefined.class_variable_defined?("@@2") }
end

assert('Module#class_variable_get', '15.2.2.4.17') do
  class Test4ClassVariableGet
    @@cv = 99
  end

  assert_equal 99, Test4ClassVariableGet.class_variable_get(:@@cv)
  assert_raise(NameError) { Test4ClassVariableGet.class_variable_get(:@@a) }
  %w[@@a? @@! @a a].each do |n|
    assert_raise(NameError) { Test4ClassVariableGet.class_variable_get(n) }
  end
end

assert('Module#class_variable_set', '15.2.2.4.18') do
  class Test4ClassVariableSet
    @@foo = 100
    def foo
      @@foo
    end
  end
  assert_equal 99, Test4ClassVariableSet.class_variable_set(:@@cv, 99)
  assert_equal 101, Test4ClassVariableSet.class_variable_set(:@@foo, 101)
  assert_true Test4ClassVariableSet.class_variables.include? :@@cv
  assert_equal 99, Test4ClassVariableSet.class_variable_get(:@@cv)
  assert_equal 101, Test4ClassVariableSet.new.foo
  %w[@@ @@1 @@x= @x @ x 1].each do |n|
    assert_raise(NameError) { Test4ClassVariableSet.class_variable_set(n, 1) }
  end

  m = Module.new.freeze
  assert_raise(FrozenError) { m.class_variable_set(:@@cv, 1) }

  parent = Class.new{ class_variable_set(:@@a, nil) }.freeze
  child = Class.new(parent)
  assert_raise(FrozenError) { child.class_variable_set(:@@a, 1) }
end

assert('Module#class_variables', '15.2.2.4.19') do
  class Test4ClassVariables1
    @@var1 = 1
  end
  class Test4ClassVariables2 < Test4ClassVariables1
    @@var2 = 2
  end

  assert_equal [:@@var1], Test4ClassVariables1.class_variables
  assert_equal [:@@var2, :@@var1], Test4ClassVariables2.class_variables
end

assert('Module#constants', '15.2.2.4.24') do
  $n = []
  module TestA
    C = 1
  end
  class TestB
    include TestA
    C2 = 1
    $n = constants.sort
  end

  assert_equal [ :C ], TestA.constants
  assert_equal [ :C, :C2 ], $n
end

assert('Module#included_modules', '15.2.2.4.30') do
  module Test4includedModules
  end
  module Test4includedModules2
    include Test4includedModules
  end
  r = Test4includedModules2.included_modules

  assert_equal Array, r.class
  assert_true r.include?(Test4includedModules)
end

assert('Module#instance_methods', '15.2.2.4.33') do
  module Test4InstanceMethodsA
    def method1()  end
  end
  class Test4InstanceMethodsB
    def method2()  end
  end
  class Test4InstanceMethodsC < Test4InstanceMethodsB
    def method3()  end
  end

  r = Test4InstanceMethodsC.instance_methods(true)

  assert_equal [:method1], Test4InstanceMethodsA.instance_methods
  assert_equal [:method2], Test4InstanceMethodsB.instance_methods(false)
  assert_equal [:method3], Test4InstanceMethodsC.instance_methods(false)
  assert_equal Array, r.class
  assert_true r.include?(:method3)
  assert_true r.include?(:method2)
end

assert 'Module#prepend #instance_methods(false)' do
  bug6660 = '[ruby-dev:45863]'
  assert_equal([:m1], Class.new{ prepend Module.new; def m1; end }.instance_methods(false), bug6660)
  assert_equal([:m1], Class.new(Class.new{def m2;end}){ prepend Module.new; def m1; end }.instance_methods(false), bug6660)
end

assert('Module#remove_class_variable', '15.2.2.4.39') do
  class Test4RemoveClassVariable
    @@cv = 99
  end

  assert_equal 99, Test4RemoveClassVariable.remove_class_variable(:@@cv)
  assert_false Test4RemoveClassVariable.class_variables.include? :@@cv
  assert_raise(NameError) do
    Test4RemoveClassVariable.remove_class_variable(:@@cv)
  end
  assert_raise(NameError) do
    Test4RemoveClassVariable.remove_class_variable(:@v)
  end
  assert_raise(FrozenError) do
    Test4RemoveClassVariable.freeze.remove_class_variable(:@@cv)
  end
end

assert('Module#remove_method', '15.2.2.4.41') do
  module Test4RemoveMethod
    class Parent
      def hello
      end
    end

    class Child < Parent
      def hello
      end
    end
  end

  klass = Test4RemoveMethod::Child
  assert_same klass, klass.class_eval{ remove_method :hello }
  assert_true klass.instance_methods.include? :hello
  assert_false klass.instance_methods(false).include? :hello
  assert_raise(FrozenError) { klass.freeze.remove_method :m }
end

assert('Module.nesting', '15.2.2.2.2') do
  module Test4ModuleNesting
    module Test4ModuleNesting2
      assert_equal [Test4ModuleNesting2, Test4ModuleNesting],
                   Module.nesting
    end
  end
  module Test4ModuleNesting::Test4ModuleNesting2
    assert_equal [Test4ModuleNesting::Test4ModuleNesting2], Module.nesting
  end
end

assert('Moduler#prepend + #instance_methods') do
  bug6655 = '[ruby-core:45915]'
  assert_equal(Object.instance_methods, Class.new {prepend Module.new}.instance_methods, bug6655)
end

assert 'Module#prepend + #singleton_methods' do
  o = Object.new
  o.singleton_class.class_eval {prepend Module.new}
  assert_equal([], o.singleton_methods)
end

assert 'Module#prepend + #remove_method' do
  c = Class.new do
    prepend Module.new { def foo; end }
  end
  assert_raise(NameError) do
    c.class_eval do
      remove_method(:foo)
    end
  end
  c.class_eval do
    def foo; end
  end
  removed = nil
  c.singleton_class.class_eval do
    define_method(:method_removed) {|id| removed = id}
  end
  assert_nothing_raised('[Bug #7843]') do
    c.class_eval do
      remove_method(:foo)
    end
  end
  assert_equal(:foo, removed)
end

assert 'Module#prepend + #included_modules' do
  bug8025 = '[ruby-core:53158] [Bug #8025]'
  mixin = labeled_module("mixin")
  c = labeled_module("c") {prepend mixin}
  im = c.included_modules
  assert_not_include(im, c, bug8025)
  assert_include(im, mixin, bug8025)
  c1 = labeled_class("c1") {prepend mixin}
  c2 = labeled_class("c2", c1)
  im = c2.included_modules
  assert_not_include(im, c1, bug8025)
  assert_not_include(im, c2, bug8025)
  assert_include(im, mixin, bug8025)
end

assert("remove_method doesn't segfault if the passed in argument isn't a symbol") do
  klass = Class.new
  assert_raise(TypeError) { klass.remove_method nil }
  assert_raise(TypeError) { klass.remove_method 123 }
  assert_raise(TypeError) { klass.remove_method 1.23 }
  assert_raise(NameError) { klass.remove_method "hello" }
  assert_raise(TypeError) { klass.remove_method Class.new }
end

assert('alias_method and remove_method') do
  begin
    Integer.alias_method :to_s_, :to_s
    Integer.remove_method :to_s

    assert_nothing_raised do
      # segfaults if mrb_cptr is used
      1.to_s
    end
  ensure
    Integer.alias_method :to_s, :to_s_
    Integer.remove_method :to_s_
  end
end
