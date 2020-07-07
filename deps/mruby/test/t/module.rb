##
# Module ISO Test

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

def assert_uninitialized_const(&block)
  assert_raise_with_message_pattern(NameError, "uninitialized constant *", &block)
end

def assert_wrong_const_name(&block)
  assert_raise_with_message_pattern(NameError, "wrong constant name *", &block)
end

assert('Module', '15.2.2') do
  assert_equal Class, Module.class
end

assert('Module#alias_method', '15.2.2.4.8') do
  cls = Class.new do
    def foo
      "FOO"
    end
  end

  assert_same(cls, cls.alias_method(:bar, :foo))
  assert_equal("FOO", cls.new.bar)
end

# TODO not implemented ATM assert('Module.constants', '15.2.2.3.1') do

assert('Module#ancestors', '15.2.2.4.9') do
  class Test4ModuleAncestors
  end
  r = String.ancestors

  assert_equal Array, r.class
  assert_true r.include?(String)
  assert_true r.include?(Object)
end

assert('Module#append_features', '15.2.2.4.10') do
  module Test4AppendFeatures
    def self.append_features(mod)
      Test4AppendFeatures2.const_set(:Const4AppendFeatures2, mod)
    end
  end
  module Test4AppendFeatures2
    include Test4AppendFeatures
  end

  assert_equal Test4AppendFeatures2, Test4AppendFeatures2.const_get(:Const4AppendFeatures2)
  assert_raise(FrozenError) { Module.new.append_features Class.new.freeze }
end

assert('Module#attr NameError') do
  %w[
    foo?
    @foo
    @@foo
    $foo
  ].each do |name|
    module NameTest; end

    assert_raise(NameError) do
      NameTest.module_eval { attr_reader name.to_sym }
    end

    assert_raise(NameError) do
      NameTest.module_eval { attr_writer name.to_sym }
    end

    assert_raise(NameError) do
      NameTest.module_eval { attr name.to_sym }
    end

    assert_raise(NameError) do
      NameTest.module_eval { attr_accessor name.to_sym }
    end
  end

end

assert('Module#attr', '15.2.2.4.11') do
  class AttrTest
    class << self
      attr :cattr
      def cattr_val=(val)
        @cattr = val
      end
    end
    attr :iattr
    def iattr_val=(val)
      @iattr = val
    end
  end

  test = AttrTest.new
  assert_true AttrTest.respond_to?(:cattr)
  assert_true test.respond_to?(:iattr)

  assert_false AttrTest.respond_to?(:cattr=)
  assert_false test.respond_to?(:iattr=)

  test.iattr_val = 'test'
  assert_equal 'test', test.iattr

  AttrTest.cattr_val = 'test'
  assert_equal 'test', AttrTest.cattr
end

assert('Module#attr_accessor', '15.2.2.4.12') do
  class AttrTestAccessor
    class << self
      attr_accessor :cattr
    end
    attr_accessor :iattr, 'iattr2'
  end

  attr_instance = AttrTestAccessor.new
  assert_true AttrTestAccessor.respond_to?(:cattr=)
  assert_true attr_instance.respond_to?(:iattr=)
  assert_true attr_instance.respond_to?(:iattr2=)
  assert_true AttrTestAccessor.respond_to?(:cattr)
  assert_true attr_instance.respond_to?(:iattr)
  assert_true attr_instance.respond_to?(:iattr2)

  attr_instance.iattr = 'test'
  assert_equal 'test', attr_instance.iattr

  AttrTestAccessor.cattr = 'test'
  assert_equal 'test', AttrTestAccessor.cattr
end

assert('Module#attr_reader', '15.2.2.4.13') do
  class AttrTestReader
    class << self
      attr_reader :cattr
      def cattr_val=(val)
        @cattr = val
      end
    end
    attr_reader :iattr, 'iattr2'
    def iattr_val=(val)
      @iattr = val
    end
  end

  attr_instance = AttrTestReader.new
  assert_true AttrTestReader.respond_to?(:cattr)
  assert_true attr_instance.respond_to?(:iattr)
  assert_true attr_instance.respond_to?(:iattr2)

  assert_false AttrTestReader.respond_to?(:cattr=)
  assert_false attr_instance.respond_to?(:iattr=)
  assert_false attr_instance.respond_to?(:iattr2=)

  attr_instance.iattr_val = 'test'
  assert_equal 'test', attr_instance.iattr

  AttrTestReader.cattr_val = 'test'
  assert_equal 'test', AttrTestReader.cattr
end

assert('Module#attr_writer', '15.2.2.4.14') do
  class AttrTestWriter
    class << self
      attr_writer :cattr
      def cattr_val
        @cattr
      end
    end
    attr_writer :iattr, 'iattr2'
    def iattr_val
      @iattr
    end
  end

  attr_instance = AttrTestWriter.new
  assert_true AttrTestWriter.respond_to?(:cattr=)
  assert_true attr_instance.respond_to?(:iattr=)
  assert_true attr_instance.respond_to?(:iattr2=)

  assert_false AttrTestWriter.respond_to?(:cattr)
  assert_false attr_instance.respond_to?(:iattr)
  assert_false attr_instance.respond_to?(:iattr2)

  attr_instance.iattr = 'test'
  assert_equal 'test', attr_instance.iattr_val

  AttrTestWriter.cattr = 'test'
  assert_equal 'test', AttrTestWriter.cattr_val
end

assert('Module#class_eval', '15.2.2.4.15') do
  class Test4ClassEval
    @a = 11
    @b = 12
  end
  Test4ClassEval.class_eval do
    def method1
    end
  end
  assert_equal 11, Test4ClassEval.class_eval{ @a }
  assert_equal 12, Test4ClassEval.class_eval{ @b }
  assert_equal true, Test4ClassEval.new.respond_to?(:method1)
end

assert('Module#const_defined?', '15.2.2.4.20') do
  module Test4ConstDefined
    Const4Test4ConstDefined = true
  end

  assert_true Test4ConstDefined.const_defined?(:Const4Test4ConstDefined)
  assert_false Test4ConstDefined.const_defined?(:NotExisting)
  assert_wrong_const_name{ Test4ConstDefined.const_defined?(:wrong_name) }
end

assert('Module#const_get', '15.2.2.4.21') do
  module Test4ConstGet
    Const4Test4ConstGet = 42
  end

  assert_equal 42, Test4ConstGet.const_get(:Const4Test4ConstGet)
  assert_equal 42, Test4ConstGet.const_get("Const4Test4ConstGet")
  assert_equal 42, Object.const_get("Test4ConstGet::Const4Test4ConstGet")

  assert_raise(TypeError){ Test4ConstGet.const_get(123) }
  assert_uninitialized_const{ Test4ConstGet.const_get(:I_DO_NOT_EXIST) }
  assert_uninitialized_const{ Test4ConstGet.const_get("I_DO_NOT_EXIST::ME_NEITHER") }
  assert_wrong_const_name{ Test4ConstGet.const_get(:wrong_name) }
end

assert('Module#const_set', '15.2.2.4.23') do
  module Test4ConstSet
    Const4Test4ConstSet = 42
  end

  assert_equal 23, Test4ConstSet.const_set(:Const4Test4ConstSet, 23)
  assert_equal 23, Test4ConstSet.const_get(:Const4Test4ConstSet)
  ["", "wrongNAME", "Wrong-Name"].each do |n|
    assert_wrong_const_name { Test4ConstSet.const_set(n, 1) }
  end
end

assert('Module#remove_const', '15.2.2.4.40') do
  module Test4RemoveConst
    ExistingConst = 23
  end

  assert_equal 23, Test4RemoveConst.remove_const(:ExistingConst)
  assert_false Test4RemoveConst.const_defined?(:ExistingConst)
  assert_raise_with_message_pattern(NameError, "constant * not defined") do
    Test4RemoveConst.remove_const(:NonExistingConst)
  end
  %i[x X!].each do |n|
    assert_wrong_const_name { Test4RemoveConst.remove_const(n) }
  end
  assert_raise(FrozenError) { Test4RemoveConst.freeze.remove_const(:A) }
end

assert('Module#const_missing', '15.2.2.4.22') do
  module Test4ConstMissing
    def self.const_missing(sym)
      42 # the answer to everything
    end
  end

  assert_equal 42, Test4ConstMissing.const_get(:ConstDoesntExist)
end

assert('Module#extend_object', '15.2.2.4.25') do
  cls = Class.new
  mod = Module.new { def foo; end }
  a = cls.new
  b = cls.new
  mod.extend_object(b)
  assert_false a.respond_to?(:foo)
  assert_true b.respond_to?(:foo)
  assert_raise(FrozenError) { mod.extend_object(cls.new.freeze) }
  assert_raise(FrozenError, TypeError) { mod.extend_object(1) }
end

assert('Module#include', '15.2.2.4.27') do
  module Test4Include
    Const4Include = 42
  end
  module Test4Include2
    @include_result = include Test4Include
    class << self
      attr_reader :include_result
    end
  end

  assert_equal 42, Test4Include2.const_get(:Const4Include)
  assert_equal Test4Include2, Test4Include2.include_result
  assert_raise(FrozenError) { Module.new.freeze.include Test4Include }
end

assert('Module#include?', '15.2.2.4.28') do
  module Test4IncludeP
  end
  class Test4IncludeP2
    include Test4IncludeP
  end
  class Test4IncludeP3 < Test4IncludeP2
  end

  assert_true Test4IncludeP2.include?(Test4IncludeP)
  assert_true Test4IncludeP3.include?(Test4IncludeP)
  assert_false Test4IncludeP.include?(Test4IncludeP)
end

assert('Module#included', '15.2.2.4.29') do
  module Test4Included
    Const4Included = 42
    def self.included mod
      Test4Included.const_set(:Const4Included2, mod)
    end
  end
  module Test4Included2
    include Test4Included
  end

  assert_equal 42, Test4Included2.const_get(:Const4Included)
  assert_equal Test4Included2, Test4Included2.const_get(:Const4Included2)
end

assert('Module#initialize', '15.2.2.4.31') do
  assert_kind_of Module, Module.new
  mod = Module.new { def hello; "hello"; end }
  cls = Class.new{include mod}
  assert_true cls.new.respond_to?(:hello)
  a = nil
  mod = Module.new { |m| a = m }
  assert_equal mod, a
end

assert('Module#method_defined?', '15.2.2.4.34') do
  module Test4MethodDefined
    module A
      def method1()  end
    end

    class B
      def method2()  end
    end

    class C < B
      include A
      def method3()  end
    end
  end

  assert_true Test4MethodDefined::A.method_defined? :method1
  assert_true Test4MethodDefined::C.method_defined? :method1
  assert_true Test4MethodDefined::C.method_defined? "method2"
  assert_true Test4MethodDefined::C.method_defined? "method3"
  assert_false Test4MethodDefined::C.method_defined? "method4"
end

assert('Module#module_eval', '15.2.2.4.35') do
  module Test4ModuleEval
    @a = 11
    @b = 12
  end

  assert_equal 11, Test4ModuleEval.module_eval{ @a }
  assert_equal 12, Test4ModuleEval.module_eval{ @b }
end

assert('Module#undef_method', '15.2.2.4.42') do
  module Test4UndefMethod
    class Parent
      def hello
      end
     end

     class Child < Parent
      def hello
      end
     end

     class GrandChild < Child
     end
  end
  Test4UndefMethod::Child.class_eval{ undef_method :hello }

  assert_true Test4UndefMethod::Parent.new.respond_to?(:hello)
  assert_false Test4UndefMethod::Child.new.respond_to?(:hello)
  assert_false Test4UndefMethod::GrandChild.new.respond_to?(:hello)
end

# Not ISO specified

assert('Module#dup') do
  module TestModuleDup
    @@cvar = :cvar
    class << self
      attr_accessor :cattr
      def cmeth; :cmeth end
    end
    def cvar; @@cvar end
    def imeth; :imeth end
    self.cattr = :cattr
  end

  m = TestModuleDup.dup
  o = Object.include(m).new
  assert_equal(:cattr, m.cattr)
  assert_equal(:cmeth, m.cmeth)
  assert_equal(:cvar, o.cvar)
  assert_equal(:imeth, o.imeth)
  assert_match("#<Module:0x*>", m.to_s)
  assert_not_predicate(m, :frozen?)
  assert_not_predicate(TestModuleDup.freeze.dup, :frozen?)
end

assert('Module#define_method') do
  c = Class.new {
    define_method(:m1) { :ok }
    define_method(:m2, Proc.new { :ok })
  }
  assert_equal c.new.m1, :ok
  assert_equal c.new.m2, :ok
  assert_raise(TypeError) do
    Class.new { define_method(:n1, nil) }
  end
end

assert 'Module#prepend_features' do
  mod = Module.new { def m; :mod end }
  cls = Class.new { def m; :cls end }
  assert_equal :cls, cls.new.m
  mod.prepend_features(cls)
  assert_equal :mod, cls.new.m
  assert_raise(FrozenError) { Module.new.prepend_features(Class.new.freeze) }
end

# @!group prepend
  assert('Module#prepend') do
    module M0
      def m1; [:M0] end
    end
    module M1
      def m1; [:M1, super, :M1] end
    end
    module M2
      def m1; [:M2, super, :M2] end
    end
    M3 = Module.new do
      def m1; [:M3, super, :M3] end
    end
    module M4
      def m1; [:M4, super, :M4] end
    end

    class P0
      include M0
      prepend M1
      def m1; [:C0, super, :C0] end
    end
    class P1 < P0
      prepend M2, M3
      include M4
      def m1; [:C1, super, :C1] end
    end

    obj = P1.new
    expected = [:M2,[:M3,[:C1,[:M4,[:M1,[:C0,[:M0],:C0],:M1],:M4],:C1],:M3],:M2]
    assert_equal(expected, obj.m1)
  end

  assert('Module#prepend result') do
    module TestPrepended; end
    module TestPrependResult
      @prepend_result = prepend TestPrepended
      class << self
        attr_reader :prepend_result
      end
    end

    assert_equal TestPrependResult, TestPrependResult.prepend_result
  end

  # mruby shouldn't be affected by this since there is
  # no visibility control (yet)
  assert('Module#prepend public') do
    assert_nothing_raised('ruby/ruby #8846') do
      Class.new.prepend(Module.new)
    end
  end

  assert('Module#prepend inheritance') do
    bug6654 = '[ruby-core:45914]'
    a = labeled_module('a')
    b = labeled_module('b') { include a }
    c = labeled_module('c') { prepend b }

    #assert bug6654 do
      # the Module#< operator should be used here instead, but we don't have it
      assert_include(c.ancestors, a)
      assert_include(c.ancestors, b)
    #end

    bug8357 = '[ruby-core:54736] [Bug #8357]'
    b = labeled_module('b') { prepend a }
    c = labeled_class('c') { include b }

    #assert bug8357 do
      # the Module#< operator should be used here instead, but we don't have it
      assert_include(c.ancestors, a)
      assert_include(c.ancestors, b)
    #end

    bug8357 = '[ruby-core:54742] [Bug #8357]'
    assert_kind_of(b, c.new, bug8357)
  end

  assert 'Module#prepend + Class#ancestors' do
    bug6658 = '[ruby-core:45919]'
    m = labeled_module("m")
    c = labeled_class("c") {prepend m}
    assert_equal([m, c], c.ancestors[0, 2], bug6658)

    bug6662 = '[ruby-dev:45868]'
    c2 = labeled_class("c2", c)
    anc = c2.ancestors
    assert_equal([c2, m, c, Object], anc[0..anc.index(Object)], bug6662)
  end

  assert 'Module#prepend + Module#ancestors' do
    bug6659 = '[ruby-dev:45861]'
    m0 = labeled_module("m0") { def x; [:m0, *super] end }
    m1 = labeled_module("m1") { def x; [:m1, *super] end; prepend m0 }
    m2 = labeled_module("m2") { def x; [:m2, *super] end; prepend m1 }
    c0 = labeled_class("c0") { def x; [:c0] end }
    c1 = labeled_class("c1") { def x; [:c1] end; prepend m2 }
    c2 = labeled_class("c2", c0) { def x; [:c2, *super] end; include m2 }
    #
    assert_equal([m0, m1], m1.ancestors, bug6659)
    #
    bug6662 = '[ruby-dev:45868]'
    assert_equal([m0, m1, m2], m2.ancestors, bug6662)
    assert_equal([m0, m1, m2, c1], c1.ancestors[0, 4], bug6662)
    assert_equal([:m0, :m1, :m2, :c1], c1.new.x)
    assert_equal([c2, m0, m1, m2, c0], c2.ancestors[0, 5], bug6662)
    assert_equal([:c2, :m0, :m1, :m2, :c0], c2.new.x)
    #
    m3 = labeled_module("m3") { include m1; prepend m1 }
    assert_equal([m3, m0, m1], m3.ancestors)
    m3 = labeled_module("m3") { prepend m1; include m1 }
    assert_equal([m0, m1, m3], m3.ancestors)
    m3 = labeled_module("m3") { prepend m1; prepend m1 }
    assert_equal([m0, m1, m3], m3.ancestors)
    m3 = labeled_module("m3") { include m1; include m1 }
    assert_equal([m3, m0, m1], m3.ancestors)
  end

  assert 'cyclic Module#prepend' do
    bug7841 = '[ruby-core:52205] [Bug #7841]'
    m1 = Module.new
    m2 = Module.new
    m1.instance_eval { prepend(m2) }
    assert_raise(ArgumentError, bug7841) do
      m2.instance_eval { prepend(m1) }
    end
  end

  # these assertions will not run without a #assert_separately method
  #assert 'test_prepend_optmethod' do
  #  bug7983 = '[ruby-dev:47124] [Bug #7983]'
  #  assert_separately [], %{
  #    module M
  #      def /(other)
  #        to_f / other
  #      end
  #    end
  #    Fixnum.send(:prepend, M)
  #    assert_equal(0.5, 1 / 2, "#{bug7983}")
  #  }
  #  assert_equal(0, 1 / 2)
  #end

  # mruby has no visibility control
  # assert 'Module#prepend visibility' do
  #   bug8005 = '[ruby-core:53106] [Bug #8005]'
  #   c = Class.new do
  #     prepend Module.new {}
  #     def foo() end
  #     protected :foo
  #   end
  #   a = c.new
  #   assert_true a.respond_to?(:foo), bug8005
  #   assert_nothing_raised(bug8005) {a.send :foo}
  # end

  # mruby has no visibility control
  # assert 'Module#prepend inherited visibility' do
  #   bug8238 = '[ruby-core:54105] [Bug #8238]'
  #   module Test4PrependVisibilityInherited
  #     class A
  #       def foo() A; end
  #       private :foo
  #     end
  #     class B < A
  #       public :foo
  #       prepend Module.new
  #     end
  #   end
  #   assert_equal(Test4PrependVisibilityInherited::A, Test4PrependVisibilityInherited::B.new.foo, "#{bug8238}")
  # end

  # assert 'Module#prepend super in alias' do
  #   skip "super does not currently work in aliased methods"
  #   bug7842 = '[Bug #7842]'

  #   p = labeled_module("P") do
  #     def m; "P"+super; end
  #   end

  #   a = labeled_class("A") do
  #     def m; "A"; end
  #   end

  #   b = labeled_class("B", a) do
  #     def m; "B"+super; end
  #     alias m2 m
  #     prepend p
  #     alias m3 m
  #   end

  #   assert_nothing_raised do
  #     assert_equal("BA", b.new.m2, bug7842)
  #   end

  #   assert_nothing_raised do
  #     assert_equal("PBA", b.new.m3, bug7842)
  #   end
  # end

  assert 'Module#prepend each class' do
    m = labeled_module("M")
    c1 = labeled_class("C1") {prepend m}
    c2 = labeled_class("C2", c1) {prepend m}
    assert_equal([m, c2, m, c1], c2.ancestors[0, 4], "should be able to prepend each class")
  end

  assert 'Module#prepend no duplication' do
    m = labeled_module("M")
    c = labeled_class("C") {prepend m; prepend m}
    assert_equal([m, c], c.ancestors[0, 2], "should never duplicate")
  end

  assert 'Module#prepend in superclass' do
    m = labeled_module("M")
    c1 = labeled_class("C1")
    c2 = labeled_class("C2", c1) {prepend m}
    c1.class_eval {prepend m}
    assert_equal([m, c2, m, c1], c2.ancestors[0, 4], "should accesisble prepended module in superclass")
  end

  # requires #assert_separately
  #assert 'Module#prepend call super' do
  #  assert_separately([], <<-'end;') #do
  #    bug10847 = '[ruby-core:68093] [Bug #10847]'
  #    module M; end
  #    Float.prepend M
  #    assert_nothing_raised(SystemStackError, bug10847) do
  #      0.3.numerator
  #    end
  #  end;
  #end

  assert 'Module#prepend to frozen class' do
    assert_raise(FrozenError) { Class.new.freeze.prepend Module.new }
  end
# @!endgroup prepend

assert('Module#to_s') do
  module Outer
    class Inner; end
    const_set :SetInner, Class.new
  end

  assert_equal 'Outer', Outer.to_s
  assert_equal 'Outer::Inner', Outer::Inner.to_s
  assert_equal 'Outer::SetInner', Outer::SetInner.to_s

  outer = Module.new do
    const_set :SetInner, Class.new
  end
  Object.const_set :SetOuter, outer

  assert_equal 'SetOuter', SetOuter.to_s
  assert_equal 'SetOuter::SetInner', SetOuter::SetInner.to_s

  assert_match "#<Module:0x*>", Module.new.to_s
  assert_match "#<Class:0x*>", Class.new.to_s

  assert_equal "FrozenClassToS", (FrozenClassToS = Class.new.freeze).to_s
  assert_equal "Outer::A", (Outer::A = Module.new.freeze).to_s
  assert_match "#<Module:0x*>::A", (Module.new::A = Class.new.freeze).to_s
end

assert('Module#inspect') do
  module Test4to_sModules
  end

  assert_equal 'Test4to_sModules', Test4to_sModules.inspect
end

assert('Issue 1467') do
  module M1
    def initialize()
      super()
    end
  end

  class C1
    include M1
     def initialize()
       super()
     end
  end

  class C2
    include M1
  end

  assert_kind_of(M1, C1.new)
  assert_kind_of(M1, C2.new)
end

assert('clone Module') do
  module M1
    def foo
      true
    end
  end

  class B
    include M1.clone
  end

  assert_true(B.new.foo)
end

assert('Module#module_function') do
  module M
    def modfunc; end
    module_function :modfunc
  end

  assert_true M.respond_to?(:modfunc)
end

assert('module with non-class/module outer raises TypeError') do
  assert_raise(TypeError) { module 0::M1 end }
  assert_raise(TypeError) { module []::M2 end }
end

assert('module to return the last value') do
  m = module M; :m end
  assert_equal(m, :m)
end

assert('module to return nil if body is empty') do
  assert_nil(module M end)
end

assert('get constant of parent module in singleton class; issue #3568') do
  actual = module GetConstantInSingletonTest
    EXPECTED = "value"
    class << self
      EXPECTED
    end
  end

  assert_equal("value", actual)
end
