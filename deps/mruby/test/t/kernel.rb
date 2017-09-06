##
# Kernel ISO Test

assert('Kernel', '15.3.1') do
  assert_equal Module, Kernel.class
end

assert('Kernel.block_given?', '15.3.1.2.2') do
  def bg_try(&b)
    if Kernel.block_given?
      yield
    else
      "no block"
    end
  end

  assert_false Kernel.block_given?
  # test without block
  assert_equal "no block", bg_try
  # test with block
  assert_equal "block" do
    bg_try { "block" }
  end
  # test with block
  assert_equal "block" do
    bg_try do
      "block"
    end
  end
end

# Kernel.eval is provided by the mruby-gem mrbgem. '15.3.1.2.3'

assert('Kernel.global_variables', '15.3.1.2.4') do
  assert_equal Array, Kernel.global_variables.class
end

assert('Kernel.iterator?', '15.3.1.2.5') do
  assert_false Kernel.iterator?
end

assert('Kernel.lambda', '15.3.1.2.6') do
  l = Kernel.lambda do
    true
  end

  m = Kernel.lambda(&l)

  assert_true l.call
  assert_equal Proc, l.class
  assert_true m.call
  assert_equal Proc, m.class
end

# Not implemented at the moment
#assert('Kernel.local_variables', '15.3.1.2.7') do
#  Kernel.local_variables.class == Array
#end

assert('Kernel.loop', '15.3.1.2.8') do
  i = 0

  Kernel.loop do
    i += 1
    break if i == 100
  end

  assert_equal 100, i
end

assert('Kernel.p', '15.3.1.2.9') do
  # TODO search for a way to test p to stdio
  assert_true true
end

assert('Kernel.print', '15.3.1.2.10') do
  # TODO search for a way to test print to stdio
  assert_true true
end

assert('Kernel.puts', '15.3.1.2.11') do
  # TODO search for a way to test puts to stdio
  assert_true true
end

assert('Kernel.raise', '15.3.1.2.12') do
  assert_raise RuntimeError do
    Kernel.raise
  end

  assert_raise RuntimeError do
    Kernel.raise RuntimeError.new
  end
end

assert('Kernel#__id__', '15.3.1.3.3') do
  assert_equal Fixnum, __id__.class
end

assert('Kernel#__send__', '15.3.1.3.4') do
  # test with block
  l = __send__(:lambda) do
    true
  end

  assert_true l.call
  assert_equal Proc, l.class
  # test with argument
  assert_true __send__(:respond_to?, :nil?)
  # test without argument and without block
  assert_equal  Array, __send__(:public_methods).class
end

assert('Kernel#block_given?', '15.3.1.3.6') do
  def bg_try(&b)
    if block_given?
      yield
    else
      "no block"
    end
  end

  assert_false block_given?
  assert_equal "no block", bg_try
  assert_equal "block" do
    bg_try { "block" }
  end
  assert_equal "block" do
    bg_try do
      "block"
    end
  end
end

assert('Kernel#class', '15.3.1.3.7') do
  assert_equal Module, Kernel.class
end

assert('Kernel#clone', '15.3.1.3.8') do
  class KernelCloneTest
    def initialize
      @v = 0
    end

    def get
      @v
    end

    def set(v)
      @v = v
    end
  end

  a = KernelCloneTest.new
  a.set(1)
  b = a.clone

  def a.test
  end
  a.set(2)
  c = a.clone

  immutables = [ 1, :foo, true, false, nil ]
  error_count = 0
  immutables.each do |i|
    begin
      i.clone
    rescue TypeError
      error_count += 1
    end
  end

  assert_equal 2, a.get
  assert_equal 1, b.get
  assert_equal 2, c.get
  assert_true a.respond_to?(:test)
  assert_false b.respond_to?(:test)
  assert_true c.respond_to?(:test)
end

assert('Kernel#dup', '15.3.1.3.9') do
  class KernelDupTest
    def initialize
      @v = 0
    end

    def get
      @v
    end

    def set(v)
      @v = v
    end
  end

  a = KernelDupTest.new
  a.set(1)
  b = a.dup

  def a.test
  end
  a.set(2)
  c = a.dup

  immutables = [ 1, :foo, true, false, nil ]
  error_count = 0
  immutables.each do |i|
    begin
      i.dup
    rescue TypeError
      error_count += 1
    end
  end

  assert_equal immutables.size, error_count
  assert_equal 2, a.get
  assert_equal 1, b.get
  assert_equal 2, c.get
  assert_true a.respond_to?(:test)
  assert_false b.respond_to?(:test)
  assert_false c.respond_to?(:test)
end

assert('Kernel#dup class') do
  assert_nothing_raised do
    Array.dup.new(200)
    Range.dup.new(2, 3)
    String.dup.new("a"*50)
  end
end

# Kernel#eval is provided by mruby-eval mrbgem '15.3.1.3.12'

assert('Kernel#extend', '15.3.1.3.13') do
  class Test4ExtendClass
  end

  module Test4ExtendModule
    def test_method; end
  end

  a = Test4ExtendClass.new
  a.extend(Test4ExtendModule)
  b = Test4ExtendClass.new

  assert_true a.respond_to?(:test_method)
  assert_false b.respond_to?(:test_method)
end

assert('Kernel#extend works on toplevel', '15.3.1.3.13') do
  module Test4ExtendModule
    def test_method; end
  end
  # This would crash...
  extend(Test4ExtendModule)

  assert_true respond_to?(:test_method)
end

assert('Kernel#freeze') do
  obj = Object.new
  assert_equal obj, obj.freeze
  assert_equal 0, 0.freeze
  assert_equal :a, :a.freeze
end

assert('Kernel#global_variables', '15.3.1.3.14') do
  assert_equal Array, global_variables.class
end

assert('Kernel#hash', '15.3.1.3.15') do
  assert_equal hash, hash
end

assert('Kernel#inspect', '15.3.1.3.17') do
  s = inspect

  assert_equal String, s.class
  assert_equal "main", s
end

assert('Kernel#instance_variable_defined?', '15.3.1.3.20') do
  o = Object.new
  o.instance_variable_set(:@a, 1)

  assert_true o.instance_variable_defined?("@a")
  assert_false o.instance_variable_defined?("@b")
  assert_true o.instance_variable_defined?("@a"[0,2])
  assert_true o.instance_variable_defined?("@abc"[0,2])
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

assert('Kernel#is_a?', '15.3.1.3.24') do
  assert_true is_a?(Kernel)
  assert_false is_a?(Array)

  assert_raise TypeError do
    42.is_a?(42)
  end
end

assert('Kernel#iterator?', '15.3.1.3.25') do
  assert_false iterator?
end

assert('Kernel#kind_of?', '15.3.1.3.26') do
  assert_true kind_of?(Kernel)
  assert_false kind_of?(Array)
end

assert('Kernel#lambda', '15.3.1.3.27') do
  l = lambda do
    true
  end

  m = lambda(&l)

  assert_true l.call
  assert_equal Proc, l.class
  assert_true m.call
  assert_equal Proc, m.class
end

# Not implemented yet
#assert('Kernel#local_variables', '15.3.1.3.28') do
#  local_variables.class == Array
#end

assert('Kernel#loop', '15.3.1.3.29') do
  i = 0

  loop do
    i += 1
    break if i == 100
  end

  assert_equal i, 100
end

assert('Kernel#method_missing', '15.3.1.3.30') do
  class MMTestClass
    def method_missing(sym)
      "A call to #{sym}"
    end
  end
  mm_test = MMTestClass.new
  assert_equal 'A call to no_method_named_this', mm_test.no_method_named_this

  class SuperMMTestClass < MMTestClass
    def no_super_method_named_this
      super
    end
  end
  super_mm_test = SuperMMTestClass.new
  assert_equal 'A call to no_super_method_named_this', super_mm_test.no_super_method_named_this

  class NoSuperMethodTestClass
    def no_super_method_named_this
      super
    end
  end
  no_super_test = NoSuperMethodTestClass.new
  begin
    no_super_test.no_super_method_named_this
  rescue NoMethodError => e
    assert_equal "undefined method 'no_super_method_named_this' for #{no_super_test}", e.message
  end

  a = String.new
  begin
    a.no_method_named_this
  rescue NoMethodError => e
    assert_equal "undefined method 'no_method_named_this' for \"\"", e.message
  end

  class ShortInspectClass
    def inspect
      'An inspect string'
    end
  end
  b = ShortInspectClass.new
  begin
    b.no_method_named_this
  rescue NoMethodError => e
    assert_equal "undefined method 'no_method_named_this' for An inspect string", e.message
  end

  class LongInspectClass
    def inspect
      "A" * 70
    end
  end
  c = LongInspectClass.new
  begin
    c.no_method_named_this
  rescue NoMethodError => e
    assert_equal "undefined method 'no_method_named_this' for #{c}", e.message
  end

  class NoInspectClass
    undef inspect
  end
  d = NoInspectClass.new
  begin
    d.no_method_named_this
  rescue NoMethodError => e
    assert_equal "undefined method 'no_method_named_this' for #{d}", e.message
  end
end

assert('Kernel#methods', '15.3.1.3.31') do
  assert_equal Array, methods.class
end

assert('Kernel#nil?', '15.3.1.3.32') do
  assert_false nil?
end

assert('Kernel#object_id', '15.3.1.3.33') do
  a = ""
  b = ""
  assert_not_equal a.object_id, b.object_id

  assert_kind_of Numeric, object_id
  assert_kind_of Numeric, "".object_id
  assert_kind_of Numeric, true.object_id
  assert_kind_of Numeric, false.object_id
  assert_kind_of Numeric, nil.object_id
  assert_kind_of Numeric, :no.object_id
  assert_kind_of Numeric, 1.object_id
  assert_kind_of Numeric, 1.0.object_id
end

# Kernel#p is defined in mruby-print mrbgem. '15.3.1.3.34'

# Kernel#print is defined in mruby-print mrbgem. '15.3.1.3.35'

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

# Kernel#puts is defined in mruby-print mrbgem. '15.3.1.3.39'

assert('Kernel#raise', '15.3.1.3.40') do
  assert_raise RuntimeError do
    raise
  end

  assert_raise RuntimeError do
    raise RuntimeError.new
  end
end

assert('Kernel#remove_instance_variable', '15.3.1.3.41') do
  class Test4RemoveInstanceVar
    attr_reader :var
    def initialize
      @var = 99
    end
    def remove
      remove_instance_variable(:@var)
    end
  end

  tri = Test4RemoveInstanceVar.new
  assert_equal 99, tri.var
  tri.remove
  assert_equal nil, tri.var
  assert_raise NameError do
    tri.remove
  end
end

# Kernel#require is defined in mruby-require. '15.3.1.3.42'

assert('Kernel#respond_to?', '15.3.1.3.43') do
  class Test4RespondTo
    def valid_method; end

    def test_method; end
    undef test_method
  end

  assert_raise TypeError do
    Test4RespondTo.new.respond_to?(1)
  end

  assert_raise ArgumentError do
    Test4RespondTo.new.respond_to?
  end

  assert_raise ArgumentError do
    Test4RespondTo.new.respond_to? :a, true, :aa
  end

  assert_true respond_to?(:nil?)
  assert_true Test4RespondTo.new.respond_to?(:valid_method)
  assert_true Test4RespondTo.new.respond_to?('valid_method')
  assert_false Test4RespondTo.new.respond_to?(:test_method)
end

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
  assert_equal send(:public_methods).class, Array
end

assert('Kernel#singleton_methods', '15.3.1.3.45') do
  assert_equal singleton_methods.class, Array
end

assert('Kernel#to_s', '15.3.1.3.46') do
  assert_equal to_s.class, String
end

assert('Kernel#to_s on primitives') do
  begin
    Fixnum.alias_method :to_s_, :to_s
    Fixnum.remove_method :to_s

    assert_nothing_raised do
      # segfaults if mrb_cptr is used
      1.to_s
    end
  ensure
    Fixnum.alias_method :to_s, :to_s_
    Fixnum.remove_method :to_s_
  end
end

assert('Kernel.local_variables', '15.3.1.2.7') do
  a, b = 0, 1
  a += b

  vars = Kernel.local_variables.sort
  assert_equal [:a, :b, :vars], vars

  assert_equal [:a, :b, :c, :vars], Proc.new { |a, b|
    c = 2
    Kernel.local_variables.sort
  }.call(-1, -2)
end

assert('Kernel#!=') do
  str1 = "hello"
  str2 = str1
  str3 = "world"

  assert_false (str1[1] != 'e')
  assert_true (str1 != str3)
  assert_false (str2 != str1)
end

# operator "!~" is defined in ISO Ruby 11.4.4.
assert('Kernel#!~') do
  x = "x"
  def x.=~(other)
    other == "x"
  end
  assert_false x !~ "x"
  assert_true  x !~ "z"

  y = "y"
  def y.=~(other)
    other == "y"
  end
  def y.!~(other)
    other == "not y"
  end
  assert_false y !~ "y"
  assert_false y !~ "z"
  assert_true  y !~ "not y"
end

assert('Kernel#respond_to_missing?') do
  class Test4RespondToMissing
    def respond_to_missing?(method_name, include_private = false)
      method_name == :a_method
    end
  end

  assert_true Test4RespondToMissing.new.respond_to?(:a_method)
  assert_false Test4RespondToMissing.new.respond_to?(:no_method)
end

assert('Kernel#global_variables') do
  variables = global_variables
  1.upto(9) do |i|
    assert_equal variables.include?(:"$#{i}"), true
  end
end

assert('Kernel#define_singleton_method') do
  o = Object.new
  ret = o.define_singleton_method(:test_method) do
    :singleton_method_ok
  end
  assert_equal :test_method, ret
  assert_equal :singleton_method_ok, o.test_method
end

assert('stack extend') do
  def recurse(count, stop)
    return count if count > stop
    recurse(count+1, stop)
  end

  assert_equal 6, recurse(0, 5)
end
