class Base
  def foo() :base end
end

class Derived < Base
  def foo() :derived end
end

class Interpreter
  attr_accessor :ret

  def do_a() @ret += "there, "; end
  def do_d() @ret += "Hello ";  end
  def do_e() @ret += "!\n";     end
  def do_v() @ret += "Dave";    end
  Dispatcher = {
    "a" => instance_method(:do_a),
    "d" => instance_method(:do_d),
    "e" => instance_method(:do_e),
    "v" => instance_method(:do_v)
  }
  def interpret(string)
    @ret = ""
    string.each_char {|b| Dispatcher[b].bind(self).call }
  end
end

assert 'demo' do
  interpreter = Interpreter.new
  interpreter.interpret('dave')
  assert_equal "Hello there, Dave!\n", interpreter.ret
end

assert 'Method#arity' do
  Class.new {
    attr_accessor :done
    def initialize; @done = false; end
    def m0() end
    def m1(a) end
    def m2(a, b) end
    def mo1(a = nil, &b) end
    def mo2(a, b = nil) end
    def mo3(*a) end
    def mo4(a, *b, &c) end
    def mo5(a, *b, c) end
    def mo6(a, *b, c, &d) end
    def mo7(a, b = nil, *c, d, &e) end
    def ma1((a), &b) nil && a end

    def run
      assert_equal(0, method(:m0).arity)
      assert_equal(1, method(:m1).arity)
      assert_equal(2, method(:m2).arity)
      assert_equal(-1, method(:mo1).arity)
      assert_equal(-2, method(:mo2).arity)
      assert_equal(-1, method(:mo3).arity)
      assert_equal(-2, method(:mo4).arity)
      assert_equal(-3, method(:mo5).arity)
      assert_equal(-3, method(:mo6).arity)
      assert_equal(-3, method(:mo7).arity)
      assert_equal(1, method(:ma1).arity)

      assert_equal(-1, method(:__send__).arity)
      assert_equal(-1, method(:nothing).arity)
    end

    def respond_to_missing?(m, b)
      m == :nothing
    end
  }.new.run
end

assert 'Method and UnboundMethod should not be have a `new` method' do
  assert_raise(NoMethodError){ Method.new }
  assert_raise(NoMethodError){ UnboundMethod.new }
end

assert 'instance' do
  assert_kind_of Method, 1.method(:+)
  assert_kind_of UnboundMethod, Fixnum.instance_method(:+)
end

assert 'Method#call' do
  assert_equal 3, 1.method(:+).call(2)
  assert_equal "ab", "a".method(:+)["b"]
  klass = Class.new {
    def foo; 42; end
  }
  klass2 = Class.new(klass) {
    def foo; super; end
  }
  assert_equal 42, klass2.new.method(:foo).call

  i = Class.new {
   def bar
     yield 3
   end
  }.new
  assert_raise(LocalJumpError) { i.method(:bar).call }
  assert_equal 3, i.method(:bar).call { |i| i }
end

assert 'Method#call for regression' do
  obj = BasicObject.new
  def obj.foo
    :ok
  end
  assert_equal :ok, Kernel.instance_method(:send).bind(obj).call(:foo), "https://github.com/ksss/mruby-method/issues/4"
end

assert 'Method#call with undefined method' do
  c = Class.new {
    attr_accessor :m, :argv
    def respond_to_missing?(m, b)
      m == :foo
    end

    def method_missing(m, *argv)
      @m = m
      @argv = argv
      super
    end
  }
  cc = c.new
  assert_raise(NameError) { cc.method(:nothing) }
  assert_kind_of Method, cc.method(:foo)
  assert_raise(NoMethodError) { cc.method(:foo).call(:arg1, :arg2) }
  assert_equal :foo, cc.m
  assert_equal [:arg1, :arg2], cc.argv

  cc = c.new
  m = cc.method(:foo)
  c.class_eval do
    def foo
      :ng
    end
  end
  assert_raise(NoMethodError) { m.call(:arg1, :arg2) }
end

assert 'Method#source_location' do
  skip if proc{}.source_location.nil?

  filename = __FILE__
  klass = Class.new

  lineno = __LINE__ + 1
  klass.define_method(:find_me_if_you_can) {}
  assert_equal [filename, lineno], klass.new.method(:find_me_if_you_can).source_location

  lineno = __LINE__ + 1
  klass.define_singleton_method(:s_find_me_if_you_can) {}
  assert_equal [filename, lineno], klass.method(:s_find_me_if_you_can).source_location

  klass = Class.new { def respond_to_missing?(m, b); m == :nothing; end }
  assert_nil klass.new.method(:nothing).source_location
end

assert 'UnboundMethod#source_location' do
  skip if proc{}.source_location.nil?

  filename = __FILE__
  klass = Class.new {
    def respond_to_missing?(m, b)
      m == :nothing
    end
  }

  lineno = __LINE__ + 1
  klass.define_method(:find_me_if_you_can) {}
  assert_equal [filename, lineno], klass.instance_method(:find_me_if_you_can).source_location
  assert_nil klass.new.method(:nothing).unbind.source_location
end

assert 'Method#parameters' do
  klass = Class.new {
    def foo(a, b=nil, *c) end
    def respond_to_missing?(m, b)
      m == :missing
    end
  }
  assert_equal [[:req, :a], [:opt, :b], [:rest, :c]], klass.new.method(:foo).parameters
  assert_equal [[:rest]], klass.new.method(:missing).parameters
end

assert 'UnboundMethod#parameters' do
  klass = Class.new {
    def foo(a, b=nil, *c) end
    def respond_to_missing?(m, b)
      m == :nothing
    end
  }
  assert_equal [[:req, :a], [:opt, :b], [:rest, :c]], klass.instance_method(:foo).parameters
  assert_equal [[:rest]], klass.new.method(:nothing).unbind.parameters
end

assert 'Method#to_proc' do
  m = 3.method(:+)
  assert_kind_of Proc, m.to_proc
  assert_equal 7, m.call(4)

  o = Object.new
  def o.foo(a, b=nil, *c)
    [a, b, c]
  end
  assert_equal [:bar, nil, []], o.method(:foo).to_proc.call(:bar)
#  We can fix this issue but leave until the problem
#  assert_equal o.method(:foo).arity, o.method(:foo).to_proc.arity

  def o.bar
    yield 39
  end
  assert_equal 42, o.bar(&3.method(:+))
end

assert 'to_s' do
  o = Object.new
  def o.foo; end
  m = o.method(:foo)
  assert_equal("#<UnboundMethod: #{ class << o; self; end.inspect }#foo>", m.unbind.inspect)

  c = Class.new
  c.class_eval { def foo; end; }
  m = c.new.method(:foo)
  assert_equal("#<Method: #{ c.inspect }#foo>", m.inspect)
  m = c.instance_method(:foo)
  assert_equal("#<UnboundMethod: #{ c.inspect }#foo>", m.inspect)
end

assert 'owner' do
  c = Class.new do
    def foo; end
    def self.bar; end
  end
  m = Module.new do
    def baz; end
  end
  c.include(m)
  c2 = Class.new(c)

  assert_equal(c, c.instance_method(:foo).owner)
  assert_equal(c, c2.instance_method(:foo).owner)

  assert_equal(c, c.new.method(:foo).owner)
  assert_equal(c, c2.new.method(:foo).owner)
  assert_equal(c.singleton_class, c2.method(:bar).owner)
end

assert 'owner missing' do
  c = Class.new do
    def respond_to_missing?(name, bool)
      name == :foo
    end
  end
  c2 = Class.new(c)
  assert_equal(c, c.new.method(:foo).owner)
  assert_equal(c2, c2.new.method(:foo).owner)
end

assert 'receiver name owner' do
  o = Object.new
  def o.foo; end
  m = o.method(:foo)
  assert_equal(o, m.receiver)
  assert_equal(:foo, m.name)
  assert_equal(class << o; self; end, m.owner)
  assert_equal(:foo, m.unbind.name)
  assert_equal(class << o; self; end, m.unbind.owner)
end

assert 'Method#unbind' do
  assert_equal(:derived, Derived.new.foo)
  um = Derived.new.method(:foo).unbind
  assert_kind_of(UnboundMethod, um)
  Derived.class_eval do
    def foo() :changed end
  end
  assert_equal(:changed, Derived.new.foo)
  assert_equal(:changed, Derived.new.foo{})
  assert_equal(:derived, um.bind(Derived.new).call)
  assert_raise(TypeError) do
    um.bind(Base.new)
  end

  # TODO:
  #  Block passed method not handled correctly with workaround.
  #  See comment near `mrb_funcall_with_block` for detail.
  # assert_equal(:derived, um.bind(Derived.new).call{})
end

assert 'Kernel#method' do
  c1 = Class.new {
    def foo; :foo; end
  }
  o = c1.new
  assert_kind_of Method, o.method(:foo)
  assert_kind_of Method, o.method('foo')
  assert_raise(TypeError) { o.method(nil) }
  assert_raise(NameError) { o.method('bar') }
  assert_raise(NameError) { o.method(:bar) }
end

assert "Module#instance_method" do
  assert_kind_of UnboundMethod, Object.instance_method(:object_id)
  assert_raise(NameError) { Object.instance_method(:nothing) }
  c = Class.new {
    def respond_to_missing?(m, b)
      false
    end
  }
  assert_raise(NameError) { c.instance_method(:nothing) }
end

assert 'Kernel#singleton_method' do
  c1 = Class.new {
    def foo; :foo; end
  }
  o = c1.new
  def o.bar; :bar; end
  assert_kind_of Method, o.method(:foo)
  assert_raise(NameError) { o.singleton_method(:foo) }
  assert_kind_of Method, o.singleton_method(:bar)
  assert_raise(TypeError) { o.singleton_method(nil) }
  m = assert_nothing_raised(NameError) { break o.singleton_method(:bar) }
  assert_equal(:bar, m.call)
end

assert 'Method#super_method' do
  o = Derived.new
  m = o.method(:foo).super_method
  assert_equal(Base, m.owner)
  assert_true(o.equal? m.receiver)
  assert_equal(:foo, m.name)
  assert_nil(m.super_method)

  c = Class.new {
    def foo; end
  }
  o = c.new
  o.extend Module.new {
    def foo; end
  }
  assert_equal c, o.method(:foo).super_method.owner
  assert_equal :foo, o.method(:foo).super_method.name
  assert_equal o, o.method(:foo).super_method.receiver
end

assert 'Method#==' do
  o = Object.new
  class << o
    def foo; end
  end
  assert_not_equal(o.method(:foo), nil)
  m = o.method(:foo)
  def m.foo; end
  # TODO: assert_not_equal(o.method(:foo), m)
  assert_equal(o.method(:foo), o.method(:foo))
  # TODO: assert_false(o.method(:foo).eql? m)
  assert_true(o.method(:foo).eql? o.method(:foo))

  assert_false(0.method(:+) == 1.method(:+))
  assert_false(0.method(:+) == 0.method(:-))
  a = 0.method(:+)
  assert_true(a.method(:==) == a.method(:eql?))
end

assert "Method#initialize_copy" do
  c = Class.new {
    def foo
    end
  }.new
  m1 = c.method(:foo)
  m2 = m1.clone
  assert_equal(m1, m2)
end

assert 'UnboundMethod#arity' do
  c = Class.new {
    def foo(a, b)
    end

    def respond_to_missing?(m, b)
      m == :nothing
    end
  }
  assert_equal 2, c.instance_method(:foo).arity
  assert_equal(-1, c.new.method(:nothing).unbind.arity)
end

assert 'UnboundMethod#==' do
  assert_false(Fixnum.instance_method(:+) == Fixnum.instance_method(:-))
  assert_true(Fixnum.instance_method(:+) == Fixnum.instance_method(:+))
  assert_false(Fixnum.instance_method(:+) == Float.instance_method(:+))
  assert_true(UnboundMethod.instance_method(:==) == UnboundMethod.instance_method(:eql?))
end

assert 'UnboundMethod#super_method' do
  m = Derived.instance_method(:foo)
  m = m.super_method
  assert_equal(Base.instance_method(:foo), m)
  assert_nil(m.super_method)

  m = Object.instance_method(:object_id)
  assert_nil(m.super_method)
end

assert 'UnboundMethod#bind' do
  m = Module.new{ def meth() :meth end }.instance_method(:meth)
  assert_raise(ArgumentError) { m.bind }
  assert_kind_of Method, m.bind(1)
  assert_kind_of Method, m.bind(:sym)
  assert_kind_of Method, m.bind(Object.new)
  assert_equal(:meth, m.bind(1).call)
  assert_equal(:meth, m.bind(:sym).call)
  assert_equal(:meth, m.bind(Object.new).call)
  sc = Class.new {
    class << self
      def foo
      end
    end
  }.singleton_class
  assert_raise(TypeError) { sc.instance_method(:foo).bind([]) }
  assert_raise(TypeError) { Array.instance_method(:each).bind(1) }
  assert_kind_of Method, Object.instance_method(:object_id).bind(Object.new)
end
